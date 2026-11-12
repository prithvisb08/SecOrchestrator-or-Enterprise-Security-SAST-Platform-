import ast
from typing import Any

from security_platform.dataflow.config import (
    DEFAULT_SANITIZERS,
    DEFAULT_SOURCES,
    is_sanitizer_valid_for_sink,
    match_sink,
)
from security_platform.dataflow.core import DataFlowNode, TaintPath
from security_platform.intelligence.resolver import ImportResolver
from security_platform.models.location import SourceLocation


class TaintTracker(ast.NodeVisitor):
    def __init__(self, file_path: str, resolver: ImportResolver | None = None):
        self.file_path = file_path
        self.resolver = resolver or ImportResolver()
        self.global_taint: dict[str, DataFlowNode] = {}
        self.function_scopes: dict[str, dict[str, DataFlowNode]] = {}
        self.current_function: str | None = None
        self.discovered_paths: list[TaintPath] = []

    def _get_location(self, node: ast.AST) -> SourceLocation:
        return SourceLocation(
            file_path=self.file_path,
            start_line=getattr(node, "lineno", 1),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
            start_column=getattr(node, "col_offset", 0) + 1,
            end_column=getattr(node, "end_col_offset", getattr(node, "col_offset", 0)) + 1
        )

    def _get_taint(self, var_name: str) -> DataFlowNode | None:
        if self.current_function and self.current_function in self.function_scopes:
            scope = self.function_scopes[self.current_function]
            if var_name in scope:
                return scope[var_name]
        return self.global_taint.get(var_name)

    def _set_taint(self, var_name: str, node: DataFlowNode | None) -> None:
        if self.current_function and self.current_function in self.function_scopes:
            scope = self.function_scopes[self.current_function]
            if node:
                scope[var_name] = node
            else:
                scope.pop(var_name, None)
        else:
            if node:
                self.global_taint[var_name] = node
            else:
                self.global_taint.pop(var_name, None)

    def _is_source_expression(self, expr_str: str) -> bool:
        if expr_str in DEFAULT_SOURCES:
            return True
        # Check standard web framework patterns
        lowered = expr_str.lower()
        if any(prefix in lowered for prefix in [
            "request.args", "request.form", "request.values", "request.json",
            "request.data", "request.get_json", "request.get", "request.post",
            "req.args", "req.form", "req.json", "sys.argv"
        ]):
            return True
        return False

    def _is_node_tainted(self, node: ast.AST | None) -> DataFlowNode | None:
        if node is None:
            return None

        if isinstance(node, ast.Name):
            return self._get_taint(node.id)

        elif isinstance(node, ast.Attribute):
            expr = self.resolver.resolve_expr(node)
            if self._is_source_expression(expr):
                return DataFlowNode(
                    node_type="SOURCE",
                    expression=expr,
                    location=self._get_location(node)
                )
            # Check if base object is tainted
            return self._is_node_tainted(node.value)

        elif isinstance(node, ast.Subscript):
            base_expr = self.resolver.resolve_expr(node.value)
            if self._is_source_expression(base_expr):
                return DataFlowNode(
                    node_type="SOURCE",
                    expression=f"{base_expr}[...]",
                    location=self._get_location(node)
                )
            return self._is_node_tainted(node.value)

        elif isinstance(node, ast.Call):
            call_name = self.resolver.resolve_call_name(node)

            # Check if call is a known source
            if self._is_source_expression(call_name):
                return DataFlowNode(
                    node_type="SOURCE",
                    expression=call_name,
                    location=self._get_location(node)
                )

            # Check if call is a sanitizer
            sanitizer_name = None
            if call_name in DEFAULT_SANITIZERS:
                sanitizer_name = call_name
            elif call_name.split(".")[-1] in DEFAULT_SANITIZERS:
                sanitizer_name = call_name.split(".")[-1]

            if sanitizer_name:
                # Find tainted argument inside sanitizer
                for arg in node.args:
                    arg_taint = self._is_node_tainted(arg)
                    if arg_taint:
                        # Return sanitized node with tracked sanitizer
                        return DataFlowNode(
                            node_type="SANITIZER",
                            expression=arg_taint.expression,
                            location=arg_taint.location,
                            sanitizers=list(set(arg_taint.sanitizers + [sanitizer_name]))
                        )

            # For normal function calls (e.g., str(x), x.strip()), propagate taint from arguments
            for arg in node.args:
                arg_taint = self._is_node_tainted(arg)
                if arg_taint:
                    return arg_taint
            for kw in node.keywords:
                kw_taint = self._is_node_tainted(kw.value)
                if kw_taint:
                    return kw_taint

        elif isinstance(node, ast.BinOp):
            left_taint = self._is_node_tainted(node.left)
            right_taint = self._is_node_tainted(node.right)
            if left_taint and right_taint:
                # If both are sanitized with same sanitizer, keep; if one is unsanitized, whole op is unsanitized
                common_sans = [s for s in left_taint.sanitizers if s in right_taint.sanitizers]
                return DataFlowNode(
                    node_type="PROPAGATION",
                    expression=f"{left_taint.expression} + {right_taint.expression}",
                    location=self._get_location(node),
                    sanitizers=common_sans
                )
            return left_taint or right_taint

        elif isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    val_taint = self._is_node_tainted(value.value)
                    if val_taint:
                        return val_taint

        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                elt_taint = self._is_node_tainted(elt)
                if elt_taint:
                    return elt_taint

        elif isinstance(node, ast.Dict):
            for v in node.values:
                v_taint = self._is_node_tainted(v)
                if v_taint:
                    return v_taint

        return None

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Any:
        prev_func = self.current_function
        self.current_function = node.name
        self.function_scopes[node.name] = {}

        # Inspect decorators and parameters for public routes
        is_route = False
        for dec in node.decorator_list:
            dec_str = self.resolver.resolve_expr(dec)
            if any(k in dec_str.lower() for k in ["route", "get", "post", "put", "delete", "endpoint"]):
                is_route = True
                break

        for arg in node.args.args:
            # Route handler arguments or 'request' parameters are untrusted sources
            if is_route and arg.arg not in {"self", "cls", "db", "session"}:
                self.function_scopes[node.name][arg.arg] = DataFlowNode(
                    node_type="SOURCE",
                    expression=f"param:{arg.arg}",
                    location=self._get_location(arg)
                )
            elif arg.arg in {"request", "req"}:
                self.function_scopes[node.name][arg.arg] = DataFlowNode(
                    node_type="SOURCE",
                    expression="request",
                    location=self._get_location(arg)
                )

        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        taint = self._is_node_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._set_taint(target.id, taint)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        self._set_taint(elt.id, taint)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            taint = self._is_node_tainted(node.value)
            if isinstance(node.target, ast.Name):
                self._set_taint(node.target.id, taint)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        val_taint = self._is_node_tainted(node.value)
        if isinstance(node.target, ast.Name):
            existing = self._get_taint(node.target.id)
            if val_taint:
                self._set_taint(node.target.id, val_taint)
            elif not existing:
                self._set_taint(node.target.id, None)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self.resolver.resolve_call_name(node)
        sink = match_sink(callee)

        if sink:
            # Check each argument or keyword argument
            tainted_arg_node: DataFlowNode | None = None
            for arg in node.args:
                tainted_arg_node = self._is_node_tainted(arg)
                if tainted_arg_node:
                    break

            if not tainted_arg_node:
                for kw in node.keywords:
                    if kw.arg != "shell":
                        tainted_arg_node = self._is_node_tainted(kw.value)
                        if tainted_arg_node:
                            break

            if tainted_arg_node:
                # Check sink-specific sanitization
                is_safe = False
                effective_sanitizer = None
                for san in tainted_arg_node.sanitizers:
                    if is_sanitizer_valid_for_sink(san, sink.vulnerability_type):
                        is_safe = True
                        effective_sanitizer = san
                        break

                sink_node = DataFlowNode(
                    node_type="SINK",
                    expression=callee,
                    location=self._get_location(node)
                )
                self.discovered_paths.append(TaintPath(
                    source=tainted_arg_node,
                    propagations=[],
                    sink=sink_node,
                    is_sanitized=is_safe,
                    sanitizer_name=effective_sanitizer
                ))

        self.generic_visit(node)
