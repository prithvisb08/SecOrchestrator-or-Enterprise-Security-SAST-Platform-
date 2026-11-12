import ast
from typing import Any

from security_platform.intelligence.models import (
    CallNode,
    ClassNode,
    FunctionNode,
    ImportNode,
    ParameterNode,
)
from security_platform.intelligence.resolver import ImportResolver
from security_platform.models.location import SourceLocation


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, resolver: ImportResolver | None = None):
        self.file_path = file_path
        self.resolver = resolver or ImportResolver()
        self.imports: list[ImportNode] = []
        self.functions: list[FunctionNode] = []
        self.classes: list[ClassNode] = []
        self.calls: list[CallNode] = []
        self._current_function: str | None = None

    def _get_location(self, node: ast.AST) -> SourceLocation:
        return SourceLocation(
            file_path=self.file_path,
            start_line=getattr(node, "lineno", 1),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
            start_column=getattr(node, "col_offset", 0) + 1,
            end_column=getattr(node, "end_col_offset", getattr(node, "col_offset", 0)) + 1
        )

    def _extract_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.resolver.resolve_name(node.id)
        elif isinstance(node, ast.Attribute):
            return f"{self._extract_name(node.value)}.{node.attr}"
        return "<unknown>"

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self.imports.append(ImportNode(
                module=alias.name,
                alias=alias.asname,
                location=self._get_location(node)
            ))
            local_name = alias.asname or alias.name
            self.resolver.aliases[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(ImportNode(
                module=module,
                name=alias.name,
                alias=alias.asname,
                location=self._get_location(node)
            ))
            local_name = alias.asname or alias.name
            fq_name = f"{module}.{alias.name}" if module else alias.name
            self.resolver.aliases[local_name] = fq_name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Any:
        prev_func = self._current_function
        self._current_function = node.name

        params = [ParameterNode(name=arg.arg) for arg in node.args.args]
        decorators = [self._extract_name(dec) for dec in node.decorator_list]

        func_node = FunctionNode(
            name=node.name,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            parameters=params,
            decorators=decorators,
            location=self._get_location(node)
        )

        for item in ast.walk(node):
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                func_node.local_variables.add(item.id)
            if isinstance(item, ast.Return):
                func_node.has_return = True
            if isinstance(item, ast.Yield):
                func_node.has_yield = True

        self.functions.append(func_node)
        self.generic_visit(node)
        self._current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        bases = [self._extract_name(b) for b in node.bases]
        class_node = ClassNode(
            name=node.name,
            base_classes=bases,
            location=self._get_location(node)
        )
        self.classes.append(class_node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        callee = self.resolver.resolve_call_name(node)

        # Extract arg representations
        arg_strs: list[str] = []
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                arg_strs.append(str(arg.value))
            elif isinstance(arg, ast.Name):
                arg_strs.append(arg.id)
            else:
                try:
                    arg_strs.append(ast.unparse(arg))
                except Exception:
                    arg_strs.append("<expr>")

        # Extract keyword argument mappings
        keyword_map: dict[str, str] = {}
        for kw in node.keywords:
            if kw.arg:
                if isinstance(kw.value, ast.Constant):
                    keyword_map[kw.arg] = str(kw.value.value)
                elif isinstance(kw.value, ast.Name):
                    keyword_map[kw.arg] = kw.value.id
                else:
                    try:
                        keyword_map[kw.arg] = ast.unparse(kw.value)
                    except Exception:
                        keyword_map[kw.arg] = "<expr>"

        call_node = CallNode(
            caller_function=self._current_function,
            callee_name=callee,
            location=self._get_location(node),
            args=arg_strs,
            keywords=keyword_map
        )
        self.calls.append(call_node)
        if self._current_function:
            for f in self.functions:
                if f.name == self._current_function:
                    f.calls.append(call_node)
        self.generic_visit(node)


class CodeParser:
    @staticmethod
    def parse_python_file(file_path: str, source_code: str) -> PythonASTVisitor:
        resolver = ImportResolver()
        visitor = PythonASTVisitor(file_path, resolver=resolver)
        try:
            tree = ast.parse(source_code)
            resolver.scan_ast(tree)
            visitor.visit(tree)
        except (SyntaxError, RecursionError, MemoryError, ValueError):
            # Gracefully handle parser crashes and resource exhaustion on untrusted code
            pass
        return visitor
