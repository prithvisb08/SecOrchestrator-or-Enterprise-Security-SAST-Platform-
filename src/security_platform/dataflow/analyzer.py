import ast

from security_platform.dataflow.config import DEFAULT_SANITIZERS, DEFAULT_SINKS, DEFAULT_SOURCES
from security_platform.dataflow.core import DataFlowNode, TaintPath
from security_platform.models.location import SourceLocation


class TaintTracker(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.tainted_variables: dict[str, DataFlowNode] = {}
        self.discovered_paths: list[TaintPath] = []

    def _get_location(self, node: ast.AST) -> SourceLocation:
        return SourceLocation(
            file_path=self.file_path,
            start_line=getattr(node, "lineno", 1),
            end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
            start_column=getattr(node, "col_offset", 0) + 1,
            end_column=getattr(node, "end_col_offset", getattr(node, "col_offset", 0)) + 1
        )

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute) and isinstance(node.func.value.value, ast.Name):
                return f"{node.func.value.value.id}.{node.func.value.attr}.{node.func.attr}"
        return "<unknown>"

    def _is_node_tainted(self, node: ast.AST) -> DataFlowNode | None:
        if isinstance(node, ast.Name):
            return self.tainted_variables.get(node.id)
        elif isinstance(node, ast.Call):
            call_name = self._get_call_name(node)
            if call_name in DEFAULT_SANITIZERS:
                return None
            if call_name in DEFAULT_SOURCES:
                return DataFlowNode(node_type="SOURCE", expression=call_name, location=self._get_location(node))
            for arg in node.args:
                taint_source = self._is_node_tainted(arg)
                if taint_source:
                    return taint_source
        elif isinstance(node, ast.BinOp):
            return self._is_node_tainted(node.left) or self._is_node_tainted(node.right)
        elif isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    taint = self._is_node_tainted(value.value)
                    if taint:
                        return taint
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        taint_source = self._is_node_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if taint_source:
                    self.tainted_variables[target.id] = taint_source
                else:
                    self.tainted_variables.pop(target.id, None)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node)
        if call_name in DEFAULT_SINKS:
            for arg in node.args:
                taint_source = self._is_node_tainted(arg)
                if taint_source:
                    sink_node = DataFlowNode(node_type="SINK", expression=call_name, location=self._get_location(node))
                    self.discovered_paths.append(TaintPath(source=taint_source, propagations=[], sink=sink_node))
        self.generic_visit(node)
