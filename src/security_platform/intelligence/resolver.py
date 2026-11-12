import ast


class ImportResolver:
    """Builds an import and alias resolution table for a Python module."""

    def __init__(self) -> None:
        # Maps local identifier -> fully-qualified canonical target
        self.aliases: dict[str, str] = {}

    def scan_ast(self, tree: ast.AST) -> None:
        """Populates alias tables from import statements in the AST."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    self.aliases[local_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    fq_name = f"{module}.{alias.name}" if module else alias.name
                    self.aliases[local_name] = fq_name

    def resolve_name(self, name: str) -> str:
        """Resolves a bare name or base identifier using the alias table."""
        return self.aliases.get(name, name)

    def resolve_expr(self, node: ast.AST) -> str:
        """Resolves an AST expression to a canonical dot-separated representation."""
        if isinstance(node, ast.Name):
            return self.resolve_name(node.id)
        elif isinstance(node, ast.Attribute):
            base = self.resolve_expr(node.value)
            return f"{base}.{node.attr}"
        elif isinstance(node, ast.Call):
            func_name = self.resolve_expr(node.func)
            return f"{func_name}()"
        elif isinstance(node, ast.Constant):
            return str(node.value)
        return "<unknown>"

    def resolve_call_name(self, node: ast.Call) -> str:
        """
        Resolves the callee of a call node to its fully qualified or canonical name,
        resolving aliases and handling chained method calls (e.g., cursor().execute).
        """
        if isinstance(node.func, ast.Name):
            return self.resolve_name(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if isinstance(node.func.value, ast.Name):
                base = self.resolve_name(node.func.value.id)
                return f"{base}.{attr}"
            elif isinstance(node.func.value, ast.Attribute):
                base = self.resolve_expr(node.func.value)
                return f"{base}.{attr}"
            elif isinstance(node.func.value, ast.Call):
                inner_base = self.resolve_call_name(node.func.value)
                # Normalize cursor().execute -> cursor.execute, *.execute
                clean_base = inner_base.replace("()", "")
                return f"{clean_base}.{attr}"
        return self.resolve_expr(node.func)
