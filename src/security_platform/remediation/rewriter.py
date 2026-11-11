import ast


class VulnerabilityFixer(ast.NodeTransformer):
    """AST transformer that safely rewrites known vulnerable code patterns."""

    def __init__(self) -> None:
        self.modifications_made = 0

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)

        # Rule Fix: Upgrade hashlib.md5 or hashlib.sha1 to hashlib.sha256
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib" and node.func.attr in ("md5", "sha1"):
                node.func.attr = "sha256"
                self.modifications_made += 1

        return node

class ASTRewriter:
    """Applies AST transformations and formats rewritten source code."""

    def fix_python_code(self, source_code: str) -> tuple[str, int]:
        try:
            tree = ast.parse(source_code)
            fixer = VulnerabilityFixer()
            modified_tree = fixer.visit(tree)
            ast.fix_missing_locations(modified_tree)

            if fixer.modifications_made > 0:
                fixed_code = ast.unparse(modified_tree)
                return fixed_code, fixer.modifications_made
        except Exception:
            pass

        return source_code, 0
