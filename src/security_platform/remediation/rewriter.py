import difflib

import libcst as cst
from pydantic import BaseModel


class FixReport(BaseModel):
    rule_id: str
    description: str
    line_number: int | None = None
    original_snippet: str = ""
    fixed_snippet: str = ""


class LibCSTSecurityTransformer(cst.CSTTransformer):
    """Deterministic AST transformer using LibCST that preserves formatting and comments."""

    def __init__(self) -> None:
        super().__init__()
        self.modifications_made = 0
        self.reports: list[FixReport] = []

    def leave_Call(self, original_node: cst.Call, updated_node: cst.Call) -> cst.Call:
        func = updated_node.func

        # 1. yaml.load(...) -> yaml.safe_load(...)
        if isinstance(func, cst.Attribute) and func.attr.value == "load":
            if isinstance(func.value, cst.Name) and func.value.value == "yaml":
                # Check if Loader is already specified and safe
                has_safe_loader = False
                for arg in updated_node.args:
                    if arg.keyword and arg.keyword.value == "Loader":
                        if isinstance(arg.value, cst.Attribute) and arg.value.attr.value in ("SafeLoader", "CSafeLoader"):
                            has_safe_loader = True
                if not has_safe_loader:
                    self.modifications_made += 1
                    self.reports.append(
                        FixReport(
                            rule_id="SEC-DESER-001",
                            description="Rewrote insecure yaml.load to yaml.safe_load",
                        )
                    )
                    return updated_node.with_changes(
                        func=func.with_changes(attr=cst.Name("safe_load"))
                    )

        # 2. hashlib.md5 / hashlib.sha1 -> hashlib.sha256 (unless usedforsecurity=False)
        if isinstance(func, cst.Attribute) and func.attr.value in ("md5", "sha1"):
            if isinstance(func.value, cst.Name) and func.value.value == "hashlib":
                is_non_security = False
                for arg in updated_node.args:
                    if arg.keyword and arg.keyword.value == "usedforsecurity":
                        if isinstance(arg.value, cst.Name) and arg.value.value == "False":
                            is_non_security = True
                if not is_non_security:
                    old_algo = func.attr.value
                    self.modifications_made += 1
                    self.reports.append(
                        FixReport(
                            rule_id="SEC-CRYPTO-001",
                            description=f"Upgraded weak hash {old_algo} to sha256",
                        )
                    )
                    return updated_node.with_changes(
                        func=func.with_changes(attr=cst.Name("sha256"))
                    )

        # 3. subprocess.*(..., shell=True) -> shell=False
        if isinstance(func, cst.Attribute) and func.attr.value in ("run", "Popen", "call", "check_call", "check_output"):
            is_subprocess = (isinstance(func.value, cst.Name) and func.value.value == "subprocess")
            if is_subprocess:
                new_args: list[cst.Arg] = []
                changed = False
                for arg in updated_node.args:
                    if arg.keyword and arg.keyword.value == "shell":
                        if isinstance(arg.value, cst.Name) and arg.value.value == "True":
                            new_args.append(arg.with_changes(value=cst.Name("False")))
                            changed = True
                            continue
                    new_args.append(arg)
                if changed:
                    self.modifications_made += 1
                    self.reports.append(
                        FixReport(
                            rule_id="SEC-CMD-001",
                            description="Disabled shell=True in subprocess invocation",
                        )
                    )
                    return updated_node.with_changes(args=new_args)

        # 4. cursor.execute(f"SELECT ... {var}") -> cursor.execute("SELECT ... %s", (var,))
        if isinstance(func, cst.Attribute) and func.attr.value == "execute":
            if updated_node.args:
                first_arg = updated_node.args[0].value
                if isinstance(first_arg, cst.FormattedString):
                    # Convert f-string with interpolated expressions into %s and tuple of parameters
                    new_string_parts: list[str] = []
                    extracted_expressions: list[cst.BaseExpression] = []
                    has_format_spec = False

                    for part in first_arg.parts:
                        if isinstance(part, cst.FormattedStringText):
                            new_string_parts.append(part.value)
                        elif isinstance(part, cst.FormattedStringExpression):
                            new_string_parts.append("%s")
                            extracted_expressions.append(part.expression)
                        else:
                            has_format_spec = True

                    if not has_format_spec and extracted_expressions:
                        # Build plain string literal
                        joined_str = "".join(new_string_parts)
                        new_sql_literal = cst.SimpleString(f'"{joined_str}"')
                        # Build parameter tuple
                        param_tuple = cst.Tuple(
                            elements=[cst.Element(value=expr) for expr in extracted_expressions]
                        )
                        new_call_args = [
                            cst.Arg(value=new_sql_literal),
                            cst.Arg(value=param_tuple),
                        ]
                        # Retain any additional kwargs from original call
                        new_call_args.extend(updated_node.args[1:])

                        self.modifications_made += 1
                        self.reports.append(
                            FixReport(
                                rule_id="SEC-SQL-001",
                                description="Parameterized dynamic f-string query in cursor.execute",
                            )
                        )
                        return updated_node.with_changes(args=new_call_args)

        return updated_node


class LibCSTRewriter:
    """Applies deterministic, comment-preserving AST auto-fixes."""

    def fix_code(self, source_code: str) -> tuple[str, int, list[FixReport]]:
        try:
            tree = cst.parse_module(source_code)
            transformer = LibCSTSecurityTransformer()
            modified_tree = tree.visit(transformer)
            if transformer.modifications_made > 0:
                return modified_tree.code, transformer.modifications_made, transformer.reports
        except Exception:
            # Fall back safely if parsing fails
            pass
        return source_code, 0, []

    @staticmethod
    def generate_unified_diff(
        original_code: str,
        fixed_code: str,
        filename: str = "file.py"
    ) -> str:
        """Generates a standard Git-compatible unified diff patch."""
        orig_lines = original_code.splitlines(keepends=True)
        fixed_lines = fixed_code.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
        return "".join(diff)


class ASTRewriter(LibCSTRewriter):
    """Backward-compatible alias for existing tests."""

    def fix_python_code(self, source_code: str) -> tuple[str, int]:
        fixed, count, _ = self.fix_code(source_code)
        return fixed, count


class LLMFixSuggestion(BaseModel):
    rule_id: str
    file_path: str
    line_number: int
    original_code: str
    suggested_code: str
    explanation: str
    is_llm_generated: bool = True
    disclaimer: str = (
        "LLM-generated remediation proposal. Requires thorough manual security review and testing. "
        "Will never be auto-merged."
    )


class LLMSuggestionEngine:
    """Generates clearly marked advisory suggestions for complex vulnerabilities that cannot be safely auto-fixed deterministically."""

    def generate_suggestion(
        self,
        rule_id: str,
        file_path: str,
        line_number: int,
        code_context: str,
        vulnerability_type: str,
    ) -> LLMFixSuggestion:
        return LLMFixSuggestion(
            rule_id=rule_id,
            file_path=file_path,
            line_number=line_number,
            original_code=code_context,
            suggested_code=f"# TODO: Manual review required for {vulnerability_type}\n{code_context}",
            explanation=(
                f"Automated deterministic remediation cannot safely deduce intended business logic "
                f"for {vulnerability_type}. Please inspect dataflow and sanitize input at the boundary."
            ),
        )
