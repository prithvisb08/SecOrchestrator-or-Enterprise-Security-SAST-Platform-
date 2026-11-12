import json
import re
import uuid
from pathlib import Path

from pydantic import BaseModel, Field

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: str
    manifest_path: str
    is_transitive: bool = False
    vulnerabilities: list[str] = Field(default_factory=list)


# Reference database of known vulnerable packages and CVE mappings
KNOWN_ADVISORIES: dict[str, list[tuple[str, str, str, Severity]]] = {
    "requests": [
        ("2.31.0", "CVE-2023-32681", "Leaking Proxy-Authorization headers to destination servers on redirects", Severity.MEDIUM),
    ],
    "urllib3": [
        ("2.0.7", "CVE-2023-45803", "Request body not stripped when redirected with 303 See Other", Severity.HIGH),
    ],
    "flask": [
        ("2.2.5", "CVE-2023-30861", "Potential session cookie leak due to missing Vary: Cookie cache header", Severity.HIGH),
    ],
    "jinja2": [
        ("3.1.3", "CVE-2024-22195", "Cross-site scripting (XSS) vulnerability via xmlattr filter", Severity.MEDIUM),
    ],
    "pyyaml": [
        ("5.4", "CVE-2020-14343", "Arbitrary code execution via full_load and UnsafeLoader", Severity.CRITICAL),
    ],
    "cryptography": [
        ("41.0.6", "CVE-2023-49083", "NULL pointer dereference when parsing malicious PKCS7 certificates", Severity.HIGH),
    ],
    "django": [
        ("4.2.11", "CVE-2024-27351", "Regular expression Denial of Service (ReDoS) in django.utils.text.Truncator", Severity.HIGH),
    ],
    "lodash": [
        ("4.17.21", "CVE-2021-23337", "Command injection via template parameter manipulation", Severity.HIGH),
    ],
    "axios": [
        ("0.21.2", "CVE-2021-3749", "Regular expression Denial of Service in data parameter parsing", Severity.HIGH),
    ],
    "jsonwebtoken": [
        ("9.0.0", "CVE-2022-23529", "Insecure key object validation leading to arbitrary code execution", Severity.CRITICAL),
    ]
}


def _parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Extract numeric segments for semver comparison."""
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts) if parts else (0,)


def _is_version_less_than(v1: str, v2: str) -> bool:
    """Returns True if v1 < v2 according to semver numeric ordering."""
    t1 = _parse_version_tuple(v1)
    t2 = _parse_version_tuple(v2)
    return t1 < t2


class DependencyAnalyzer:
    def __init__(self, scanner_version: str = "1.0.0"):
        self.scanner_version = scanner_version

    def _parse_pip_spec(self, raw_line: str) -> tuple[str, str] | None:
        """Parses a pip requirement line handling extras, markers, URLs, and comparison specs."""
        line = raw_line.strip()
        if not line or line.startswith("#"):
            return None

        # Strip inline comments
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        # Strip environment markers (e.g. ; python_version < '3.8')
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        # Strip URL requirements (e.g. pkg @ https://...)
        if "@" in line:
            name = line.split("@", 1)[0].strip()
            return name, "unknown"

        # Match package name and version specifiers
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]+\])?(.*)$", line)
        if not match:
            return None

        name = match.group(1).strip()
        spec = match.group(2).strip()

        version = "unknown"
        if spec:
            # Extract first version literal (e.g. ==1.2.3, >=1.2.3, ~=1.2.3)
            ver_match = re.search(r"[=><~^]+\s*([0-9a-zA-Z_\-\.]+)", spec)
            if ver_match:
                version = ver_match.group(1).strip()

        return name, version

    def analyze_manifest(self, file_path: str, content: str) -> list[Dependency]:
        """Backwards-compatible API returning parsed dependencies."""
        deps, _ = self.scan_manifest(file_path, content)
        return deps

    def scan_manifest(
        self, file_path: str, content: str, scanner_version: str | None = None
    ) -> tuple[list[Dependency], list[Finding]]:
        version = scanner_version or self.scanner_version
        deps: list[Dependency] = []
        findings: list[Finding] = []
        path = Path(file_path)
        filename = path.name

        if filename == "requirements.txt":
            for line_idx, line in enumerate(content.splitlines(), start=1):
                parsed = self._parse_pip_spec(line)
                if not parsed:
                    continue
                name, ver = parsed
                dep = Dependency(name=name, version=ver, ecosystem="pip", manifest_path=file_path)
                deps.append(dep)

                # Check for known vulnerabilities
                norm_name = name.lower().replace("-", "_")
                for fixed_in, cve_id, desc, sev in KNOWN_ADVISORIES.get(norm_name, []):
                    if ver != "unknown" and _is_version_less_than(ver, fixed_in):
                        dep.vulnerabilities.append(cve_id)
                        finding = Finding(
                            finding_id=str(uuid.uuid4()),
                            rule_id=f"SEC-SCA-{cve_id}",
                            category=Category.DEPENDENCY,
                            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                            title=f"Vulnerable Dependency: {name} ({cve_id})",
                            description=f"Dependency '{name}=={ver}' is vulnerable to {cve_id}: {desc}.",
                            severity=sev,
                            confidence=0.95,
                            location=SourceLocation(file_path=file_path, start_line=line_idx, end_line=line_idx),
                            code_snippet=line.strip(),
                            evidence=f"Manifest specifies {name}=={ver}, which is below patched version {fixed_in}.",
                            root_cause=f"Using an unpatched version of {name} exposes the application to {cve_id}.",
                            recommendation=f"Upgrade {name} to version {fixed_in} or higher.",
                            scanner_version=version,
                            metadata={"cve": cve_id, "fixed_in": fixed_in, "ecosystem": "pip"}
                        )
                        findings.append(finding)

        elif filename == "pyproject.toml":
            try:
                import tomllib
                data = tomllib.loads(content)
                project = data.get("project", {})
                for dep_str in project.get("dependencies", []):
                    parsed = self._parse_pip_spec(dep_str)
                    if parsed:
                        name, ver = parsed
                        dep = Dependency(name=name, version=ver, ecosystem="pip", manifest_path=file_path)
                        deps.append(dep)

                        norm_name = name.lower().replace("-", "_")
                        for fixed_in, cve_id, desc, sev in KNOWN_ADVISORIES.get(norm_name, []):
                            if ver != "unknown" and _is_version_less_than(ver, fixed_in):
                                dep.vulnerabilities.append(cve_id)
                                finding = Finding(
                                    finding_id=str(uuid.uuid4()),
                                    rule_id=f"SEC-SCA-{cve_id}",
                                    category=Category.DEPENDENCY,
                                    vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                                    title=f"Vulnerable Dependency: {name} ({cve_id})",
                                    description=f"Dependency '{name}=={ver}' is vulnerable to {cve_id}: {desc}.",
                                    severity=sev,
                                    confidence=0.95,
                                    location=SourceLocation(file_path=file_path, start_line=1, end_line=1),
                                    code_snippet=dep_str.strip(),
                                    evidence=f"pyproject.toml specifies {name}=={ver}, below patched version {fixed_in}.",
                                    root_cause=f"Unpatched {name} exposes the application to {cve_id}.",
                                    recommendation=f"Upgrade {name} to version {fixed_in} or higher.",
                                    scanner_version=version,
                                    metadata={"cve": cve_id, "fixed_in": fixed_in, "ecosystem": "pip"}
                                )
                                findings.append(finding)
            except Exception:
                pass

        elif filename == "package.json":
            try:
                data = json.loads(content)
                for section in ["dependencies", "devDependencies"]:
                    for name, raw_version in data.get(section, {}).items():
                        clean_ver = re.sub(r"[^\d\.]", "", raw_version)
                        dep = Dependency(name=name, version=clean_ver or "unknown", ecosystem="npm", manifest_path=file_path)
                        deps.append(dep)

                        norm_name = name.lower()
                        for fixed_in, cve_id, desc, sev in KNOWN_ADVISORIES.get(norm_name, []):
                            if clean_ver and _is_version_less_than(clean_ver, fixed_in):
                                dep.vulnerabilities.append(cve_id)
                                finding = Finding(
                                    finding_id=str(uuid.uuid4()),
                                    rule_id=f"SEC-SCA-{cve_id}",
                                    category=Category.DEPENDENCY,
                                    vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                                    title=f"Vulnerable Dependency: {name} ({cve_id})",
                                    description=f"NPM package '{name}@{clean_ver}' is vulnerable to {cve_id}: {desc}.",
                                    severity=sev,
                                    confidence=0.95,
                                    location=SourceLocation(file_path=file_path, start_line=1, end_line=1),
                                    code_snippet=f'"{name}": "{raw_version}"',
                                    evidence=f"Package.json specifies {name}@{clean_ver}, below fixed version {fixed_in}.",
                                    root_cause=f"Unpatched {name} exposes the application to {cve_id}.",
                                    recommendation=f"Upgrade {name} to version {fixed_in} or higher.",
                                    scanner_version=version,
                                    metadata={"cve": cve_id, "fixed_in": fixed_in, "ecosystem": "npm"}
                                )
                                findings.append(finding)
            except Exception:
                pass

        return deps, findings
