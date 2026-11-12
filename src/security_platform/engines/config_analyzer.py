import re
import uuid

from security_platform.enums.severity import Severity
from security_platform.models.finding import Finding
from security_platform.models.location import SourceLocation
from security_platform.taxonomy.categories import Category
from security_platform.taxonomy.vulnerability_types import VulnerabilityType


class ConfigurationAnalyzer:
    def analyze_dockerfile(self, file_path: str, content: str, scanner_version: str = "1.0.0") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        stage_count = 0
        final_stage_user = "root"
        has_healthcheck = False
        secret_pattern = re.compile(r"(?i)(?:password|secret|token|api_key|private_key)\s*[:=]\s*(\S+)")

        for line_idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            upper = line.upper()

            # 1. Multi-stage tracking & Base image inspection
            if upper.startswith("FROM "):
                stage_count += 1
                final_stage_user = "root"  # Each new stage resets the user context back to root

                # Check for :latest or untagged images
                parts = line.split()
                if len(parts) >= 2:
                    image_ref = parts[1]
                    if ":" not in image_ref or image_ref.endswith(":latest"):
                        findings.append(Finding(
                            finding_id=str(uuid.uuid4()),
                            rule_id="SEC-DOCKER-LATEST-001",
                            category=Category.CONFIGURATION,
                            vulnerability_type=VulnerabilityType.MISCONFIGURATION,
                            title="Base Image Uses Latest or Untagged Version",
                            description=f"Base image '{image_ref}' does not use a pinned digest or immutable version tag.",
                            severity=Severity.MEDIUM,
                            confidence=0.90,
                            location=SourceLocation(file_path=file_path, start_line=line_idx, end_line=line_idx),
                            code_snippet=line,
                            evidence=f"Found unpinned base image on line {line_idx}.",
                            root_cause="Using 'latest' or untagged container images introduces non-deterministic builds and supply-chain drift.",
                            recommendation="Pin container images by specific version tag or immutable SHA256 digest.",
                            scanner_version=scanner_version
                        ))

            # 2. USER instructions
            elif upper.startswith("USER "):
                user_val = line.split(None, 1)[1].strip()
                if user_val.lower() not in {"root", "0"}:
                    final_stage_user = user_val
                else:
                    final_stage_user = "root"

            # 3. Insecure ADD instructions from URLs
            elif upper.startswith("ADD "):
                if "http://" in line.lower() or "https://" in line.lower():
                    findings.append(Finding(
                        finding_id=str(uuid.uuid4()),
                        rule_id="SEC-DOCKER-ADD-URL-001",
                        category=Category.CONFIGURATION,
                        vulnerability_type=VulnerabilityType.INSECURE_CONFIG,
                        title="Remote Insecure ADD Instruction Used",
                        description="ADD instruction fetches files from a remote URL without integrity checking.",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        location=SourceLocation(file_path=file_path, start_line=line_idx, end_line=line_idx),
                        code_snippet=line,
                        evidence=f"Remote URL in ADD instruction on line {line_idx}.",
                        root_cause="Using ADD with remote URLs lacks cryptographic verification and can be MITMed.",
                        recommendation="Use 'RUN curl/wget' with checksum verification or 'COPY' local resources.",
                        scanner_version=scanner_version
                    ))

            # 4. Pipe to shell in RUN instructions
            elif upper.startswith("RUN "):
                if re.search(r"(?:curl|wget)\s+[^|]+\|\s*(?:ba)?sh", line, re.IGNORECASE):
                    findings.append(Finding(
                        finding_id=str(uuid.uuid4()),
                        rule_id="SEC-DOCKER-PIPE-SHELL-001",
                        category=Category.SECURITY,
                        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                        title="Dangerous Pipe to Shell in RUN Instruction",
                        description="Directly piping curl/wget into sh/bash can execute arbitrary untrusted code.",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        location=SourceLocation(file_path=file_path, start_line=line_idx, end_line=line_idx),
                        code_snippet=line,
                        evidence=f"Piped shell execution on line {line_idx}.",
                        root_cause="Executing remote scripts directly without validation allows remote compromise during build.",
                        recommendation="Download the script, verify its checksum, and execute it explicitly.",
                        scanner_version=scanner_version
                    ))

            # 5. Secrets in ENV or ARG
            elif upper.startswith("ENV ") or upper.startswith("ARG "):
                m = secret_pattern.search(line)
                if m:
                    secret_val = m.group(1).strip("'\"")
                    if len(secret_val) >= 8 and secret_val.lower() not in {"dummy", "test", "changeme"}:
                        findings.append(Finding(
                            finding_id=str(uuid.uuid4()),
                            rule_id="SEC-DOCKER-SECRET-001",
                            category=Category.SECRETS,
                            vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                            title="Potential Secret Stored in Dockerfile ENV or ARG",
                            description="Sensitive credentials stored in Dockerfile instructions persist in image metadata.",
                            severity=Severity.HIGH,
                            confidence=0.90,
                            location=SourceLocation(file_path=file_path, start_line=line_idx, end_line=line_idx),
                            code_snippet=f"{line.split()[0]} [REDACTED_SECRET]",
                            evidence=f"Credential pattern detected in {line.split()[0]} on line {line_idx}.",
                            root_cause="ENV and ARG values are visible in docker history and inspect commands.",
                            recommendation="Use Docker BuildKit secrets mount (--mount=type=secret) or runtime secrets.",
                            scanner_version=scanner_version
                        ))

            # 6. Debug mode check
            if "DEBUG=TRUE" in upper or "DEBUG=1" in upper:
                findings.append(Finding(
                    finding_id=str(uuid.uuid4()),
                    rule_id="SEC-CFG-DEBUG-001",
                    category=Category.CONFIGURATION,
                    vulnerability_type=VulnerabilityType.DEBUG_MODE,
                    title="Debug Mode Enabled in Container",
                    description="The container configuration has debug mode explicitly enabled.",
                    severity=Severity.MEDIUM,
                    confidence=0.95,
                    location=SourceLocation(file_path=file_path, start_line=line_idx, end_line=line_idx),
                    code_snippet=line,
                    evidence=f"Found debug flag on line {line_idx}.",
                    root_cause="Enabling debug mode in production containers can expose stack traces and internal service state.",
                    recommendation="Disable debug mode for production deployments.",
                    scanner_version=scanner_version
                ))

            # 7. Healthcheck check
            if upper.startswith("HEALTHCHECK "):
                has_healthcheck = True

        # Check if the final stage runs as root
        if final_stage_user.lower() in {"root", "0"}:
            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                rule_id="SEC-CFG-ROOT-001",
                category=Category.CONFIGURATION,
                vulnerability_type=VulnerabilityType.INSECURE_DOCKER,
                title="Container Runs as Root User",
                description="The Dockerfile's final execution stage does not switch to a non-privileged user, running processes as root by default.",
                severity=Severity.HIGH,
                confidence=0.90,
                location=SourceLocation(file_path=file_path, start_line=1, end_line=1),
                code_snippet="[Final stage user check]",
                evidence=f"Final stage executes as user '{final_stage_user}'.",
                root_cause="Running containers as root grants unnecessary host system privileges if container isolation is breached.",
                recommendation="Add a dedicated non-root user via 'USER' instruction in the final build stage.",
                scanner_version=scanner_version
            ))

        # Check missing healthcheck
        if not has_healthcheck and stage_count > 0:
            findings.append(Finding(
                finding_id=str(uuid.uuid4()),
                rule_id="SEC-DOCKER-HEALTHCHECK-001",
                category=Category.CONFIGURATION,
                vulnerability_type=VulnerabilityType.MISCONFIGURATION,
                title="Missing HEALTHCHECK Instruction",
                description="The container does not define a HEALTHCHECK instruction for container runtime liveness verification.",
                severity=Severity.LOW,
                confidence=0.85,
                location=SourceLocation(file_path=file_path, start_line=1, end_line=1),
                code_snippet="[File-level check]",
                evidence="No HEALTHCHECK instruction declared.",
                root_cause="Without a HEALTHCHECK, orchestrators cannot automatically detect stalled container processes.",
                recommendation="Add an appropriate HEALTHCHECK instruction.",
                scanner_version=scanner_version
            ))

        return findings
