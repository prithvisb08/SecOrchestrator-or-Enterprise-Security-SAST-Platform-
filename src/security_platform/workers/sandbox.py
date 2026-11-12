from typing import Any

from pydantic import BaseModel, Field


class SandboxConfig(BaseModel):
    """Execution constraints and security boundaries for ephemeral scan containers."""

    memory_limit_mb: int = 1024
    cpu_limit: float = 1.0
    timeout_seconds: int = 300
    read_only_rootfs: bool = True
    drop_all_capabilities: bool = True
    network_disabled: bool = True  # Network severed post-clone to stop exfiltration
    user: str = "65532:65532"  # Unprivileged non-root user
    tmpfs_mounts: list[str] = Field(default_factory=lambda: ["/tmp:rw,noexec,nosuid,size=512m"])


class SandboxRunner:
    """Generates container and orchestrator execution flags adhering to Pod Security Restricted."""

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()

    def build_docker_run_command(
        self,
        image: str,
        workspace_host_path: str,
        scan_command: list[str]
    ) -> list[str]:
        """Constructs hardened docker run command with read-only rootfs and dropped caps."""
        cmd = [
            "docker", "run", "--rm",
            f"--memory={self.config.memory_limit_mb}m",
            f"--cpus={self.config.cpu_limit}",
            f"--user={self.config.user}",
        ]

        if self.config.read_only_rootfs:
            cmd.append("--read-only")

        if self.config.drop_all_capabilities:
            cmd.extend(["--cap-drop=ALL", "--security-opt=no-new-privileges"])

        if self.config.network_disabled:
            cmd.append("--network=none")

        for tmpfs in self.config.tmpfs_mounts:
            cmd.append(f"--tmpfs={tmpfs}")

        # Mount workspace as read-only volume inside container
        cmd.extend(["-v", f"{workspace_host_path}:/workspace:ro"])
        cmd.append(image)
        cmd.extend(scan_command)

        return cmd

    def build_k8s_security_context(self) -> dict[str, Any]:
        """Generates Kubernetes PodSecurity restricted security context specification."""
        return {
            "runAsNonRoot": True,
            "runAsUser": int(self.config.user.split(":")[0]),
            "readOnlyRootFilesystem": self.config.read_only_rootfs,
            "allowPrivilegeEscalation": False,
            "capabilities": {
                "drop": ["ALL"]
            },
            "seccompProfile": {
                "type": "RuntimeDefault"
            }
        }
