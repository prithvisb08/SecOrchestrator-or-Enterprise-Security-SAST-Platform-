# ADR-003: Ephemeral Container Sandboxing for Multi-Tenant Scans

## Status
Accepted

## Context
Running third-party or untrusted customer code analysis within the API server host process exposes the system to remote code execution (RCE), malicious repository setups, zip bombs, and unauthorized network exfiltration.

## Decision
Every scan job executes in an isolated, ephemeral container sandbox (`SandboxRunner` / Kubernetes Job):
1. **Unprivileged Execution:** UID/GID 65532, `runAsNonRoot: true`.
2. **Read-Only Root Filesystem:** Root filesystem is mounted read-only (`--read-only`), with temporary in-memory tmpfs limits.
3. **Dropped Capabilities:** Drops `ALL` Linux capabilities with `no-new-privileges`.
4. **Network Isolation:** After initial git clone or archive upload, network access is severed (`--network=none` / Kubernetes `NetworkPolicy`).
5. **Strict Limits:** Hard CPU, memory (max 2GiB), and runtime wall-clock timeouts.
