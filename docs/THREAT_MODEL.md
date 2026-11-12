# Threat Model: SecOrchestrator Platform (STRIDE Analysis)

This document provides a systematic STRIDE threat modeling assessment of the SecOrchestrator SAST Platform.

## 1. System Scope & Trust Boundaries

```
[Untrusted Client / VCS Webhook]
             │
             ▼ (HTTPS / TLS 1.3 + HMAC-SHA256)
┌──────────────────────────────────────────────┐
│  SecOrchestrator API (Boundary 1)            │
│  - JWT / API Key RBAC Authentication         │
│  - Strict Path Traversal Validation          │
│  - Anti-Zip Slip / Anti-Zip Bomb Loader      │
└──────────────────────┬───────────────────────┘
                       │
                       ▼ (Internal Encrypted Network)
┌──────────────────────────────────────────────┐
│  Scan Worker & Sandbox Runner (Boundary 2)   │
│  - Non-Root UID 65532                        │
│  - Read-Only Root Filesystem                 │
│  - Network Severed (--network=none)          │
│  - Memory, CPU, and Process Limits           │
└──────────────────────┬───────────────────────┘
                       │
                       ▼ (Tenant Isolation via row-level tenant_id)
┌──────────────────────────────────────────────┐
│  Data Layer: PostgreSQL & S3 Artifact Store  │
└──────────────────────────────────────────────┘
```

## 2. STRIDE Threat Matrix & Mitigations

| Category | Threat Description | Severity | Platform Mitigation & Security Hardening |
|---|---|---|---|
| **Spoofing** | Attacker impersonates an admin or sends forged GitHub webhooks | CRITICAL | Signed JWT with HS256/RS256, API Key validation, and constant-time HMAC-SHA256 signature verification for VCS webhooks. |
| **Tampering** | Malicious repository crafted with Zip Slip, symlinks, or path traversal to overwrite host files | CRITICAL | `ArchiveLoader` rejects path traversal (`../`), extracts strictly inside temp workspace, refuses symlinks/hardlinks, and enforces zip bomb ratio & max file limits. |
| **Repudiation** | User denies approving a high-risk finding or altering security policy | HIGH | Immutable `TriageAuditEntry` and `AuditLogRecord` written to database for every status transition, requiring approver ID and rationale. |
| **Information Disclosure** | Secret scanner dumps cleartext API tokens in logs, scan reports, or UI | HIGH | Automatic line redaction with zero-exposure policy; secret hashes computed with tenant-salted SHA-256 (`salt + secret`). |
| **Denial of Service** | Malicious recursive AST or 50GB file exhausting memory/CPU on server | HIGH | AST recursion depth guard, file size limit (10MB per file), worker memory cgroup limit (2GiB), and per-scan timeout. |
| **Elevation of Privilege** | Malicious package or code executes commands in the host environment | CRITICAL | `SandboxRunner` executes all scans in ephemeral non-root container (UID 65532), read-only rootfs, drop `ALL` capabilities, `--network=none`. |
