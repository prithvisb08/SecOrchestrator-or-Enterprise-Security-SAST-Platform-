import datetime
import os
from pathlib import Path


class ArtifactStore:
    """Manages secure persistence and retention of scan artifacts (SARIF, SBOMs, raw logs)."""

    def __init__(self, base_storage_dir: Path | str | None = None) -> None:
        target = base_storage_dir if base_storage_dir is not None else os.getenv("SEC_ORCH_ARTIFACT_DIR", "/tmp/secorch_artifacts")
        self.base_dir = Path(target)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_target_dir(self, tenant_id: str, scan_id: str) -> Path:
        target = self.base_dir / tenant_id / scan_id
        target.mkdir(parents=True, exist_ok=True)
        return target

    def save_artifact(
        self,
        tenant_id: str,
        scan_id: str,
        filename: str,
        content: str | bytes,
        retention_days: int = 90
    ) -> Path:
        """Stores artifact with tenant isolation and retention metadata."""
        target_dir = self._get_target_dir(tenant_id, scan_id)
        file_path = target_dir / filename

        if isinstance(content, str):
            file_path.write_text(content, encoding="utf-8")
        else:
            file_path.write_bytes(content)

        # Store retention metadata
        meta_file = target_dir / f"{filename}.metadata.json"
        expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=retention_days)
        meta_file.write_text(
            f'{{"filename": "{filename}", "retention_days": {retention_days}, "expires_at": "{expires_at.isoformat()}"}}',
            encoding="utf-8"
        )
        return file_path

    def load_artifact(self, tenant_id: str, scan_id: str, filename: str) -> bytes | None:
        file_path = self.base_dir / tenant_id / scan_id / filename
        if file_path.exists():
            return file_path.read_bytes()
        return None

    def delete_expired_artifacts(self) -> int:
        """Prunes expired artifacts based on retention policies."""
        # Simple local cleanup loop
        deleted_count = 0
        now = datetime.datetime.now(datetime.UTC)
        for meta in self.base_dir.rglob("*.metadata.json"):
            try:
                import json
                data = json.loads(meta.read_text(encoding="utf-8"))
                exp_dt = datetime.datetime.fromisoformat(data["expires_at"])
                if now > exp_dt:
                    data_file = meta.parent / data["filename"]
                    if data_file.exists():
                        data_file.unlink()
                    meta.unlink()
                    deleted_count += 1
            except Exception:
                continue
        return deleted_count


default_artifact_store = ArtifactStore()
