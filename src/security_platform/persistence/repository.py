import threading
from typing import Any


class ScanRepository:
    """Thread-safe, tenant-isolated in-memory and database-ready scan storage."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # storage: { tenant_id: { scan_id: result_dict } }
        self._storage: dict[str, dict[str, dict[str, Any]]] = {}

    def save(self, tenant_id: str, scan_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            if tenant_id not in self._storage:
                self._storage[tenant_id] = {}
            self._storage[tenant_id][scan_id] = data

    def get(self, tenant_id: str, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            tenant_scans = self._storage.get(tenant_id, {})
            return tenant_scans.get(scan_id)

    def list_by_tenant(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._lock:
            tenant_scans = self._storage.get(tenant_id, {})
            return list(tenant_scans.values())

    def clear(self) -> None:
        with self._lock:
            self._storage.clear()


scan_repository = ScanRepository()
