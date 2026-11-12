import queue
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class ScanJob(BaseModel):
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    tenant_id: str
    repository_id: str
    target_path: str
    asset_criticality: float = 1.0
    webhook_url: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanJobQueue:
    """Thread-safe and Redis-compatible job queue for scan dispatch."""

    def __init__(self, redis_url: str | None = None) -> None:
        self.redis_url = redis_url
        self._local_queue: queue.Queue[ScanJob] = queue.Queue()

    def enqueue(self, job: ScanJob) -> None:
        """Enqueues a new scan job for worker execution."""
        self._local_queue.put(job)

    def dequeue(self, timeout_seconds: float = 2.0) -> ScanJob | None:
        """Pulls the next available job, waiting up to timeout_seconds."""
        try:
            return self._local_queue.get(timeout=timeout_seconds)
        except queue.Empty:
            return None

    def size(self) -> int:
        return self._local_queue.qsize()

    def clear(self) -> None:
        with self._local_queue.mutex:
            self._local_queue.queue.clear()


default_scan_queue = ScanJobQueue()
