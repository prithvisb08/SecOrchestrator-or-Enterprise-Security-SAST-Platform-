import hmac
import json
from typing import Any

import httpx

from security_platform.analysis.orchestrator import ScanOrchestrator, ScanResult
from security_platform.core.logging import logger
from security_platform.persistence.repository import scan_repository
from security_platform.workers.queue import ScanJob, ScanJobQueue, default_scan_queue


class ScanWorker:
    """Asynchronous background worker consuming scan jobs and invoking orchestrators."""

    def __init__(
        self,
        job_queue: ScanJobQueue | None = None,
        orchestrator: ScanOrchestrator | None = None,
        webhook_secret: str = "secorch_webhook_signing_secret"
    ) -> None:
        self.queue = job_queue or default_scan_queue
        self.orchestrator = orchestrator or ScanOrchestrator()
        self.webhook_secret = webhook_secret

    def _dispatch_webhook(self, webhook_url: str, payload: dict[str, Any]) -> None:
        """Sends signed HMAC notification to subscriber URL upon scan completion."""
        try:
            body = json.dumps(payload)
            signature = hmac.new(
                self.webhook_secret.encode("utf-8"),
                body.encode("utf-8"),
                "sha256"
            ).hexdigest()

            headers = {
                "Content-Type": "application/json",
                "X-SecOrch-Signature": signature
            }
            with httpx.Client(timeout=10.0) as client:
                client.post(webhook_url, content=body, headers=headers)
            logger.info("Webhook dispatched successfully", extra={"url": webhook_url})
        except Exception as exc:
            logger.error("Failed to dispatch webhook callback", extra={"url": webhook_url, "error": str(exc)})

    def process_job(self, job: ScanJob) -> ScanResult:
        """Executes a single scan job end-to-end with status tracking and webhooks."""
        logger.info(
            "Worker started scan job",
            extra={"job_id": job.job_id, "scan_id": job.scan_id, "tenant_id": job.tenant_id}
        )

        scan_repository.save(
            tenant_id=job.tenant_id,
            scan_id=job.scan_id,
            data={
                "status": "RUNNING",
                "scan_id": job.scan_id,
                "tenant_id": job.tenant_id,
                "repository_id": job.repository_id
            }
        )

        try:
            result = self.orchestrator.run_scan(
                target_path=job.target_path,
                asset_criticality=job.asset_criticality,
                scan_id=job.scan_id,
                repository_id=job.repository_id
            )

            # Persist finished scan in repository
            scan_repository.save(
                tenant_id=job.tenant_id,
                scan_id=job.scan_id,
                data=result.model_dump(mode="json")
            )

            # Trigger optional webhook callback
            if job.webhook_url:
                payload = {
                    "event": "scan.completed",
                    "scan_id": job.scan_id,
                    "status": result.status,
                    "findings_count": result.findings_count,
                    "risk_score": result.risk_assessment.overall_risk_score,
                    "risk_level": str(result.risk_assessment.risk_level)
                }
                self._dispatch_webhook(job.webhook_url, payload)

            return result

        except Exception as exc:
            logger.error("Scan job execution failed", extra={"scan_id": job.scan_id, "error": str(exc)})
            scan_repository.save(
                tenant_id=job.tenant_id,
                scan_id=job.scan_id,
                data={
                    "status": "FAILED",
                    "scan_id": job.scan_id,
                    "tenant_id": job.tenant_id,
                    "error": str(exc)
                }
            )
            raise

    def process_one_available_job(self, timeout_seconds: float = 1.0) -> ScanResult | None:
        """Pulls and executes one job if available on the queue."""
        job = self.queue.dequeue(timeout_seconds=timeout_seconds)
        if job:
            return self.process_job(job)
        return None
