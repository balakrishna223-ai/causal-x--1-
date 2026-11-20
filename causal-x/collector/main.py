"""
CAUSAL-X Tier 1 Local Collector Pipeline.

Pipeline order (non-negotiable):
1. Sample genuine local host telemetry via psutil (or explicit simulation via CLI).
2. Retain raw event locally in SQLite (raw_events).
3. Classify fields, redact sensitive IDs, block restricted secrets via PrivacyShield.
4. Build canonical JSON + SHA-256 + HMAC-SHA256 proof record before egress.
5. Enqueue into durable SQLite outbox_queue.
6. Authenticate with central backend JWT and deliver with exponential backoff.
"""

import argparse
from datetime import datetime, timezone
import logging
import os
import socket
import time
from typing import Any, Dict, Optional
import uuid

import httpx
import psutil

from buffer.sqlite_store import SQLiteCollectorStore
from config import CollectorSettings, get_collector_settings
from privacy.shield import PrivacyShield
from proof.proof_engine import ProofEngine
from simulator import SUPPORTED_SCENARIOS, build_simulated_events

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("causalx.collector")


class CollectorPipeline:
    def __init__(self, settings: CollectorSettings) -> None:
        self.settings = settings
        self.store = SQLiteCollectorStore(settings.causalx_sqlite_path)
        self.shield = PrivacyShield(
            pseudonym_salt=settings.pseudonym_salt,
            policy_version=settings.causalx_policy_version,
        )
        self.proof_engine = ProofEngine(
            hmac_secret=settings.collector_hmac_secret,
            policy_version=settings.causalx_policy_version,
        )
        self._jwt_token: Optional[str] = None
        self._last_heartbeat_ts: float = 0.0

    def sample_real_telemetry(self) -> Dict[str, Any]:
        cpu_pct = psutil.cpu_percent(interval=0.2)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        now_utc = datetime.now(timezone.utc)
        uptime_seconds = max(0.0, now_utc.timestamp() - psutil.boot_time())

        proc = psutil.Process(os.getpid())
        proc_mem_mb = round(proc.memory_info().rss / (1024 * 1024), 2)
        proc_cpu_pct = proc.cpu_percent(interval=None)
        raw_hostname = socket.gethostname()

        return {
            "event_id": str(uuid.uuid4()),
            "hostname": raw_hostname,
            "component": "host-system",
            "event_category": "infrastructure",
            "event_timestamp_utc": now_utc.isoformat(),
            "source_timezone": self.settings.causalx_source_timezone,
            "is_simulation": False,
            "cpu_usage": round(cpu_pct, 2),
            "memory_usage": round(mem.percent, 2),
            "disk_usage": round(disk.percent, 2),
            "net_bytes_sent": int(net.bytes_sent),
            "net_bytes_recv": int(net.bytes_recv),
            "network_latency_ms": 12.0,
            "packet_loss_pct": 0.0,
            "service_status": "healthy",
            "uptime_seconds": round(uptime_seconds, 1),
            "collector_rss_mb": proc_mem_mb,
            "collector_cpu_pct": round(proc_cpu_pct, 2),
            # Local-only identifier retained in SQLite, stripped before egress:
            "pid": proc.pid,
        }

    def process_raw_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Run local retention -> PrivacyShield -> ProofEngine -> SQLite Outbox."""
        shield_result = self.shield.apply(raw_event, self.settings.causalx_collector_id)
        self.store.save_raw_event(
            event_id=str(raw_event.get("event_id", uuid.uuid4())),
            raw_record=raw_event,
            raw_risk_score=shield_result.raw_risk_score,
        )
        envelope = self.proof_engine.build_proof_envelope(
            collector_id=self.settings.causalx_collector_id,
            tenant_slug=self.settings.causalx_tenant_slug,
            shield_result=shield_result,
        )
        self.store.save_local_proof_and_enqueue(envelope)
        return envelope

    def authenticate(self, client: httpx.Client) -> Optional[str]:
        url = f"{self.settings.causalx_backend_url.rstrip('/')}/api/v1/auth/login"
        try:
            resp = client.post(
                url,
                json={
                    "collector_id": self.settings.causalx_collector_id,
                    "collector_api_key": self.settings.causalx_collector_api_key,
                    "tenant_slug": self.settings.causalx_tenant_slug,
                },
                timeout=5.0,
            )
            if resp.status_code == 200:
                self._jwt_token = resp.json()["access_token"]
                return self._jwt_token
            logger.warning("Collector auth rejected status=%s", resp.status_code)
        except httpx.HTTPError as exc:
            logger.warning("Backend auth unreachable: %s", exc)
        return None

    def send_heartbeat(self, client: httpx.Client) -> None:
        now_ts = time.monotonic()
        if now_ts - self._last_heartbeat_ts < self.settings.causalx_heartbeat_seconds:
            return
        if not self._jwt_token and not self.authenticate(client):
            return

        proc = psutil.Process(os.getpid())
        url = f"{self.settings.causalx_backend_url.rstrip('/')}/api/v1/collectors/heartbeat"
        try:
            resp = client.post(
                url,
                headers={"Authorization": f"Bearer {self._jwt_token}"},
                json={
                    "collector_id": self.settings.causalx_collector_id,
                    "version": "1.0.0",
                    "source_timezone": self.settings.causalx_source_timezone,
                    "cpu_pct": round(proc.cpu_percent(interval=None), 2),
                    "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
                    "pending_outbox": self.store.count_pending(),
                },
                timeout=5.0,
            )
            if resp.status_code == 401:
                self._jwt_token = None
            elif resp.status_code in (200, 202):
                self._last_heartbeat_ts = now_ts
        except httpx.HTTPError:
            pass

    def flush_outbox(self, client: httpx.Client) -> int:
        due_items = self.store.get_due_outbox_items(limit=50)
        if not due_items:
            return 0
        if not self._jwt_token and not self.authenticate(client):
            for item in due_items:
                self.store.schedule_retry(item["payload_id"], item["retry_count"])
            return 0

        delivered_count = 0
        url = f"{self.settings.causalx_backend_url.rstrip('/')}/api/v1/telemetry"
        for item in due_items:
            try:
                resp = client.post(
                    url,
                    headers={"Authorization": f"Bearer {self._jwt_token}"},
                    json=item["envelope"],
                    timeout=5.0,
                )
                if resp.status_code == 401:
                    self._jwt_token = None
                    self.store.schedule_retry(item["payload_id"], item["retry_count"])
                    break
                if resp.status_code in (200, 201, 202):
                    self.store.mark_delivered(item["payload_id"])
                    delivered_count += 1
                else:
                    self.store.schedule_retry(item["payload_id"], item["retry_count"])
            except httpx.HTTPError:
                self.store.schedule_retry(item["payload_id"], item["retry_count"])
        return delivered_count


def main() -> None:
    parser = argparse.ArgumentParser(description="CAUSAL-X Local Telemetry Collector")
    parser.add_argument(
        "--inject",
        choices=SUPPORTED_SCENARIOS,
        default=None,
        help="Run a single clearly labelled controlled fault-injection scenario and exit",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Collect one real psutil sample, flush outbox once, and exit",
    )
    args = parser.parse_args()

    settings = get_collector_settings()
    pipeline = CollectorPipeline(settings)

    with httpx.Client() as client:
        if args.inject:
            events = build_simulated_events(args.inject, settings.causalx_source_timezone)
            for evt in events:
                env = pipeline.process_raw_event(evt)
                logger.info(
                    "Simulated scenario=%s payload_id=%s blocked=%s decision=%s",
                    args.inject,
                    env["payload_id"],
                    env["blocked_fields"],
                    env["approval_decision"],
                )
            sent = pipeline.flush_outbox(client)
            logger.info("Outbox flush delivered=%d pending=%d", sent, pipeline.store.count_pending())
            return

        logger.info(
            "Starting CAUSAL-X Collector id=%s tenant=%s poll=%.1fs",
            settings.causalx_collector_id,
            settings.causalx_tenant_slug,
            settings.causalx_collector_poll_seconds,
        )
        while True:
            raw_sample = pipeline.sample_real_telemetry()
            envelope = pipeline.process_raw_event(raw_sample)
            pipeline.send_heartbeat(client)
            sent = pipeline.flush_outbox(client)
            logger.info(
                "Sample payload_id=%s cpu=%.1f%% mem=%.1f%% sent=%d pending_outbox=%d",
                envelope["payload_id"],
                raw_sample["cpu_usage"],
                raw_sample["memory_usage"],
                sent,
                pipeline.store.count_pending(),
            )
            if args.once:
                break
            time.sleep(settings.causalx_collector_poll_seconds)


if __name__ == "__main__":
    main()
