"""
Controlled fault-injection telemetry generator for CAUSAL-X testing & demos.

IMPORTANT: Every event emitted by this module is explicitly tagged with
`is_simulation = True` and `telemetry_origin = "CONTROLLED_SIMULATION"` so it is
never confused with real host metrics gathered by psutil.
"""

import argparse
from datetime import datetime, timezone
import json
from typing import Any, Dict, List
import uuid


SUPPORTED_SCENARIOS = (
    "normal",
    "sensitive_secret",
    "failed_logins",
    "network_latency",
    "cpu_memory_spike",
    "cascading_outage",
)


def build_simulated_events(scenario: str, source_timezone: str = "UTC") -> List[Dict[str, Any]]:
    if scenario not in SUPPORTED_SCENARIOS:
        raise ValueError(f"Unsupported scenario '{scenario}'. Choose from: {SUPPORTED_SCENARIOS}")

    now_utc = datetime.now(timezone.utc).isoformat()
    base = {
        "event_id": str(uuid.uuid4()),
        "event_timestamp_utc": now_utc,
        "source_timezone": source_timezone,
        "is_simulation": True,
        "telemetry_origin": "CONTROLLED_SIMULATION",
    }

    if scenario == "normal":
        return [
            {
                **base,
                "hostname": "prod-app-node-01.internal",
                "component": "api-gateway",
                "event_category": "infrastructure",
                "cpu_usage": 32.4,
                "memory_usage": 54.1,
                "disk_usage": 48.0,
                "network_latency_ms": 18.5,
                "packet_loss_pct": 0.0,
                "service_status": "healthy",
            }
        ]

    if scenario == "sensitive_secret":
        return [
            {
                **base,
                "hostname": "prod-auth-node-02.internal",
                "internal_ip": "10.24.18.42",
                "username": "ops_admin",
                "password": "SIMULATED_ONLY_PASSWORD_VALUE",
                "api_key": "SIMULATED_ONLY_API_KEY_TOKEN",
                "component": "auth-service",
                "event_category": "security",
                "cpu_usage": 64.2,
                "memory_usage": 71.8,
                "service_status": "healthy",
                "raw_log": "SIMULATED LOG: auth attempt user=ops_admin bearer=SIMULATED_BEARER_XYZ",
            }
        ]

    if scenario == "failed_logins":
        return [
            {
                **base,
                "hostname": "edge-bastion-01.internal",
                "username": "deploy_svc",
                "internal_ip": "10.0.12.99",
                "component": "identity-gateway",
                "event_category": "security",
                "failed_login_count": 19,
                "cpu_usage": 44.0,
                "memory_usage": 58.0,
                "service_status": "degraded",
            }
        ]

    if scenario == "network_latency":
        return [
            {
                **base,
                "hostname": "core-router-01.internal",
                "component": "ingress-network",
                "event_category": "network",
                "cpu_usage": 52.0,
                "memory_usage": 61.5,
                "network_latency_ms": 345.0,
                "packet_loss_pct": 8.4,
                "service_status": "degraded",
            }
        ]

    if scenario == "cpu_memory_spike":
        return [
            {
                **base,
                "hostname": "compute-worker-04.internal",
                "component": "analytics-worker",
                "event_category": "compute",
                "cpu_usage": 96.8,
                "memory_usage": 94.2,
                "disk_usage": 72.1,
                "network_latency_ms": 42.0,
                "packet_loss_pct": 0.2,
                "service_status": "degraded",
            }
        ]

    # cascading_outage
    return [
        {
            **base,
            "event_id": str(uuid.uuid4()),
            "hostname": "compute-worker-01.internal",
            "component": "api-gateway",
            "event_category": "compute",
            "cpu_usage": 95.4,
            "memory_usage": 92.7,
            "network_latency_ms": 265.0,
            "packet_loss_pct": 6.8,
            "service_status": "degraded",
        },
        {
            **base,
            "event_id": str(uuid.uuid4()),
            "hostname": "primary-postgres-01.internal",
            "component": "database-cluster",
            "event_category": "database",
            "cpu_usage": 91.2,
            "memory_usage": 93.5,
            "network_latency_ms": 310.0,
            "packet_loss_pct": 7.1,
            "service_status": "unavailable",
        },
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CAUSAL-X controlled fault-injection simulator (clearly labelled simulations)"
    )
    parser.add_argument(
        "--scenario",
        choices=SUPPORTED_SCENARIOS,
        default="normal",
        help="Controlled simulation scenario to generate",
    )
    args = parser.parse_args()
    events = build_simulated_events(args.scenario)
    print(json.dumps(events, indent=2))


if __name__ == "__main__":
    main()
