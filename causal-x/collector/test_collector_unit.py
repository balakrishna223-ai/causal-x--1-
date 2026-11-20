import tempfile
import unittest

from buffer.sqlite_store import SQLiteCollectorStore
from privacy.classifier import ClassificationLevel, classify_record
from privacy.shield import PrivacyShield, pseudonymize_identifier
from proof.proof_engine import ProofEngine, canonicalize_json, compute_hmac, compute_sha256


class CollectorPrivacyProofOutboxTests(unittest.TestCase):
    def test_pseudonymization_is_deterministic_hmac(self) -> None:
        a = pseudonymize_identifier("prod-node-01", "salt-1")
        b = pseudonymize_identifier("prod-node-01", "salt-1")
        c = pseudonymize_identifier("prod-node-01", "salt-2")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("src_"))

    def test_restricted_fields_classified_100_and_stripped(self) -> None:
        raw = {
            "hostname": "internal-host-01",
            "username": "alice",
            "password": "SIMULATED_PASSWORD",
            "access_token": "Bearer eyJ12345.abc.xyz",
            "cpu_usage": 82.4,
            "memory_usage": 77.1,
            "event_timestamp_utc": "2026-11-20T10:00:00Z",
        }
        classes, max_risk = classify_record(raw)
        self.assertEqual(max_risk, 100)
        by_name = {c.field_name: c.level for c in classes}
        self.assertEqual(by_name["password"], ClassificationLevel.RESTRICTED)
        self.assertEqual(by_name["access_token"], ClassificationLevel.RESTRICTED)
        self.assertEqual(by_name["username"], ClassificationLevel.SENSITIVE)
        self.assertEqual(by_name["cpu_usage"], ClassificationLevel.SAFE)

        shield = PrivacyShield(pseudonym_salt="salt-1")
        result = shield.apply(raw, "collector-local-01")
        self.assertEqual(result.approval_decision, "APPROVED")
        self.assertEqual(result.egress_risk_score, 0)
        self.assertNotIn("password", result.approved_metadata)
        self.assertNotIn("access_token", result.approved_metadata)
        self.assertNotIn("username", result.approved_metadata)
        self.assertIn("password", result.blocked_fields)
        self.assertIn("access_token", result.blocked_fields)

    def test_proof_engine_and_sqlite_outbox_backoff(self) -> None:
        shield = PrivacyShield(pseudonym_salt="salt-1")
        proof_engine = ProofEngine(hmac_secret="hmac-secret-1")
        res = shield.apply(
            {"cpu_usage": 51.2, "memory_usage": 62.3, "event_timestamp_utc": "2026-11-20T10:00:00Z"},
            "collector-local-01",
        )
        env = proof_engine.build_proof_envelope("collector-local-01", "acme-cloud", res)

        canon = canonicalize_json(env["approved_metadata"])
        self.assertEqual(env["payload_hash_sha256"], compute_sha256(canon))
        self.assertEqual(env["hmac_signature"], compute_hmac("hmac-secret-1", canon))

        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteCollectorStore(f"{tmpdir}/local.db")
            store.save_raw_event("evt-1", {"password": "secret", "cpu_usage": 51.2}, 100)
            store.save_local_proof_and_enqueue(env)
            self.assertEqual(store.count_pending(), 1)
            self.assertEqual(len(store.list_raw_events()), 1)

            store.mark_delivered(env["payload_id"])
            self.assertEqual(store.count_pending(), 0)
            self.assertEqual(store.count_delivered(), 1)


if __name__ == "__main__":
    unittest.main()
