"""
Phase 0 test suite — production-safe foundation.

Tests all four Phase 0 components:
  0a. WORM Storage adapters
  0b. Pre-model PII firewall
  0c. Cross-session override rate / compliance DB
  0d. OTEL export (graceful degradation)

All tests run offline with zero external dependencies.
Run with:  pytest tests/test_phase0.py -v
"""

import json
import os
import tempfile
import pytest

from agentlens.audit_log import AuditLog, AuditEvent, EventType, RiskTier


# ─────────────────────────────────────────────────────────────────────────────
# 0a. WORM Storage
# ─────────────────────────────────────────────────────────────────────────────

class TestLocalNDJSONAdapter:

    def test_writes_event_to_file(self, tmp_path):
        from agentlens.storage import LocalNDJSONAdapter
        adapter = LocalNDJSONAdapter(base_dir=str(tmp_path))
        log = AuditLog(entity_name="TestBank", storage_adapter=adapter)
        log.append(AuditEvent(agent_id="agent1", event_type=EventType.AGENT_START))

        files = list(tmp_path.rglob("*.ndjson"))
        assert len(files) == 1
        lines = files[0].read_text().strip().split("\n")
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["agent_id"] == "agent1"

    def test_multiple_events_append_not_overwrite(self, tmp_path):
        from agentlens.storage import LocalNDJSONAdapter
        adapter = LocalNDJSONAdapter(base_dir=str(tmp_path))
        log = AuditLog(entity_name="TestBank", storage_adapter=adapter)
        log.append(AuditEvent(agent_id="agent1", event_type=EventType.AGENT_START))
        log.append(AuditEvent(agent_id="agent1", event_type=EventType.AGENT_END))

        files = list(tmp_path.rglob("*.ndjson"))
        lines = files[0].read_text().strip().split("\n")
        assert len(lines) == 2

    def test_chain_still_intact_with_storage(self, tmp_path):
        from agentlens.storage import LocalNDJSONAdapter
        adapter = LocalNDJSONAdapter(base_dir=str(tmp_path))
        log = AuditLog(entity_name="TestBank", storage_adapter=adapter)
        log.append(AuditEvent(agent_id="a", event_type=EventType.AGENT_START))
        log.append(AuditEvent(agent_id="a", event_type=EventType.DECISION))
        assert log.verify_integrity() is True

    def test_health_check_returns_dict(self, tmp_path):
        from agentlens.storage import LocalNDJSONAdapter
        adapter = LocalNDJSONAdapter(base_dir=str(tmp_path))
        hc = adapter.health_check()
        assert hc["adapter"] == "LocalNDJSONAdapter"
        assert "base_dir" in hc

    def test_persisted_json_is_valid_audit_event(self, tmp_path):
        from agentlens.storage import LocalNDJSONAdapter
        adapter = LocalNDJSONAdapter(base_dir=str(tmp_path))
        log = AuditLog(entity_name="TestBank", storage_adapter=adapter)
        event = AuditEvent(
            agent_id="credit_agent",
            event_type=EventType.DECISION,
            risk_tier=RiskTier.HIGH,
            human_readable_reasoning="Approved: CIBIL 724",
        )
        log.append(event)
        files = list(tmp_path.rglob("*.ndjson"))
        obj = json.loads(files[0].read_text())
        assert obj["event_type"] == "agent.decision"
        assert obj["risk_tier"] == 1
        assert obj["human_readable_reasoning"] == "Approved: CIBIL 724"
        assert len(obj["event_hash"]) == 64


class TestMultiAdapter:

    def test_writes_to_all_adapters(self, tmp_path):
        from agentlens.storage import LocalNDJSONAdapter, MultiAdapter
        dir1 = tmp_path / "store1"
        dir2 = tmp_path / "store2"
        adapter = MultiAdapter([
            LocalNDJSONAdapter(str(dir1)),
            LocalNDJSONAdapter(str(dir2)),
        ])
        log = AuditLog(entity_name="TestBank", storage_adapter=adapter)
        log.append(AuditEvent(agent_id="a", event_type=EventType.AGENT_START))

        assert len(list(dir1.rglob("*.ndjson"))) == 1
        assert len(list(dir2.rglob("*.ndjson"))) == 1

    def test_one_adapter_failure_does_not_raise(self, tmp_path):
        """A failing adapter records an error but does not crash the audit chain."""
        from agentlens.storage import LocalNDJSONAdapter, MultiAdapter, WORMStorageAdapter

        class BrokenAdapter(WORMStorageAdapter):
            def write(self, event):
                raise RuntimeError("Simulated S3 outage")
            def health_check(self):
                return {"error": "broken"}

        good_dir = tmp_path / "good"
        adapter = MultiAdapter([BrokenAdapter(), LocalNDJSONAdapter(str(good_dir))])
        log = AuditLog(entity_name="TestBank", storage_adapter=adapter)
        log.append(AuditEvent(agent_id="a", event_type=EventType.AGENT_START))

        # Good adapter still wrote
        assert len(list(good_dir.rglob("*.ndjson"))) == 1
        # No exception was raised


class TestS3AdapterNoBoto3:
    def test_s3_adapter_graceful_without_boto3(self, monkeypatch):
        """S3ObjectLockAdapter must not crash at import or init without boto3."""
        import agentlens.storage as storage_mod
        monkeypatch.setattr(storage_mod, "_OTEL_AVAILABLE", False, raising=False)
        from agentlens.storage import S3ObjectLockAdapter
        adapter = S3ObjectLockAdapter(bucket="test-bucket", region="ap-south-1")
        hc = adapter.health_check()
        # Either works or reports missing boto3 — must not raise
        assert "adapter" in hc or "error" in hc


# ─────────────────────────────────────────────────────────────────────────────
# 0b. PII Firewall
# ─────────────────────────────────────────────────────────────────────────────

class TestTokenizePII:

    def test_pan_tokenized(self):
        from agentlens.pii_firewall import tokenize_pii
        clean, vault = tokenize_pii("My PAN is ABCDE1234F please help")
        assert "ABCDE1234F" not in clean
        assert "[PAN_1]" in clean
        assert "PAN" in vault.pii_types_found

    def test_aadhaar_tokenized(self):
        from agentlens.pii_firewall import tokenize_pii
        clean, vault = tokenize_pii("Aadhaar: 1234 5678 9012")
        assert "1234 5678 9012" not in clean
        assert "[AADHAAR_1]" in clean

    def test_phone_tokenized(self):
        from agentlens.pii_firewall import tokenize_pii
        clean, vault = tokenize_pii("Call me on 9876543210")
        assert "9876543210" not in clean
        assert "[PHONE_1]" in clean

    def test_email_tokenized(self):
        from agentlens.pii_firewall import tokenize_pii
        clean, vault = tokenize_pii("Email me at user@example.com")
        assert "user@example.com" not in clean
        assert "[EMAIL_1]" in clean

    def test_toll_free_not_tokenized(self):
        from agentlens.pii_firewall import tokenize_pii
        clean, vault = tokenize_pii("Call our helpline 1800-123-4567")
        # 1800 numbers are institutional — must not be tokenized
        assert "1800" in clean
        assert "PHONE" not in vault.pii_types_found

    def test_multiple_pii_types_in_one_message(self):
        from agentlens.pii_firewall import tokenize_pii
        text = "PAN: ABCDE1234F, Aadhaar: 1234 5678 9012, Phone: 9876543210"
        clean, vault = tokenize_pii(text)
        assert "ABCDE1234F" not in clean
        assert "1234 5678 9012" not in clean
        assert "9876543210" not in clean
        assert vault.token_count >= 3

    def test_vault_restore_round_trips(self):
        from agentlens.pii_firewall import tokenize_pii
        original = "My PAN is ABCDE1234F"
        clean, vault = tokenize_pii(original)
        restored = vault.restore(clean)
        assert restored == original

    def test_no_pii_returns_unchanged(self):
        from agentlens.pii_firewall import tokenize_pii
        text = "What is my loan eligibility?"
        clean, vault = tokenize_pii(text)
        assert clean == text
        assert vault.token_count == 0

    def test_firewall_messages_only_filters_user_role(self):
        from agentlens.pii_firewall import firewall_messages
        messages = [
            {"role": "system", "content": "You are a banking assistant."},
            {"role": "user", "content": "My PAN ABCDE1234F, Aadhaar 1234 5678 9012"},
            {"role": "assistant", "content": "Thank you for sharing."},
        ]
        clean, vault = firewall_messages(messages)
        # System and assistant messages unchanged
        assert clean[0]["content"] == "You are a banking assistant."
        assert clean[2]["content"] == "Thank you for sharing."
        # User message tokenized
        assert "ABCDE1234F" not in clean[1]["content"]
        assert vault.token_count > 0

    def test_firewall_disabled_passes_through(self):
        from agentlens.pii_firewall import firewall_messages
        messages = [{"role": "user", "content": "PAN ABCDE1234F"}]
        clean, vault = firewall_messages(messages, enabled=False)
        assert clean[0]["content"] == "PAN ABCDE1234F"
        assert vault.token_count == 0


class TestChatTracerPIIFirewall:

    def test_llm_never_sees_raw_pan(self):
        """ChatSessionTracer must pass tokenized messages to llm_adapter."""
        from agentlens import ChatSessionTracer, ModelCard
        from agentlens.config import AgentLensConfig, EntityType, RegulatoryFramework
        from agentlens.audit_log import RiskTier

        seen_by_llm = []

        def mock_adapter(messages, system):
            seen_by_llm.extend(messages)
            return "I have noted your information.", 10, 8

        config = AgentLensConfig(
            entity_name="TestBank",
            entity_type=EntityType.NBFC,
            pii_masking_enabled=True,
            board_policy_ref="TEST_POLICY_v1",
        )
        card = ModelCard(
            model_id="mock-model", model_version="1.0",
            provider="mock", risk_tier=RiskTier.MEDIUM,
            intended_use="test",
        )
        with ChatSessionTracer(
            config=config, model_card=card,
            llm_adapter=mock_adapter, consent_ref="CONSENT-001",
        ) as tracer:
            tracer.send("My PAN is ABCDE1234F, am I eligible for a loan?")

        user_messages = [m["content"] for m in seen_by_llm if m["role"] == "user"]
        assert all("ABCDE1234F" not in m for m in user_messages), \
            "Raw PAN reached the LLM — firewall not working"
        assert any("[PAN_1]" in m for m in user_messages), \
            "Tokenized PAN not found in messages sent to LLM"


# ─────────────────────────────────────────────────────────────────────────────
# 0c. Compliance Database
# ─────────────────────────────────────────────────────────────────────────────

class TestComplianceDatabase:

    @pytest.fixture
    def db(self, tmp_path):
        from agentlens.compliance_db import ComplianceDatabase
        return ComplianceDatabase(db_path=str(tmp_path / "compliance.db"))

    def test_record_and_retrieve(self, db):
        db.record_session({
            "session_id": "s-001",
            "entity": "TestBank",
            "decisions_recorded": 10,
            "human_overrides": 2,
            "chain_intact": True,
        })
        summary = db.entity_summary("TestBank")
        assert summary["total_sessions"] == 1
        assert summary["total_decisions"] == 10
        assert summary["total_human_overrides"] == 2

    def test_override_rate_calculation(self, db):
        db.record_session({"session_id": "s-001", "entity": "Bank", "decisions_recorded": 10, "human_overrides": 1, "chain_intact": True})
        db.record_session({"session_id": "s-002", "entity": "Bank", "decisions_recorded": 10, "human_overrides": 0, "chain_intact": True})
        rate = db.override_rate("Bank")
        assert rate == pytest.approx(0.05, abs=0.01)  # 1/20

    def test_zero_override_rate_when_no_decisions(self, db):
        rate = db.override_rate("NonExistent")
        assert rate == 0.0

    def test_rubber_stamp_detection(self, db):
        # Session with 0 overrides and 8 decisions — should be flagged
        db.record_session({"session_id": "s-rubber", "entity": "Bank", "decisions_recorded": 8, "human_overrides": 0, "chain_intact": True})
        # Session with overrides — should NOT be flagged
        db.record_session({"session_id": "s-good",   "entity": "Bank", "decisions_recorded": 8, "human_overrides": 2, "chain_intact": True})
        stamps = db.rubber_stamp_sessions("Bank", min_decisions=5)
        assert "s-rubber" in stamps
        assert "s-good" not in stamps

    def test_rubber_stamp_ignores_low_decision_count(self, db):
        # Only 2 decisions — below min_decisions threshold, should not be flagged
        db.record_session({"session_id": "s-tiny", "entity": "Bank", "decisions_recorded": 2, "human_overrides": 0, "chain_intact": True})
        stamps = db.rubber_stamp_sessions("Bank", min_decisions=5)
        assert "s-tiny" not in stamps

    def test_idempotent_record(self, db):
        db.record_session({"session_id": "s-001", "entity": "Bank", "decisions_recorded": 10, "human_overrides": 1, "chain_intact": True})
        db.record_session({"session_id": "s-001", "entity": "Bank", "decisions_recorded": 10, "human_overrides": 1, "chain_intact": True})
        summary = db.entity_summary("Bank")
        assert summary["total_sessions"] == 1  # not duplicated

    def test_last_n_sessions_window(self, db):
        for i in range(5):
            db.record_session({"session_id": f"s-{i:03d}", "entity": "Bank", "decisions_recorded": 10, "human_overrides": 0, "chain_intact": True})
        # Add one recent session with overrides
        db.record_session({"session_id": "s-recent", "entity": "Bank", "decisions_recorded": 10, "human_overrides": 5, "chain_intact": True})
        # Only looking at last 1 session — rate should be 50%
        rate = db.override_rate("Bank", last_n_sessions=1)
        assert rate == pytest.approx(0.5, abs=0.01)

    def test_responsibility_map(self, db):
        db.set_responsibility_map(
            entity_name="Bank",
            developer="AgentLens Ltd.",
            platform="AWS Mumbai",
            deployer="Bank IT Team",
            end_user_ref="retail_banking",
        )
        rmap = db.get_responsibility_map("Bank")
        roles = {r["role"] for r in rmap}
        assert "developer" in roles
        assert "platform" in roles
        assert "deployer" in roles

    def test_entity_summary_rubber_stamp_flag(self, db):
        db.record_session({"session_id": "s-001", "entity": "Bank", "decisions_recorded": 10, "human_overrides": 0, "chain_intact": True})
        summary = db.entity_summary("Bank")
        assert summary["rubber_stamp_flag"] is True


class TestComplianceReporterCrossSession:

    def test_cross_session_report_without_db(self):
        from agentlens import ComplianceReporter, AgentLensConfig
        from agentlens.config import EntityType
        config = AgentLensConfig(entity_name="Bank", entity_type=EntityType.NBFC, board_policy_ref="P1")
        log = AuditLog("Bank")
        reporter = ComplianceReporter(log, config)
        result = reporter.cross_session_report()
        assert "error" in result

    def test_cross_session_report_with_db(self, tmp_path):
        from agentlens import ComplianceReporter, AgentLensConfig
        from agentlens.compliance_db import ComplianceDatabase
        from agentlens.config import EntityType
        db = ComplianceDatabase(str(tmp_path / "c.db"))
        db.record_session({"session_id": "x-001", "entity": "Bank", "decisions_recorded": 5, "human_overrides": 1, "chain_intact": True})
        config = AgentLensConfig(entity_name="Bank", entity_type=EntityType.NBFC, board_policy_ref="P1")
        log = AuditLog("Bank")
        reporter = ComplianceReporter(log, config, compliance_db=db)
        result = reporter.cross_session_report()
        assert result["entity"] == "Bank"
        assert "override_rate" in result
        assert "rubber_stamp_flag" in result

    def test_override_rate_in_audit_log_summary(self):
        log = AuditLog("Bank")
        e1 = AuditEvent(agent_id="a", event_type=EventType.DECISION)
        e2 = AuditEvent(agent_id="a", event_type=EventType.DECISION)
        e2.human_override = True
        log.append(e1)
        log.append(e2)
        s = log.summary()
        assert "override_rate" in s
        assert s["override_rate"] == pytest.approx(0.5)


# ─────────────────────────────────────────────────────────────────────────────
# 0d. OTEL Export
# ─────────────────────────────────────────────────────────────────────────────

class TestOTELExporter:

    def test_graceful_degradation_without_sdk(self):
        from agentlens.otel import OTELExporter
        exporter = OTELExporter(endpoint="http://localhost:4317")
        hc = exporter.health_check()
        # Must not raise regardless of whether opentelemetry is installed
        assert "adapter" in hc or "exporter" in hc
        assert "initialised" in hc

    def test_emit_is_noop_without_sdk(self):
        from agentlens.otel import OTELExporter
        exporter = OTELExporter(endpoint="http://localhost:4317")
        event = AuditEvent(agent_id="a", event_type=EventType.DECISION)
        # Must not raise
        exporter.emit(event)

    def test_audit_log_with_otel_exporter_does_not_crash(self):
        from agentlens.otel import OTELExporter
        exporter = OTELExporter(endpoint="http://localhost:4317")
        log = AuditLog("Bank", otel_exporter=exporter)
        log.append(AuditEvent(agent_id="a", event_type=EventType.AGENT_START))
        assert log.verify_integrity() is True

    def test_otel_failure_does_not_break_chain(self, tmp_path):
        """Even if OTEL emit raises, the audit chain must remain intact."""
        from agentlens.otel import OTELExporter
        from agentlens.storage import LocalNDJSONAdapter

        class BrokenOTEL(OTELExporter):
            def emit(self, event):
                raise RuntimeError("OTEL collector down")

        exporter = BrokenOTEL(endpoint="http://broken:4317")
        adapter = LocalNDJSONAdapter(str(tmp_path))
        log = AuditLog("Bank", storage_adapter=adapter, otel_exporter=exporter)
        log.append(AuditEvent(agent_id="a", event_type=EventType.AGENT_START))
        log.append(AuditEvent(agent_id="a", event_type=EventType.AGENT_END))
        assert log.verify_integrity() is True
