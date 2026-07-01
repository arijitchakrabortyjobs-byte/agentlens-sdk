"""Tests for AuditLog tamper-evident chain."""

import pytest
from agentlens.audit_log import AuditLog, AuditEvent, EventType, RiskTier


def make_event(**kwargs) -> AuditEvent:
    defaults = dict(
        trace_id="trace-1",
        session_id="session-1",
        event_type=EventType.AGENT_START,
        agent_id="test_agent",
    )
    defaults.update(kwargs)
    return AuditEvent(**defaults)


class TestAuditLogIntegrity:
    def test_empty_log_verifies(self):
        log = AuditLog("TestBank")
        assert log.verify_integrity() is True

    def test_single_event_chain(self):
        log = AuditLog("TestBank")
        e = log.append(make_event())
        assert e.previous_event_hash == "GENESIS"
        assert log.verify_integrity() is True

    def test_chained_events(self):
        log = AuditLog("TestBank")
        e1 = log.append(make_event(event_type=EventType.AGENT_START))
        e2 = log.append(make_event(event_type=EventType.DECISION))
        assert e2.previous_event_hash == e1.event_hash
        assert log.verify_integrity() is True

    def test_tamper_detected(self):
        log = AuditLog("TestBank")
        log.append(make_event(event_type=EventType.AGENT_START))
        e2 = log.append(make_event(event_type=EventType.DECISION))
        # Simulate tampering
        e2.decision_output = "TAMPERED"
        assert log.verify_integrity() is False

    def test_append_returns_event(self):
        log = AuditLog("TestBank")
        e = make_event()
        returned = log.append(e)
        assert returned is e

    def test_get_events_returns_copy(self):
        log = AuditLog("TestBank")
        log.append(make_event())
        events = log.get_events()
        events.clear()
        assert len(log.get_events()) == 1

    def test_ndjson_export(self):
        log = AuditLog("TestBank")
        log.append(make_event(event_type=EventType.AGENT_START))
        log.append(make_event(event_type=EventType.AGENT_END))
        ndjson = log.to_ndjson()
        lines = ndjson.strip().split("\n")
        assert len(lines) == 2
        import json
        for line in lines:
            obj = json.loads(line)
            assert "event_id" in obj
            assert "event_hash" in obj

    def test_summary(self):
        log = AuditLog("TestBank")
        log.append(make_event(event_type=EventType.AGENT_START))
        log.append(make_event(event_type=EventType.DECISION))
        s = log.summary()
        assert s["total_events"] == 2
        assert s["chain_intact"] is True
        assert s["decisions_recorded"] == 1

    def test_risk_tier_in_summary(self):
        log = AuditLog("TestBank")
        log.append(make_event(risk_tier=RiskTier.HIGH))
        log.append(make_event(risk_tier=RiskTier.LOW))
        s = log.summary()
        assert s["min_risk_tier"] == RiskTier.HIGH.value  # 1 is numerically smallest


class TestAuditEvent:
    def test_event_hash_computed_on_init(self):
        e = AuditEvent(agent_id="a", event_type=EventType.AGENT_START)
        assert len(e.event_hash) == 64  # SHA-256 hex

    def test_to_dict_serialises_enums(self):
        e = AuditEvent(
            agent_id="a",
            event_type=EventType.TOOL_CALL,
            risk_tier=RiskTier.HIGH,
        )
        d = e.to_dict()
        assert d["event_type"] == "agent.tool_call"
        assert d["risk_tier"] == 1
