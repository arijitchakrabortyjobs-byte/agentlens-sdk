"""Tests for AuditTracer and AgentSpan."""

import pytest
from agentlens.tracer import AuditTracer, AgentSpan
from agentlens.config import AgentLensConfig, EntityType, RegulatoryFramework
from agentlens.audit_log import EventType, RiskTier
from agentlens.policy import PolicyEngine, RBIPolicy


def make_config(**kwargs) -> AgentLensConfig:
    defaults = dict(
        entity_name="TestNBFC",
        entity_type=EntityType.NBFC,
        board_policy_ref="TEST_POLICY_v1.0",
        pii_masking_enabled=True,
    )
    defaults.update(kwargs)
    return AgentLensConfig(**defaults)


class TestAuditTracer:
    def test_trace_logs_start_and_end(self):
        tracer = AuditTracer(config=make_config())
        with tracer.trace_agent("test_agent") as span:
            pass

        events = tracer.get_log().get_events()
        types = [e.event_type for e in events]
        assert EventType.AGENT_START in types
        assert EventType.AGENT_END in types

    def test_trace_logs_error_on_exception(self):
        tracer = AuditTracer(config=make_config())
        with pytest.raises(RuntimeError):
            with tracer.trace_agent("test_agent") as span:
                raise RuntimeError("boom")

        events = tracer.get_log().get_events()
        types = [e.event_type for e in events]
        assert EventType.ERROR in types

    def test_chain_intact_after_full_trace(self):
        tracer = AuditTracer(config=make_config())
        with tracer.trace_agent("test_agent") as span:
            span.set_model("llama-3.1-70b", "2025-Q3")
            span.set_risk_tier(RiskTier.HIGH)
            span.record_tool_call("cibil_api", {"hash": "abc"}, {"score": 720})
            span.record_decision("APPROVED", "CIBIL 720 passes threshold.")

        assert tracer.get_log().verify_integrity() is True

    def test_tool_call_hashes_params(self):
        tracer = AuditTracer(config=make_config())
        with tracer.trace_agent("test_agent") as span:
            span.record_tool_call(
                "sensitive_api",
                params={"pan_number": "ABCDE1234F", "aadhaar": "1234-5678-9012"},
                result={"verified": True},
            )
        events = tracer.get_log().get_events()
        tool_events = [e for e in events if e.event_type == EventType.TOOL_CALL]
        assert len(tool_events) == 1
        e = tool_events[0]
        # Raw PII must not appear
        assert e.tool_params_hash is not None
        assert "ABCDE1234F" not in str(e.tool_params_hash)
        assert "1234-5678-9012" not in str(e.tool_params_hash)
        # Hash should be 64-char SHA-256
        assert len(e.tool_params_hash) == 64

    def test_decision_with_policy_engine(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())

        tracer = AuditTracer(config=make_config(), policy_engine=engine)
        with tracer.trace_agent("credit_agent") as span:
            span.set_risk_tier(RiskTier.HIGH)
            span.record_decision(
                output="APPROVED: ₹500,000",
                reasoning="CIBIL 724 ≥ 700. DSCR 4.08x ≥ 2.5x. No DPD.",
                context={
                    "decision_amount_inr": 500_000,
                    "human_review_requested": False,
                    "pii_masked": True,
                },
            )

        events = tracer.get_log().get_events()
        decision_events = [e for e in events if e.event_type == EventType.DECISION]
        assert len(decision_events) == 1
        # Policy passed — no guardrail should fire
        assert decision_events[0].guardrail_triggered is False

    def test_decision_triggers_guardrail_on_policy_fail(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())

        tracer = AuditTracer(config=make_config(), policy_engine=engine)
        with tracer.trace_agent("credit_agent") as span:
            span.set_risk_tier(RiskTier.HIGH)
            span.record_decision(
                output="APPROVED",
                reasoning="",           # Empty reasoning → RBI_CREDIT_002 fails
                context={"pii_masked": True, "decision_amount_inr": 100_000},
            )

        events = tracer.get_log().get_events()
        decision_events = [e for e in events if e.event_type == EventType.DECISION]
        assert decision_events[0].guardrail_triggered is True

    def test_human_override_logged(self):
        tracer = AuditTracer(config=make_config())
        with tracer.trace_agent("test_agent") as span:
            span.record_human_override(
                reviewer_id="OFFICER_001",
                reason="Edge case not covered by policy",
                original_decision="REJECTED",
                new_decision="APPROVED",
            )

        events = tracer.get_log().get_events()
        override_events = [e for e in events if e.event_type == EventType.HUMAN_OVERRIDE]
        assert len(override_events) == 1
        e = override_events[0]
        assert e.human_override is True
        # Reviewer ID must be hashed, never plain
        assert "OFFICER_001" not in (e.human_reviewer_id_hash or "")
        assert e.human_reviewer_id_hash is not None

    def test_export_audit_report_json(self):
        import json
        tracer = AuditTracer(config=make_config())
        with tracer.trace_agent("test_agent") as span:
            span.record_decision("OUTPUT", "Reasoning here.", context={"pii_masked": True})

        report = tracer.export_audit_report(format="json")
        data = json.loads(report)
        assert data["entity"] == "TestNBFC"
        assert data["chain_verified"] is True
        assert "events" in data
        assert len(data["events"]) > 0

    def test_export_audit_report_ndjson(self):
        tracer = AuditTracer(config=make_config())
        with tracer.trace_agent("test_agent") as span:
            pass
        ndjson = tracer.export_audit_report(format="ndjson")
        lines = ndjson.strip().split("\n")
        assert len(lines) >= 2  # At least start + end

    def test_multiple_agents_in_same_tracer(self):
        tracer = AuditTracer(config=make_config())
        with tracer.trace_agent("agent_a") as span:
            span.record_decision("OUT_A", "Reason A", context={"pii_masked": True})
        with tracer.trace_agent("agent_b") as span:
            span.record_decision("OUT_B", "Reason B", context={"pii_masked": True})

        events = tracer.get_log().get_events()
        agent_ids = {e.agent_id for e in events if e.agent_id}
        assert "agent_a" in agent_ids
        assert "agent_b" in agent_ids
        assert tracer.get_log().verify_integrity() is True
