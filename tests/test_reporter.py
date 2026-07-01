"""Tests for ComplianceReporter."""

import json
import pytest
from agentlens.tracer import AuditTracer
from agentlens.config import AgentLensConfig, EntityType, RegulatoryFramework
from agentlens.audit_log import RiskTier
from agentlens.report import ComplianceReporter


def make_populated_tracer() -> AuditTracer:
    config = AgentLensConfig(
        entity_name="TestBank",
        entity_type=EntityType.SCB,
        regulatory_frameworks=[
            RegulatoryFramework.RBI_FREE_AI,
            RegulatoryFramework.DPDP_2023,
        ],
        board_policy_ref="AI_POLICY_v1.0_BOARD_2026",
        pii_masking_enabled=True,
    )
    tracer = AuditTracer(config=config)
    with tracer.trace_agent("credit_agent") as span:
        span.set_risk_tier(RiskTier.HIGH)
        span.record_tool_call("cibil_api", {"hash": "abc"}, {"score": 720})
        span.record_decision(
            "APPROVED: ₹500,000",
            "CIBIL 720 ≥ 700. DSCR 4.1x ≥ 2.5x.",
            context={"pii_masked": True, "decision_amount_inr": 500_000},
        )
    return tracer


class TestComplianceReporter:
    def test_rbi_report_structure(self):
        tracer = make_populated_tracer()
        reporter = ComplianceReporter(tracer.get_log(), tracer.config)
        report = reporter.rbi_free_ai_summary()

        assert report["report_type"] == "RBI_FREE_AI_Compliance_Summary"
        assert "pillar_status" in report
        assert "governance" in report["pillar_status"]
        assert "assurance" in report["pillar_status"]
        assert "protection" in report["pillar_status"]

    def test_governance_compliant_with_policy_ref(self):
        tracer = make_populated_tracer()
        reporter = ComplianceReporter(tracer.get_log(), tracer.config)
        report = reporter.rbi_free_ai_summary()
        assert report["pillar_status"]["governance"]["status"] == "COMPLIANT"

    def test_governance_noncompliant_without_policy_ref(self):
        config = AgentLensConfig(
            entity_name="NoPolicy Co",
            entity_type=EntityType.FINTECH,
            board_policy_ref=None,
            pii_masking_enabled=True,
        )
        import warnings
        tracer = AuditTracer(config=config)
        with tracer.trace_agent("agent") as span:
            pass
        reporter = ComplianceReporter(tracer.get_log(), config)
        report = reporter.rbi_free_ai_summary()
        assert report["pillar_status"]["governance"]["status"] == "NON-COMPLIANT"

    def test_assurance_chain_intact(self):
        tracer = make_populated_tracer()
        reporter = ComplianceReporter(tracer.get_log(), tracer.config)
        report = reporter.rbi_free_ai_summary()
        assert report["chain_integrity_verified"] is True
        assert report["pillar_status"]["assurance"]["chain_intact"] is True

    def test_executive_dashboard_is_string(self):
        tracer = make_populated_tracer()
        reporter = ComplianceReporter(tracer.get_log(), tracer.config)
        dash = reporter.executive_dashboard()
        assert isinstance(dash, str)
        assert "AgentLens" in dash
        assert "TestBank" in dash

    def test_executive_dashboard_shows_frameworks(self):
        tracer = make_populated_tracer()
        reporter = ComplianceReporter(tracer.get_log(), tracer.config)
        dash = reporter.executive_dashboard()
        assert "RBI_FREE_AI" in dash
        assert "DPDP" in dash

    def test_model_risk_tiers_in_report(self):
        tracer = make_populated_tracer()
        reporter = ComplianceReporter(tracer.get_log(), tracer.config)
        report = reporter.rbi_free_ai_summary()
        assert "model_risk_tiers" in report
        assert "tier_1" in report["model_risk_tiers"]
        assert report["model_risk_tiers"]["tier_1"]["count"] >= 1
