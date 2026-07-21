"""Tests for PolicyEngine and the Indian AI-governance rule sets."""

import pytest
from agentlens.policy import (
    PolicyEngine, PolicyRule, PolicyAction,
    PolicyCheckResult, RBIPolicy, SEBIPolicy,
    DPDPPolicy, IRDAIPolicy, DISHAPolicy,
)


COMPLIANT_CREDIT_CTX = {
    "policy_ref": "CREDIT_POLICY_v3.2_APR2026",
    "human_readable_reasoning": "Approved: CIBIL 724, DSCR 4.08x, no DPD.",
    "decision_amount_inr": 500_000,        # Under ₹10L threshold
    "human_review_requested": False,
    "pii_masked": True,
}

NON_COMPLIANT_CTX = {
    "policy_ref": "",
    "human_readable_reasoning": "",
    "decision_amount_inr": 2_000_000,
    "human_review_requested": False,
    "pii_masked": False,
}


class TestPolicyEngine:
    def test_allow_on_all_pass(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        result = engine.evaluate(COMPLIANT_CREDIT_CTX, risk_tier=1)
        assert result.overall_action == PolicyAction.ALLOW
        assert result.rules_failed == []
        assert result.requires_human_review is False

    def test_block_on_missing_policy_ref(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        ctx = {**COMPLIANT_CREDIT_CTX, "policy_ref": ""}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "RBI_CREDIT_001" in result.rules_failed

    def test_block_on_missing_reasoning(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        ctx = {**COMPLIANT_CREDIT_CTX, "human_readable_reasoning": ""}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "RBI_CREDIT_002" in result.rules_failed

    def test_escalate_on_high_value_without_review(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        ctx = {
            **COMPLIANT_CREDIT_CTX,
            "decision_amount_inr": 2_000_000,
            "human_review_requested": False,
        }
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action in [PolicyAction.ESCALATE, PolicyAction.BLOCK]
        assert "RBI_CREDIT_003" in result.rules_failed
        assert result.requires_human_review is True

    def test_high_value_passes_with_human_review(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        ctx = {
            **COMPLIANT_CREDIT_CTX,
            "decision_amount_inr": 2_000_000,
            "human_review_requested": True,
        }
        result = engine.evaluate(ctx, risk_tier=1)
        # RBI_CREDIT_003 should pass; overall may still be ALLOW if other rules pass
        assert "RBI_CREDIT_003" not in result.rules_failed

    def test_block_on_pii_not_masked(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        ctx = {**COMPLIANT_CREDIT_CTX, "pii_masked": False}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "RBI_CREDIT_004" in result.rules_failed

    def test_why_trail_populated(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        result = engine.evaluate(COMPLIANT_CREDIT_CTX, risk_tier=1)
        assert len(result.why_trail) > 0
        for entry in result.why_trail:
            assert "rule_id" in entry
            assert "regulatory_ref" in entry
            assert "evidence" in entry
            assert "passed" in entry

    def test_tier_filtering(self):
        """Rules that only apply to Tier 1 should not fire for Tier 3."""
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        # RBI_CREDIT_001 applies to tier 1 only
        ctx = {**NON_COMPLIANT_CTX}
        result_tier3 = engine.evaluate(ctx, risk_tier=3)
        # RBI_CREDIT_003 applies to tier 1 only; RBI_CREDIT_004 applies to 1,2,3
        assert "RBI_CREDIT_001" not in result_tier3.rules_failed
        assert "RBI_CREDIT_003" not in result_tier3.rules_failed

    def test_empty_engine_allows(self):
        engine = PolicyEngine()
        result = engine.evaluate({}, risk_tier=1)
        assert result.overall_action == PolicyAction.ALLOW

    def test_add_rules_accumulates(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        engine.add_rules(RBIPolicy.customer_service_rules())
        assert len(engine.rules) > 4

    def test_block_takes_precedence_over_escalate(self):
        """If both BLOCK and ESCALATE rules fail, overall must be BLOCK."""
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.credit_decision_rules())
        # Missing policy_ref → BLOCK; high amount no review → ESCALATE
        ctx = {
            "policy_ref": "",
            "human_readable_reasoning": "Some reason",
            "decision_amount_inr": 2_000_000,
            "human_review_requested": False,
            "pii_masked": True,
        }
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK


class TestSEBIPolicy:
    def test_algo_block_without_pretrade_check(self):
        engine = PolicyEngine()
        engine.add_rules(SEBIPolicy.algo_trading_rules())
        ctx = {
            "pre_trade_risk_check_passed": False,
            "order_value_inr": 100_000,
            "dual_approval_obtained": False,
        }
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "SEBI_ALGO_001" in result.rules_failed

    def test_algo_escalate_high_value_no_dual_approval(self):
        engine = PolicyEngine()
        engine.add_rules(SEBIPolicy.algo_trading_rules())
        ctx = {
            "pre_trade_risk_check_passed": True,
            "order_value_inr": 10_000_000,
            "dual_approval_obtained": False,
        }
        result = engine.evaluate(ctx, risk_tier=1)
        assert "SEBI_ALGO_002" in result.rules_failed

    def test_algo_allow_with_all_controls(self):
        engine = PolicyEngine()
        engine.add_rules(SEBIPolicy.algo_trading_rules())
        ctx = {
            "pre_trade_risk_check_passed": True,
            "order_value_inr": 1_000_000,
            "dual_approval_obtained": False,  # Under threshold
        }
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.ALLOW


class TestRBIExtendedRules:
    def test_aml_escalates_suspicious_without_review(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.fraud_aml_rules())
        ctx = {"suspicious_flag": True, "human_review_requested": False, "policy_ref": "AML_v1"}
        result = engine.evaluate(ctx, risk_tier=1)
        assert "RBI_AML_001" in result.rules_failed
        assert result.requires_human_review is True

    def test_aml_allows_clean_transaction(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.fraud_aml_rules())
        ctx = {"suspicious_flag": False, "policy_ref": "AML_v1"}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.ALLOW

    def test_mrm_blocks_tier1_without_kill_switch(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.model_governance_rules())
        ctx = {"model_inventory_ref": "MI-1", "days_since_last_validation": 30, "kill_switch_available": False}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "RBI_MRM_003" in result.rules_failed

    def test_mrm_escalates_stale_validation(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.model_governance_rules())
        ctx = {"model_inventory_ref": "MI-1", "days_since_last_validation": 400, "kill_switch_available": True}
        result = engine.evaluate(ctx, risk_tier=1)
        assert "RBI_MRM_002" in result.rules_failed

    def test_data_localization_blocks_foreign_region(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.data_localization_rules())
        result = engine.evaluate({"data_region": "us-east-1"}, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "RBI_LOCAL_001" in result.rules_failed

    def test_data_localization_allows_india_region(self):
        engine = PolicyEngine()
        engine.add_rules(RBIPolicy.data_localization_rules())
        result = engine.evaluate({"data_region": "ap-south-1"}, risk_tier=1)
        assert result.overall_action == PolicyAction.ALLOW


class TestDPDPPolicy:
    COMPLIANT = {
        "consent_ref": "CONSENT-123",
        "processing_purpose": "credit_underwriting",
        "pii_masked": True,
        "erasure_requested": False,
        "data_principal_is_child": False,
        "grievance_channel_ref": "grievance@bank.example",
        "breach_procedure_ref": "BREACH_SOP_v2",
    }

    def test_allows_fully_compliant(self):
        engine = PolicyEngine()
        engine.add_rules(DPDPPolicy.data_processing_rules())
        result = engine.evaluate(self.COMPLIANT, risk_tier=1)
        assert result.overall_action == PolicyAction.ALLOW

    def test_blocks_without_consent(self):
        engine = PolicyEngine()
        engine.add_rules(DPDPPolicy.data_processing_rules())
        ctx = {**self.COMPLIANT, "consent_ref": "", "legitimate_use": False}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "DPDP_CONSENT_001" in result.rules_failed

    def test_legitimate_use_satisfies_consent(self):
        engine = PolicyEngine()
        engine.add_rules(DPDPPolicy.data_processing_rules())
        ctx = {**self.COMPLIANT, "consent_ref": "", "legitimate_use": True}
        result = engine.evaluate(ctx, risk_tier=1)
        assert "DPDP_CONSENT_001" not in result.rules_failed

    def test_blocks_on_erasure_request(self):
        engine = PolicyEngine()
        engine.add_rules(DPDPPolicy.data_processing_rules())
        ctx = {**self.COMPLIANT, "erasure_requested": True}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "DPDP_ERASURE_001" in result.rules_failed

    def test_blocks_child_without_parental_consent(self):
        engine = PolicyEngine()
        engine.add_rules(DPDPPolicy.data_processing_rules())
        ctx = {**self.COMPLIANT, "data_principal_is_child": True, "parental_consent_verified": False}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "DPDP_CHILDREN_001" in result.rules_failed

    def test_warns_without_grievance_channel(self):
        engine = PolicyEngine()
        engine.add_rules(DPDPPolicy.data_processing_rules())
        ctx = {**self.COMPLIANT, "grievance_channel_ref": "", "dpo_contact_ref": ""}
        result = engine.evaluate(ctx, risk_tier=1)
        assert "DPDP_GRIEVANCE_001" in result.rules_warned


class TestIRDAIPolicy:
    def test_escalates_ai_claim_denial_without_signoff(self):
        engine = PolicyEngine()
        engine.add_rules(IRDAIPolicy.claims_underwriting_rules())
        ctx = {"decision": "deny", "human_review_requested": False}
        result = engine.evaluate(ctx, risk_tier=1)
        assert "IRDAI_CLAIM_001" in result.rules_failed
        assert result.requires_human_review is True

    def test_allows_claim_approval(self):
        engine = PolicyEngine()
        engine.add_rules(IRDAIPolicy.claims_underwriting_rules())
        ctx = {"decision": "approve", "ai_disclosed_to_user": True}
        result = engine.evaluate(ctx, risk_tier=1)
        assert "IRDAI_CLAIM_001" not in result.rules_failed

    def test_blocks_demographic_proxy_in_underwriting(self):
        engine = PolicyEngine()
        engine.add_rules(IRDAIPolicy.claims_underwriting_rules())
        ctx = {"decision": "approve", "uses_demographic_proxy": True, "ai_disclosed_to_user": True}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "IRDAI_UW_001" in result.rules_failed

    def test_warns_without_ai_disclosure(self):
        engine = PolicyEngine()
        engine.add_rules(IRDAIPolicy.claims_underwriting_rules())
        ctx = {"decision": "approve", "ai_disclosed_to_user": False}
        result = engine.evaluate(ctx, risk_tier=1)
        assert "IRDAI_DISCLOSE_001" in result.rules_warned


class TestDISHAPolicy:
    COMPLIANT = {
        "consent_ref": "ABHA-CONSENT-9",
        "pii_masked": True,
        "physician_signoff": True,
        "is_ai_prescription": False,
        "ai_disclosed_to_user": True,
    }

    def test_allows_fully_compliant(self):
        engine = PolicyEngine()
        engine.add_rules(DISHAPolicy.clinical_rules())
        result = engine.evaluate(self.COMPLIANT, risk_tier=1)
        assert result.overall_action == PolicyAction.ALLOW

    def test_blocks_ai_prescription(self):
        engine = PolicyEngine()
        engine.add_rules(DISHAPolicy.clinical_rules())
        ctx = {**self.COMPLIANT, "is_ai_prescription": True}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "DISHA_RX_001" in result.rules_failed

    def test_escalates_clinical_recommendation_without_physician(self):
        engine = PolicyEngine()
        engine.add_rules(DISHAPolicy.clinical_rules())
        ctx = {**self.COMPLIANT, "physician_signoff": False}
        result = engine.evaluate(ctx, risk_tier=1)
        assert "DISHA_CDS_001" in result.rules_failed
        assert result.requires_human_review is True

    def test_blocks_without_patient_consent(self):
        engine = PolicyEngine()
        engine.add_rules(DISHAPolicy.clinical_rules())
        ctx = {**self.COMPLIANT, "consent_ref": ""}
        result = engine.evaluate(ctx, risk_tier=1)
        assert result.overall_action == PolicyAction.BLOCK
        assert "DISHA_CONSENT_001" in result.rules_failed


class TestPolicyRule:
    def test_rule_evaluation_error_returns_false(self):
        def bad_check(ctx):
            raise ValueError("intentional error")

        rule = PolicyRule(
            rule_id="TEST_001",
            description="A failing rule",
            regulatory_ref="TEST",
            action_on_fail=PolicyAction.WARN,
            risk_tier_applies=[1],
            check_fn=bad_check,
        )
        passed, reason, evidence = rule.evaluate({})
        assert passed is False
        assert "error" in evidence
