"""Tests for PolicyEngine and RBI/SEBI rule sets."""

import pytest
from agentlens.policy import (
    PolicyEngine, PolicyRule, PolicyAction,
    PolicyCheckResult, RBIPolicy, SEBIPolicy,
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
