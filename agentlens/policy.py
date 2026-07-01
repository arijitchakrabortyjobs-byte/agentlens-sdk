"""
AgentLens Policy Engine
-----------------------
Runtime policy enforcement and guardrails aligned to Indian regulatory
frameworks. Checks agent actions against policy rules BEFORE execution,
producing verifiable why-trails independent of LLM chain-of-thought.

RBI FREE-AI Pillar: Governance + Assurance
  - Recommendation 14: Independent model validation
  - Recommendation 18: Bias and explainability checks
  - Recommendation 21: Incident escalation

RBI MRM June 2026:
  - Kill switch / human override for Tier 1 models
  - Mandatory human-in-the-loop for high-value decisions

SEBI AI/ML June 2025:
  - Algorithm accountability for securities trading
  - Pre-trade risk controls
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from enum import Enum


class PolicyAction(str, Enum):
    ALLOW     = "allow"
    WARN      = "warn"
    ESCALATE  = "escalate"   # Route to human reviewer
    BLOCK     = "block"      # Hard stop — RBI MRM kill switch


@dataclass
class PolicyRule:
    """
    A single policy rule with a check function and regulatory reference.
    
    The check function receives the agent context and returns
    (passed: bool, reason: str, evidence: dict).
    """
    rule_id: str
    description: str
    regulatory_ref: str          # e.g. "RBI_FREE_AI_REC_18", "DPDP_S8"
    action_on_fail: PolicyAction
    risk_tier_applies: List[int] # Which RBI MRM tiers this rule applies to
    check_fn: Callable           # (context: dict) -> (bool, str, dict)
    version: str = "1.0"

    def evaluate(self, context: Dict[str, Any]) -> Tuple[bool, str, Dict]:
        """
        Evaluate the rule against agent context.
        Returns (passed, human_readable_reason, evidence_dict).
        The evidence_dict feeds directly into the audit why-trail —
        it is policy-execution output, NOT LLM chain-of-thought.
        """
        try:
            return self.check_fn(context)
        except Exception as e:
            return False, f"Rule evaluation error: {e}", {"error": str(e)}


@dataclass
class PolicyCheckResult:
    """Result of running all applicable policy rules for an agent action."""
    overall_action: PolicyAction
    rules_passed: List[str]
    rules_failed: List[str]
    rules_warned: List[str]
    why_trail: List[Dict]       # Structured, verifiable reasoning entries
    requires_human_review: bool
    block_reason: Optional[str] = None


class RBIPolicy:
    """
    Curated policy rule set aligned to RBI FREE-AI Framework (Aug 2025)
    and RBI Draft Model Risk Management Guidance (June 2026).
    
    Covers the 6 mandatory pillars:
      Infrastructure, Policy, Capacity, Governance, Protection, Assurance
    """

    @staticmethod
    def credit_decision_rules() -> List[PolicyRule]:
        """
        Rules for Tier 1 credit decisioning agents.
        RBI MRM 2026: Highest scrutiny tier — board review required.
        """
        return [
            PolicyRule(
                rule_id="RBI_CREDIT_001",
                description="Credit decision must reference a versioned credit policy document",
                regulatory_ref="RBI_FREE_AI_REC_14 | RBI_MRM_2026_TIER1",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("policy_ref")),
                    "Policy document reference found: " + str(ctx.get("policy_ref", "MISSING")),
                    {"policy_ref": ctx.get("policy_ref"), "check": "policy_ref_present"}
                )
            ),
            PolicyRule(
                rule_id="RBI_CREDIT_002",
                description="Decision output must include human-readable reason (not LLM CoT)",
                regulatory_ref="RBI_FREE_AI_REC_18_EXPLAINABILITY | DPDP_S13",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("human_readable_reasoning")),
                    "Explainability reason present: " + ("YES" if ctx.get("human_readable_reasoning") else "NO"),
                    {"has_reasoning": bool(ctx.get("human_readable_reasoning"))}
                )
            ),
            PolicyRule(
                rule_id="RBI_CREDIT_003",
                description="High-value credit decision (>₹10L) requires human review flag",
                regulatory_ref="RBI_MRM_2026_HUMAN_OVERSIGHT | RBI_FREE_AI_REC_21",
                action_on_fail=PolicyAction.ESCALATE,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("decision_amount_inr", 0) <= 1_000_000 or
                    ctx.get("human_review_requested", False),
                    f"Amount ₹{ctx.get('decision_amount_inr',0):,} — " +
                    ("Human review requested" if ctx.get("human_review_requested") else "ESCALATION REQUIRED"),
                    {
                        "amount_inr": ctx.get("decision_amount_inr", 0),
                        "threshold_inr": 1_000_000,
                        "human_review_requested": ctx.get("human_review_requested", False),
                    }
                )
            ),
            PolicyRule(
                rule_id="RBI_CREDIT_004",
                description="PII fields must be hashed before logging (DPDP Act 2023)",
                regulatory_ref="DPDP_ACT_2023_S8 | RBI_FREE_AI_PILLAR_PROTECTION",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("pii_masked", False),
                    "PII masking status: " + ("COMPLIANT" if ctx.get("pii_masked") else "NON-COMPLIANT — PII exposed in log"),
                    {"pii_masked": ctx.get("pii_masked", False)}
                )
            ),
        ]

    @staticmethod
    def customer_service_rules() -> List[PolicyRule]:
        """Rules for Tier 2 customer service / chatbot agents."""
        return [
            PolicyRule(
                rule_id="RBI_CS_001",
                description="Agent must disclose it is AI to customer (FREE-AI Consumer Protection)",
                regulatory_ref="RBI_FREE_AI_REC_22_CONSUMER_TRANSPARENCY",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("ai_disclosed_to_user", False),
                    "AI disclosure to user: " + ("DONE" if ctx.get("ai_disclosed_to_user") else "MISSING"),
                    {"ai_disclosed": ctx.get("ai_disclosed_to_user", False)}
                )
            ),
            PolicyRule(
                rule_id="RBI_CS_002",
                description="Grievance redressal channel must be available (FREE-AI Rec 23)",
                regulatory_ref="RBI_FREE_AI_REC_23_GRIEVANCE",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("grievance_channel_ref")),
                    "Grievance channel: " + str(ctx.get("grievance_channel_ref", "NOT CONFIGURED")),
                    {"grievance_channel": ctx.get("grievance_channel_ref")}
                )
            ),
        ]


class SEBIPolicy:
    """
    Policy rules aligned to SEBI Consultation Paper on
    Responsible AI/ML in Indian Securities Markets (June 2025).
    """

    @staticmethod
    def algo_trading_rules() -> List[PolicyRule]:
        """Rules for AI agents in algorithmic trading."""
        return [
            PolicyRule(
                rule_id="SEBI_ALGO_001",
                description="Pre-trade risk check must be logged before order placement",
                regulatory_ref="SEBI_AIML_2025_ALGO_ACCOUNTABILITY",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("pre_trade_risk_check_passed", False),
                    "Pre-trade risk check: " + ("PASSED" if ctx.get("pre_trade_risk_check_passed") else "NOT PERFORMED — ORDER BLOCKED"),
                    {"pre_trade_check": ctx.get("pre_trade_risk_check_passed", False)}
                )
            ),
            PolicyRule(
                rule_id="SEBI_ALGO_002",
                description="Order value above ₹50L requires dual approval",
                regulatory_ref="SEBI_AIML_2025_HIGH_VALUE_CONTROL",
                action_on_fail=PolicyAction.ESCALATE,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("order_value_inr", 0) <= 5_000_000 or
                    ctx.get("dual_approval_obtained", False),
                    f"Order ₹{ctx.get('order_value_inr',0):,} — " +
                    ("Dual approval obtained" if ctx.get("dual_approval_obtained") else "ESCALATION REQUIRED"),
                    {
                        "order_value": ctx.get("order_value_inr", 0),
                        "threshold": 5_000_000,
                        "dual_approval": ctx.get("dual_approval_obtained", False),
                    }
                )
            ),
        ]


class PolicyEngine:
    """
    Runtime policy engine. Evaluates all applicable rules for a given
    agent context and returns a structured PolicyCheckResult.

    The why_trail in the result is the core of AgentLens's reasoning
    traceability — it captures WHAT policy fired, WHY it fired, and
    WHAT evidence was used, independent of any LLM output.

    This satisfies:
    - RBI FREE-AI Rec 18: Explainability and bias audit protocols
    - RBI MRM 2026: Independent model validation evidence
    - SEBI AIML 2025: Algorithm accountability documentation
    """

    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules: List[PolicyRule] = rules or []

    def add_rules(self, rules: List[PolicyRule]):
        self.rules.extend(rules)

    def evaluate(
        self,
        context: Dict[str, Any],
        risk_tier: int = 2
    ) -> PolicyCheckResult:
        """
        Evaluate all applicable rules for the given agent context.
        Produces a deterministic, verifiable why-trail.
        """
        applicable = [r for r in self.rules if risk_tier in r.risk_tier_applies]

        passed, failed, warned = [], [], []
        why_trail = []
        overall = PolicyAction.ALLOW
        block_reason = None

        for rule in applicable:
            result_ok, reason, evidence = rule.evaluate(context)
            why_entry = {
                "rule_id": rule.rule_id,
                "version": rule.version,
                "regulatory_ref": rule.regulatory_ref,
                "description": rule.description,
                "passed": result_ok,
                "action_on_fail": rule.action_on_fail.value,
                "reason": reason,
                "evidence": evidence,
            }
            why_trail.append(why_entry)

            if result_ok:
                passed.append(rule.rule_id)
            else:
                if rule.action_on_fail == PolicyAction.BLOCK:
                    failed.append(rule.rule_id)
                    overall = PolicyAction.BLOCK
                    block_reason = f"[{rule.rule_id}] {reason}"
                elif rule.action_on_fail == PolicyAction.ESCALATE:
                    failed.append(rule.rule_id)
                    if overall != PolicyAction.BLOCK:
                        overall = PolicyAction.ESCALATE
                elif rule.action_on_fail == PolicyAction.WARN:
                    warned.append(rule.rule_id)
                    if overall == PolicyAction.ALLOW:
                        overall = PolicyAction.WARN

        return PolicyCheckResult(
            overall_action=overall,
            rules_passed=passed,
            rules_failed=failed,
            rules_warned=warned,
            why_trail=why_trail,
            requires_human_review=(overall in [PolicyAction.ESCALATE, PolicyAction.BLOCK]),
            block_reason=block_reason,
        )
