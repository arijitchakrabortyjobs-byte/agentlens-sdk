"""
AgentLens Policy Engine
-----------------------
Runtime policy enforcement and guardrails aligned to Indian regulatory
frameworks. Checks agent actions against policy rules BEFORE execution,
producing verifiable why-trails independent of LLM chain-of-thought.

Indian AI-governance coverage in this module:

RBI FREE-AI Framework (Aug 2025):
  - Recommendation 14: Independent model validation
  - Recommendation 18: Bias and explainability checks
  - Recommendation 21: Incident escalation
  - Recommendation 22/23: Consumer transparency and grievance redressal

RBI Model Risk Management (June 2026):
  - Kill switch / human override for Tier 1 models
  - Model inventory and periodic validation
  - Mandatory human-in-the-loop for high-value decisions

RBI Data Localization (Apr 2018):
  - Payment / audit data residency within India

SEBI AI/ML (June 2025):
  - Algorithm accountability for securities trading
  - Pre-trade risk controls

DPDP Act 2023:
  - Consent before processing (S6), purpose limitation (S5/S6)
  - Data minimisation and security safeguards (S8)
  - Right to erasure (S8(7)/S12) and grievance redressal (S13)
  - Children's data — verifiable parental consent (S9)
  - Breach-notification readiness (S8(6))

IRDAI AI Governance (Working Group, Jun 2026):
  - Human sign-off on claim denials and adverse underwriting
  - No demographic proxy variables in premium models
  - Disclosure of AI use to policyholders

DISHA / ABDM health-data governance:
  - Physician sign-off on AI clinical recommendations
  - AI-generated prescriptions blocked (human-only)
  - Patient consent and identifier tokenization
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

    @staticmethod
    def fraud_aml_rules() -> List[PolicyRule]:
        """
        Rules for AI agents in fraud / AML monitoring.
        RBI FREE-AI Rec 21 (incident escalation) + PMLA 2002 + RBI KYC.
        A suspicious-transaction decision must never be auto-closed by AI.
        """
        return [
            PolicyRule(
                rule_id="RBI_AML_001",
                description="Suspicious-transaction flag must escalate to a human — never auto-closed",
                regulatory_ref="RBI_FREE_AI_REC_21 | PMLA_2002 | RBI_MASTER_KYC_2016",
                action_on_fail=PolicyAction.ESCALATE,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    (not ctx.get("suspicious_flag", False))
                    or ctx.get("human_review_requested", False),
                    "Suspicious flag: "
                    + ("raised — " if ctx.get("suspicious_flag") else "none — ")
                    + ("human review requested" if ctx.get("human_review_requested")
                       else "ESCALATION REQUIRED (no auto-close of STR)"),
                    {
                        "suspicious_flag": ctx.get("suspicious_flag", False),
                        "human_review_requested": ctx.get("human_review_requested", False),
                    }
                )
            ),
            PolicyRule(
                rule_id="RBI_AML_002",
                description="AML decision must reference a versioned AML/KYC policy",
                regulatory_ref="RBI_MASTER_KYC_2016 | RBI_FREE_AI_REC_14",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("policy_ref")),
                    "AML policy reference: " + str(ctx.get("policy_ref", "MISSING")),
                    {"policy_ref": ctx.get("policy_ref"), "check": "aml_policy_ref_present"}
                )
            ),
        ]

    @staticmethod
    def model_governance_rules() -> List[PolicyRule]:
        """
        RBI Model Risk Management (June 2026) obligations for Tier 1 models:
        model inventory, periodic independent validation, and a kill switch.
        """
        return [
            PolicyRule(
                rule_id="RBI_MRM_001",
                description="Model must be registered in the institution's model inventory",
                regulatory_ref="RBI_MRM_2026_MODEL_INVENTORY | RBI_FREE_AI_REC_14",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1, 2],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("model_inventory_ref")),
                    "Model inventory reference: " + str(ctx.get("model_inventory_ref", "MISSING")),
                    {"model_inventory_ref": ctx.get("model_inventory_ref")}
                )
            ),
            PolicyRule(
                rule_id="RBI_MRM_002",
                description="Tier 1 model must have a validation within the last 365 days",
                regulatory_ref="RBI_MRM_2026_PERIODIC_VALIDATION",
                action_on_fail=PolicyAction.ESCALATE,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("days_since_last_validation", 9999) <= 365,
                    f"Days since last validation: {ctx.get('days_since_last_validation', 'UNKNOWN')} "
                    + ("(within window)" if ctx.get("days_since_last_validation", 9999) <= 365
                       else "— REVALIDATION REQUIRED"),
                    {
                        "days_since_last_validation": ctx.get("days_since_last_validation"),
                        "max_days": 365,
                    }
                )
            ),
            PolicyRule(
                rule_id="RBI_MRM_003",
                description="Tier 1 model must expose an operational kill switch",
                regulatory_ref="RBI_MRM_2026_KILL_SWITCH",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("kill_switch_available", False),
                    "Kill switch: " + ("AVAILABLE" if ctx.get("kill_switch_available")
                                        else "NOT AVAILABLE — Tier 1 deployment blocked"),
                    {"kill_switch_available": ctx.get("kill_switch_available", False)}
                )
            ),
        ]

    @staticmethod
    def data_localization_rules() -> List[PolicyRule]:
        """
        RBI data-localization directive (Apr 2018): payment and audit data
        must be stored on infrastructure located within India.
        """
        return [
            PolicyRule(
                rule_id="RBI_LOCAL_001",
                description="Audit/payment data must be stored in an India region",
                regulatory_ref="RBI_DATA_LOCALIZATION_APR2018",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    str(ctx.get("data_region", "")).lower().startswith(("ap-south", "india", "central-india", "south-india")),
                    "Data region: " + str(ctx.get("data_region", "UNSET"))
                    + (" (India — compliant)" if str(ctx.get("data_region", "")).lower().startswith(
                        ("ap-south", "india", "central-india", "south-india"))
                       else " — NON-COMPLIANT: data must reside in India"),
                    {"data_region": ctx.get("data_region")}
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


class DPDPPolicy:
    """
    Policy rules for the Digital Personal Data Protection Act, 2023 —
    India's binding data-protection law. These operate at the agent-decision
    layer (complementing the conversational checks in chat_policy.py) so that
    any agent processing personal data of a Data Principal is held to the
    Act's consent, minimisation, erasure, and grievance obligations.
    """

    @staticmethod
    def data_processing_rules() -> List[PolicyRule]:
        """DPDP Act 2023 data-fiduciary obligations and data-principal rights."""
        return [
            PolicyRule(
                rule_id="DPDP_CONSENT_001",
                description="Processing requires a consent reference on file for the Data Principal (S6)",
                regulatory_ref="DPDP_ACT_2023_S6_CONSENT",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("consent_ref"))
                    or ctx.get("legitimate_use", False),
                    "Consent basis: "
                    + (f"consent_ref={ctx.get('consent_ref')}" if ctx.get("consent_ref")
                       else "legitimate use (S7)" if ctx.get("legitimate_use")
                       else "MISSING — processing blocked (S6)"),
                    {
                        "consent_ref": ctx.get("consent_ref"),
                        "legitimate_use": ctx.get("legitimate_use", False),
                    }
                )
            ),
            PolicyRule(
                rule_id="DPDP_PURPOSE_001",
                description="Processing must be limited to the notified purpose (S5/S6)",
                regulatory_ref="DPDP_ACT_2023_S5_NOTICE | DPDP_ACT_2023_S6_PURPOSE_LIMITATION",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("processing_purpose")),
                    "Processing purpose: " + str(ctx.get("processing_purpose", "UNSPECIFIED — blocked")),
                    {"processing_purpose": ctx.get("processing_purpose")}
                )
            ),
            PolicyRule(
                rule_id="DPDP_MINIMISE_001",
                description="Personal data must be tokenized/masked before logging (S8 safeguards)",
                regulatory_ref="DPDP_ACT_2023_S8_DATA_MINIMISATION",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("pii_masked", False),
                    "PII masking: " + ("COMPLIANT" if ctx.get("pii_masked")
                                       else "NON-COMPLIANT — raw personal data would be logged"),
                    {"pii_masked": ctx.get("pii_masked", False)}
                )
            ),
            PolicyRule(
                rule_id="DPDP_ERASURE_001",
                description="No further processing once erasure is requested / retention has lapsed (S8(7)/S12)",
                regulatory_ref="DPDP_ACT_2023_S8_7_ERASURE | DPDP_ACT_2023_S12_RIGHT_TO_ERASURE",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    not ctx.get("erasure_requested", False),
                    "Erasure request: "
                    + ("PRESENT — further processing blocked" if ctx.get("erasure_requested")
                       else "none on file"),
                    {"erasure_requested": ctx.get("erasure_requested", False)}
                )
            ),
            PolicyRule(
                rule_id="DPDP_CHILDREN_001",
                description="Processing a child's data requires verifiable parental consent (S9)",
                regulatory_ref="DPDP_ACT_2023_S9_CHILDREN",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    (not ctx.get("data_principal_is_child", False))
                    or ctx.get("parental_consent_verified", False),
                    "Child data: "
                    + ("N/A" if not ctx.get("data_principal_is_child")
                       else "parental consent verified" if ctx.get("parental_consent_verified")
                       else "VERIFIABLE PARENTAL CONSENT MISSING — blocked"),
                    {
                        "data_principal_is_child": ctx.get("data_principal_is_child", False),
                        "parental_consent_verified": ctx.get("parental_consent_verified", False),
                    }
                )
            ),
            PolicyRule(
                rule_id="DPDP_GRIEVANCE_001",
                description="A grievance-redressal / DPO channel must be reachable (S13)",
                regulatory_ref="DPDP_ACT_2023_S13_GRIEVANCE_REDRESSAL",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("grievance_channel_ref") or ctx.get("dpo_contact_ref")),
                    "Grievance/DPO channel: "
                    + str(ctx.get("grievance_channel_ref") or ctx.get("dpo_contact_ref", "NOT CONFIGURED")),
                    {
                        "grievance_channel_ref": ctx.get("grievance_channel_ref"),
                        "dpo_contact_ref": ctx.get("dpo_contact_ref"),
                    }
                )
            ),
            PolicyRule(
                rule_id="DPDP_BREACH_001",
                description="A breach-notification procedure reference must be on file (S8(6))",
                regulatory_ref="DPDP_ACT_2023_S8_6_BREACH_NOTIFICATION",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("breach_procedure_ref")),
                    "Breach-notification procedure: " + str(ctx.get("breach_procedure_ref", "NOT CONFIGURED")),
                    {"breach_procedure_ref": ctx.get("breach_procedure_ref")}
                )
            ),
        ]


class IRDAIPolicy:
    """
    Policy rules for AI in insurance, aligned to the mandate of the IRDAI
    AI Working Group (constituted June 2026): ethical, transparent and
    explainable AI in claims management, underwriting and fraud detection,
    with human accountability for adverse decisions.
    """

    @staticmethod
    def claims_underwriting_rules() -> List[PolicyRule]:
        """Rules for AI agents in claims, underwriting and insurance fraud."""
        return [
            PolicyRule(
                rule_id="IRDAI_CLAIM_001",
                description="AI claim denial requires human sign-off before it is issued",
                regulatory_ref="IRDAI_AI_WG_JUN2026 | IRDAI_PPHI_POLICYHOLDER_PROTECTION",
                action_on_fail=PolicyAction.ESCALATE,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    (ctx.get("decision") != "deny")
                    or ctx.get("human_review_requested", False),
                    "Claim decision: " + str(ctx.get("decision", "n/a"))
                    + (" — human sign-off present" if ctx.get("human_review_requested")
                       else " — DENIAL REQUIRES HUMAN SIGN-OFF" if ctx.get("decision") == "deny"
                       else ""),
                    {
                        "decision": ctx.get("decision"),
                        "human_review_requested": ctx.get("human_review_requested", False),
                    }
                )
            ),
            PolicyRule(
                rule_id="IRDAI_UW_001",
                description="Underwriting/premium models must not use demographic proxy variables",
                regulatory_ref="IRDAI_AI_WG_JUN2026_FAIRNESS",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2],
                version="1.0",
                check_fn=lambda ctx: (
                    not ctx.get("uses_demographic_proxy", False),
                    "Demographic proxy variables: "
                    + ("PRESENT — blocked (unfair discrimination)" if ctx.get("uses_demographic_proxy")
                       else "none detected"),
                    {"uses_demographic_proxy": ctx.get("uses_demographic_proxy", False)}
                )
            ),
            PolicyRule(
                rule_id="IRDAI_FRAUD_001",
                description="AI fraud flag must escalate to a human before any claim rejection",
                regulatory_ref="IRDAI_AI_WG_JUN2026 | RBI_FREE_AI_REC_21",
                action_on_fail=PolicyAction.ESCALATE,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    (not ctx.get("fraud_flag", False))
                    or ctx.get("human_review_requested", False),
                    "Fraud flag: "
                    + ("raised — " if ctx.get("fraud_flag") else "none — ")
                    + ("human review requested" if ctx.get("human_review_requested")
                       else "ESCALATION REQUIRED"),
                    {
                        "fraud_flag": ctx.get("fraud_flag", False),
                        "human_review_requested": ctx.get("human_review_requested", False),
                    }
                )
            ),
            PolicyRule(
                rule_id="IRDAI_DISCLOSE_001",
                description="Use of AI in the decision must be disclosed to the policyholder",
                regulatory_ref="IRDAI_AI_WG_JUN2026_TRANSPARENCY",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("ai_disclosed_to_user", False),
                    "AI disclosure to policyholder: "
                    + ("DONE" if ctx.get("ai_disclosed_to_user") else "MISSING"),
                    {"ai_disclosed": ctx.get("ai_disclosed_to_user", False)}
                )
            ),
        ]


class DISHAPolicy:
    """
    Policy rules for AI on health data, aligned to India's ABDM Health Data
    Management Policy and the draft DISHA framework: patient consent,
    identifier protection, mandatory physician oversight of AI clinical
    recommendations, and a hard block on AI-generated prescriptions.
    """

    @staticmethod
    def clinical_rules() -> List[PolicyRule]:
        """Rules for AI agents in clinical decision support and health data."""
        return [
            PolicyRule(
                rule_id="DISHA_CONSENT_001",
                description="Patient consent reference required before processing health data",
                regulatory_ref="ABDM_HDM_POLICY_CONSENT | DISHA_DRAFT | DPDP_ACT_2023_S6",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("consent_ref")),
                    "Patient consent: " + str(ctx.get("consent_ref", "MISSING — processing blocked")),
                    {"consent_ref": ctx.get("consent_ref")}
                )
            ),
            PolicyRule(
                rule_id="DISHA_PII_001",
                description="Patient identifiers (ABHA ID, phone, MRN) must be tokenized before logging",
                regulatory_ref="ABDM_HDM_POLICY_MINIMISATION | DPDP_ACT_2023_S8",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("pii_masked", False),
                    "Patient-identifier masking: "
                    + ("COMPLIANT" if ctx.get("pii_masked") else "NON-COMPLIANT — identifiers exposed"),
                    {"pii_masked": ctx.get("pii_masked", False)}
                )
            ),
            PolicyRule(
                rule_id="DISHA_CDS_001",
                description="AI clinical recommendation requires a physician's sign-off",
                regulatory_ref="DISHA_DRAFT_CLINICIAN_OVERSIGHT | ABDM_HDM_POLICY",
                action_on_fail=PolicyAction.ESCALATE,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("physician_signoff", False),
                    "Physician sign-off: "
                    + ("PRESENT" if ctx.get("physician_signoff")
                       else "MISSING — clinical recommendation must be reviewed by a physician"),
                    {"physician_signoff": ctx.get("physician_signoff", False)}
                )
            ),
            PolicyRule(
                rule_id="DISHA_RX_001",
                description="AI-generated prescriptions are blocked — prescribing is human-only",
                regulatory_ref="DISHA_DRAFT_HUMAN_ONLY_PRESCRIBING",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    not ctx.get("is_ai_prescription", False),
                    "Prescription source: "
                    + ("AI-GENERATED — blocked (human-only)" if ctx.get("is_ai_prescription")
                       else "human / not a prescription"),
                    {"is_ai_prescription": ctx.get("is_ai_prescription", False)}
                )
            ),
            PolicyRule(
                rule_id="DISHA_DISCLOSE_001",
                description="AI involvement must be disclosed to the patient",
                regulatory_ref="DISHA_DRAFT_TRANSPARENCY | ABDM_HDM_POLICY",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("ai_disclosed_to_user", False),
                    "AI disclosure to patient: "
                    + ("DONE" if ctx.get("ai_disclosed_to_user") else "MISSING"),
                    {"ai_disclosed": ctx.get("ai_disclosed_to_user", False)}
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
