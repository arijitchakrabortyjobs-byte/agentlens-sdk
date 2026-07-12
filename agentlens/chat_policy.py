"""
AgentLens Chat Guardrail Policies
-----------------------------------
Runtime guardrails for LLM chat sessions in regulated BFSI environments.

These rules fire on every conversation turn and produce a verifiable
why-trail independent of the LLM's own output.

Covers:
  - DPDP Act 2023: PII minimisation, consent validation
  - RBI FREE-AI Rec 18: Explainability per turn
  - RBI FREE-AI Rec 22: AI disclosure to user
  - RBI MRM 2026: Human oversight triggers
"""

import re
from typing import List
from .policy import PolicyRule, PolicyAction


# ─────────────────────────────────────────────────────────────────────────────
# PII Pattern Detection
# ─────────────────────────────────────────────────────────────────────────────

# HIGH-RISK: personal identifiers of a natural person — always flag
# These are PII under DPDP Act 2023 Section 2(t) regardless of context.
_PAN_PATTERN     = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')
_AADHAAR_PATTERN = re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b')
_ACCOUNT_PATTERN = re.compile(r'\b\d{9,18}\b')  # bank account / card numbers

# LOW-RISK: could be institutional contact (grievance@company.in, 1800-xxx)
# Flag only in user INPUT (user may be sharing their own contact).
# In agent OUTPUT, these are likely business contacts — do not flag as PII.
_PHONE_PATTERN   = re.compile(r'\b(\+91[\s-]?)?[6-9]\d{9}\b')
_EMAIL_PATTERN   = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')

# Institutional email indicators — suppress false positives in agent output
_INSTITUTIONAL_EMAIL = re.compile(
    r'@(grievance|support|help|info|contact|noreply|no-reply|'
    r'customercare|care|service|feedback|escalation)\.',
    re.IGNORECASE,
)
# Toll-free / helpline prefixes — not personal phone numbers
_TOLLFREE_PATTERN = re.compile(r'\b(1800|1860|1900)[\s-]?\d')


def detect_pii(text: str) -> List[str]:
    """
    Return HIGH-risk PII types found in text.

    Only returns types that are unambiguously personal data of a natural
    person under DPDP Act 2023 Section 2(t). Institutional contact details
    (grievance emails, toll-free numbers) are excluded.
    """
    found = []
    if _PAN_PATTERN.search(text):
        found.append("PAN")
    if _AADHAAR_PATTERN.search(text):
        found.append("AADHAAR")
    if _ACCOUNT_PATTERN.search(text):
        found.append("ACCOUNT_NUMBER_PATTERN")
    # Phone: only flag if not a toll-free / helpline number
    for m in _PHONE_PATTERN.finditer(text):
        if not _TOLLFREE_PATTERN.match(m.group().strip()):
            found.append("PHONE")
            break
    return found


def detect_pii_in_user_input(text: str) -> List[str]:
    """
    Extended PII detection for user-supplied input only.
    Includes email and phone since users may share their own contact details.
    """
    found = detect_pii(text)
    if _EMAIL_PATTERN.search(text) and "EMAIL" not in found:
        found.append("EMAIL")
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Chat Policy Rule Sets
# ─────────────────────────────────────────────────────────────────────────────

class ChatPolicy:
    """
    Guardrail rule sets for LLM chat sessions in Indian BFSI deployments.
    """

    @staticmethod
    def consent_and_disclosure_rules() -> List[PolicyRule]:
        """
        RBI FREE-AI Rec 22 — Consumer Protection:
        Users must know they are talking to an AI.
        DPDP Act 2023 — consent must be on file before processing.
        """
        return [
            PolicyRule(
                rule_id="CHAT_001",
                description="Consent record must be present before processing user data",
                regulatory_ref="DPDP_ACT_2023_S6_CONSENT | RBI_FREE_AI_REC_22",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("consent_ref")),
                    "Consent ref: " + (ctx.get("consent_ref") or "MISSING — processing blocked"),
                    {"consent_ref": ctx.get("consent_ref"), "dpdp_s6": "consent_required"},
                ),
            ),
            PolicyRule(
                rule_id="CHAT_002",
                description="AI identity must be disclosed in the response text, not just asserted by caller",
                regulatory_ref="RBI_FREE_AI_REC_22_CONSUMER_TRANSPARENCY",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[2, 3],
                version="1.1",
                check_fn=lambda ctx: (
                    ctx.get("analytics_ai_disclosed", False),
                    "AI disclosure in response: " + (
                        "DETECTED — response identifies as AI"
                        if ctx.get("analytics_ai_disclosed")
                        else "NOT DETECTED — response text does not identify as AI"
                    ),
                    {"ai_disclosed_in_response_text": ctx.get("analytics_ai_disclosed", False)},
                ),
            ),
        ]

    @staticmethod
    def explainability_rules() -> List[PolicyRule]:
        """
        RBI FREE-AI Rec 18 — Explainability:
        Every turn that contains a decision must have a human-authored
        summary, independent of the LLM's chain-of-thought.
        """
        return [
            PolicyRule(
                rule_id="CHAT_003",
                description="Human-authored turn summary required for decisions (not LLM CoT)",
                regulatory_ref="RBI_FREE_AI_REC_18_EXPLAINABILITY",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1, 2],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("has_human_summary")),
                    "Human summary: " + ("PRESENT" if ctx.get("has_human_summary") else "MISSING — add human_readable_summary"),
                    {"has_human_summary": bool(ctx.get("has_human_summary"))},
                ),
            ),
            PolicyRule(
                rule_id="CHAT_004",
                description="Board-approved policy reference must be set for regulated decisions",
                regulatory_ref="RBI_FREE_AI_REC_14_GOVERNANCE | RBI_MRM_2026_TIER1",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    bool(ctx.get("policy_ref")),
                    "Policy ref: " + (ctx.get("policy_ref") or "NOT SET"),
                    {"policy_ref": ctx.get("policy_ref")},
                ),
            ),
        ]

    @staticmethod
    def data_minimisation_rules() -> List[PolicyRule]:
        """
        DPDP Act 2023 Section 8 — Data minimisation:
        Only data strictly necessary for the stated purpose may be processed.
        PII must not appear in audit logs.
        """
        return [
            PolicyRule(
                rule_id="CHAT_005",
                description="PII masking must be enabled; raw identifiers must not enter audit logs",
                regulatory_ref="DPDP_ACT_2023_S8_DATA_MINIMISATION | RBI_FREE_AI_PILLAR_5",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("pii_masked", False),
                    "PII masking: " + ("COMPLIANT" if ctx.get("pii_masked") else "NON-COMPLIANT — raw PII may enter logs"),
                    {"pii_masked": ctx.get("pii_masked", False)},
                ),
            ),
            PolicyRule(
                rule_id="CHAT_010",
                description="User input containing PII (PAN/Aadhaar/account) must be flagged for data minimisation review",
                regulatory_ref="DPDP_ACT_2023_S8_DATA_MINIMISATION | DPDP_ACT_2023_S6_CONSENT",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    not bool(ctx.get("pii_in_user_input")),
                    "PII in user input: " + (
                        f"DETECTED — {ctx.get('pii_in_user_input')} — verify consent covers this data type and hash before storage"
                        if ctx.get("pii_in_user_input")
                        else "NONE — no personal identifiers in user message"
                    ),
                    {"pii_types_in_input": ctx.get("pii_in_user_input", [])},
                ),
            ),
        ]

    @staticmethod
    def human_oversight_rules() -> List[PolicyRule]:
        """
        RBI MRM 2026 — Human oversight:
        Financial outputs must carry a human review disclaimer.
        Human escalation path must be mentioned in responses on key topics.
        """
        return [
            PolicyRule(
                rule_id="CHAT_006",
                description="Tier 1 chat session must have a human escalation path defined",
                regulatory_ref="RBI_MRM_2026_HUMAN_OVERSIGHT | RBI_FREE_AI_REC_21",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("human_escalation_path_defined", False),
                    "Human escalation path: " + ("DEFINED" if ctx.get("human_escalation_path_defined") else "NOT CONFIGURED"),
                    {"human_escalation_defined": ctx.get("human_escalation_path_defined", False)},
                ),
            ),
            PolicyRule(
                rule_id="CHAT_007",
                description="Responses containing financial figures must include a human review disclaimer",
                regulatory_ref="RBI_FREE_AI_REC_18 | RBI_MRM_2026_AUTOMATION_BIAS",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    not ctx.get("analytics_has_financial_output", False)
                    or ctx.get("analytics_human_disclaimer", True),
                    "Financial output disclaimer: " + (
                        "N/A — no financial figures in response"
                        if not ctx.get("analytics_has_financial_output")
                        else ("PRESENT — response includes human review caveat"
                              if ctx.get("analytics_human_disclaimer")
                              else "ABSENT — financial figures with no human review caveat")
                    ),
                    {
                        "has_financial_output": ctx.get("analytics_has_financial_output", False),
                        "disclaimer_present": ctx.get("analytics_human_disclaimer", False),
                    },
                ),
            ),
            PolicyRule(
                rule_id="CHAT_008",
                description="Responses on eligibility or calculations must mention a human escalation path",
                regulatory_ref="RBI_FREE_AI_REC_21 | RBI_FREE_AI_REC_22",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("analytics_topic") not in ("loan_eligibility", "emi_calculation", "interest_rate")
                    or ctx.get("analytics_human_escalation", False),
                    "Human escalation in response: " + (
                        "N/A — topic does not require it"
                        if ctx.get("analytics_topic") not in ("loan_eligibility", "emi_calculation", "interest_rate")
                        else ("MENTIONED" if ctx.get("analytics_human_escalation")
                              else "NOT MENTIONED — required for financial topics")
                    ),
                    {
                        "topic": ctx.get("analytics_topic"),
                        "human_escalation_in_response": ctx.get("analytics_human_escalation", False),
                    },
                ),
            ),
            PolicyRule(
                rule_id="CHAT_009",
                description="Agent must not request PII (PAN, Aadhaar, account number) from the user",
                regulatory_ref="DPDP_ACT_2023_S8_DATA_MINIMISATION | RBI_FREE_AI_PILLAR_5",
                action_on_fail=PolicyAction.BLOCK,
                risk_tier_applies=[1, 2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    not ctx.get("analytics_pii_requested", False),
                    "PII requested by agent: " + (
                        "YES — NON-COMPLIANT, agent asked user to provide PII"
                        if ctx.get("analytics_pii_requested")
                        else "NO — compliant"
                    ),
                    {"pii_requested_by_agent": ctx.get("analytics_pii_requested", False)},
                ),
            ),
        ]

    @staticmethod
    def full_chat_ruleset() -> List[PolicyRule]:
        """All chat guardrail rules combined."""
        return (
            ChatPolicy.consent_and_disclosure_rules()
            + ChatPolicy.explainability_rules()
            + ChatPolicy.data_minimisation_rules()
            + ChatPolicy.human_oversight_rules()
        )
