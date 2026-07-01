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

# Conservative patterns — flag for review, not hard block
_PAN_PATTERN     = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')
_AADHAAR_PATTERN = re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b')
_PHONE_PATTERN   = re.compile(r'\b(\+91[\s-]?)?[6-9]\d{9}\b')
_EMAIL_PATTERN   = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
_ACCOUNT_PATTERN = re.compile(r'\b\d{9,18}\b')  # bank account numbers


def detect_pii(text: str) -> List[str]:
    """Return list of PII types found in text."""
    found = []
    if _PAN_PATTERN.search(text):
        found.append("PAN")
    if _AADHAAR_PATTERN.search(text):
        found.append("AADHAAR")
    if _PHONE_PATTERN.search(text):
        found.append("PHONE")
    if _EMAIL_PATTERN.search(text):
        found.append("EMAIL")
    if _ACCOUNT_PATTERN.search(text):
        found.append("ACCOUNT_NUMBER_PATTERN")
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
                description="AI disclosure: user must be informed they are interacting with an AI system",
                regulatory_ref="RBI_FREE_AI_REC_22_CONSUMER_TRANSPARENCY",
                action_on_fail=PolicyAction.WARN,
                risk_tier_applies=[2, 3],
                version="1.0",
                check_fn=lambda ctx: (
                    ctx.get("ai_disclosed_to_user", False),
                    "AI disclosure: " + ("CONFIRMED" if ctx.get("ai_disclosed_to_user") else "NOT RECORDED"),
                    {"ai_disclosed": ctx.get("ai_disclosed_to_user", False)},
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
        ]

    @staticmethod
    def human_oversight_rules() -> List[PolicyRule]:
        """
        RBI MRM 2026 — Human oversight for Tier 1 models:
        High-stakes outputs (credit, fraud, AML) require human review path.
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
