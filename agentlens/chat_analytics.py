"""
AgentLens Chat Analytics
-------------------------
Lightweight classifiers that run on every conversation turn to produce
the structured evidence regulators need per interaction.

All classifiers are deterministic keyword/pattern based — no LLM call,
no external dependency. Fast, auditable, reproducible.

Covers:
  RBI FREE-AI Rec 18  — topic and response type classification for explainability
  RBI FREE-AI Rec 22  — consumer protection signals (AI disclosure, escalation)
  RBI FREE-AI Rec 23  — grievance channel detection
  RBI MRM 2026        — automation bias indicators, output risk classification
  DPDP Act 2023       — PII pattern detection in both input and output
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from .chat_policy import detect_pii, detect_pii_in_user_input


# ─────────────────────────────────────────────────────────────────────────────
# Topic classification — what did the user ask about?
# ─────────────────────────────────────────────────────────────────────────────

TOPIC_PATTERNS = {
    "loan_eligibility":     [r"eligib", r"qualify", r"can i (get|apply|take)", r"am i eligible"],
    "emi_calculation":      [r"\bemi\b", r"monthly (payment|instalment|installment)", r"repay", r"how much (will|would) i pay"],
    "interest_rate":        [r"interest rate", r"roi\b", r"rate of interest", r"percent"],
    "documentation":        [r"document", r"what do i need", r"papers", r"submit", r"kyc", r"proof"],
    "loan_amount":          [r"how much (loan|amount|can i borrow)", r"maximum loan", r"loan limit", r"amount.*loan"],
    "complaint_grievance":  [r"complain", r"grievance", r"dissatisfied", r"unhappy", r"escalate", r"complaint"],
    "human_agent_request":  [r"speak to (a |an )?(human|person|agent|officer)", r"transfer (me|call)", r"real person"],
    "fraud_security":       [r"fraud", r"scam", r"unauthoris", r"stolen", r"suspicious"],
    "account_query":        [r"account (balance|statement|number)", r"transaction", r"passbook"],
    "general_enquiry":      [],   # fallback
}


def classify_topic(text: str) -> str:
    text_lower = text.lower()
    for topic, patterns in TOPIC_PATTERNS.items():
        if topic == "general_enquiry":
            continue
        if any(re.search(p, text_lower) for p in patterns):
            return topic
    return "general_enquiry"


# ─────────────────────────────────────────────────────────────────────────────
# Response type — what did the agent do?
# ─────────────────────────────────────────────────────────────────────────────

RESPONSE_TYPE_PATTERNS = {
    "eligibility_assessed":    [r"eligible", r"qualify", r"meet.{0,30}criteria", r"strong candidate"],
    "calculation_provided":    [r"emi.{0,20}(₹|\brs\.?\b|\binr\b)", r"per month", r"interest rate.{0,30}%"],
    "escalation_triggered":    [r"credit officer", r"human (officer|team|agent|review)", r"branch", r"speak with"],
    "disclaimer_added":        [r"final (decision|eligibility|assessment).{0,40}(human|officer|review)", r"indicative", r"subject to"],
    "ai_disclosed":            [r"i am an ai", r"i'?m an ai", r"ai assistant", r"virtual assistant", r"automated"],
    "grievance_provided":      [r"grievance", r"complain", r"1800", r"helpline", r"redress"],
    "information_provided":    [],   # fallback
}


def classify_response_type(text: str) -> List[str]:
    text_lower = text.lower()
    types = []
    for rtype, patterns in RESPONSE_TYPE_PATTERNS.items():
        if rtype == "information_provided":
            continue
        if any(re.search(p, text_lower) for p in patterns):
            types.append(rtype)
    return types or ["information_provided"]


# ─────────────────────────────────────────────────────────────────────────────
# Bias indicators — RBI FREE-AI Rec 18: bias audit evidence
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BiasCheckResult:
    automation_bias_risk: bool = False      # Response made a definitive claim without human review caveat
    demographic_assumption: bool = False    # Response assumed demographic (gender, caste, region)
    income_stereotype: bool = False         # Response made assumption based on income level alone
    disclaimer_present: bool = False        # Human review disclaimer included
    flags: List[str] = field(default_factory=list)

    @property
    def overall_risk(self) -> str:
        if self.automation_bias_risk or self.demographic_assumption or self.income_stereotype:
            if not self.disclaimer_present:
                return "HIGH"
            return "MEDIUM"
        return "LOW"


def check_bias_indicators(user_input: str, agent_output: str) -> BiasCheckResult:
    result = BiasCheckResult()
    out_lower = agent_output.lower()
    inp_lower = user_input.lower()

    # Automation bias: definitive statement without human caveat
    definitive_patterns = [r"\byou (are|will be) (approved|eligible|denied|rejected)\b",
                           r"\byou (qualify|don.t qualify)\b"]
    human_caveat_patterns = [r"human", r"officer", r"review", r"subject to", r"indicative", r"final decision"]

    has_definitive = any(re.search(p, out_lower) for p in definitive_patterns)
    has_caveat = any(re.search(p, out_lower) for p in human_caveat_patterns)
    result.disclaimer_present = has_caveat

    if has_definitive and not has_caveat:
        result.automation_bias_risk = True
        result.flags.append("Definitive approval/rejection without human review caveat")

    # Demographic assumption (basic signals)
    demographic_signals = [r"\b(housewife|homemaker)\b", r"\b(he|she) (earns|works)",
                           r"\bfemale applicant\b", r"\bmale applicant\b"]
    if any(re.search(p, out_lower) for p in demographic_signals):
        result.demographic_assumption = True
        result.flags.append("Possible demographic assumption in response")

    # Income stereotyping: making assumptions based only on income bracket
    income_stereotype_signals = [r"with (your|that) (salary|income|earning).{0,30}(guaranteed|definitely|certainly)"]
    if any(re.search(p, out_lower) for p in income_stereotype_signals):
        result.income_stereotype = True
        result.flags.append("Income-based assumption without full credit assessment")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Consumer protection checks — RBI FREE-AI Rec 22 + 23
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConsumerProtectionResult:
    ai_identity_disclosed: bool = False      # Agent said it is an AI
    human_escalation_mentioned: bool = False # Agent offered human escalation
    grievance_channel_mentioned: bool = False
    pii_requested_by_agent: bool = False     # Agent asked for PAN/Aadhaar (non-compliant)
    flags: List[str] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return not self.pii_requested_by_agent and not self.flags


def check_consumer_protection(agent_output: str) -> ConsumerProtectionResult:
    result = ConsumerProtectionResult()
    out_lower = agent_output.lower()

    if any(re.search(p, out_lower) for p in [r"i am an ai", r"i'?m an ai", r"ai assistant", r"virtual assistant", r"automated system"]):
        result.ai_identity_disclosed = True

    if any(re.search(p, out_lower) for p in [
        r"human (officer|agent|team|expert)", r"credit officer", r"branch",
        r"call us", r"speak with", r"\b1800\b", r"helpline", r"toll.?free",
    ]):
        result.human_escalation_mentioned = True

    if any(re.search(p, out_lower) for p in [r"grievance", r"complain", r"redress", r"helpline", r"1800"]):
        result.grievance_channel_mentioned = True

    # Flag if agent asked for PII (non-compliant under DPDP)
    pii_request_patterns = [r"(share|provide|give me|tell me).{0,20}(pan|aadhaar|account number|date of birth|dob)"]
    if any(re.search(p, out_lower) for p in pii_request_patterns):
        result.pii_requested_by_agent = True
        result.flags.append("Agent requested PII — non-compliant under DPDP Act 2023")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Combined turn analytics
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TurnAnalytics:
    topic: str = "general_enquiry"
    response_types: List[str] = field(default_factory=list)
    pii_in_input: List[str] = field(default_factory=list)
    pii_in_output: List[str] = field(default_factory=list)
    bias: Optional[BiasCheckResult] = None
    consumer_protection: Optional[ConsumerProtectionResult] = None

    @property
    def risk_summary(self) -> str:
        if self.pii_in_input or self.pii_in_output:
            return "HIGH — PII detected"
        if self.bias and self.bias.overall_risk == "HIGH":
            return "HIGH — automation bias risk"
        if self.consumer_protection and not self.consumer_protection.compliant:
            return "MEDIUM — consumer protection issue"
        if self.bias and self.bias.overall_risk == "MEDIUM":
            return "MEDIUM — bias caveat present"
        return "LOW"


def analyse_turn(user_input: str, agent_output: str) -> TurnAnalytics:
    return TurnAnalytics(
        topic=classify_topic(user_input),
        response_types=classify_response_type(agent_output),
        pii_in_input=detect_pii_in_user_input(user_input),   # broad — user may share own contact
        pii_in_output=detect_pii(agent_output),               # strict — institutional contacts excluded
        bias=check_bias_indicators(user_input, agent_output),
        consumer_protection=check_consumer_protection(agent_output),
    )
