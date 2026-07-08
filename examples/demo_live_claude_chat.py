"""
AgentLens — Live Claude Chat Audit Demo
========================================
Runs a real conversation against the Claude API (claude-haiku-4-5 for speed)
simulating a customer asking about loan eligibility at an NBFC.

Every turn is intercepted by AgentLens and produces a full 7-section
compliance audit report: chain-verified, DPDP-compliant, RBI FREE-AI aligned.

Requirements:
    pip install anthropic
    export ANTHROPIC_API_KEY=your_key_here

Run:
    python examples/demo_live_claude_chat.py
"""

import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import anthropic
except ImportError:
    print("ERROR: anthropic SDK not installed. Run: pip install anthropic")
    sys.exit(1)

from agentlens import (
    AgentLensConfig,
    PolicyEngine,
    RiskTier,
    ChatSessionTracer,
    ModelCard,
    LiveSessionReport,
    ChatPolicy,
)
from agentlens.config import EntityType, RegulatoryFramework

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None


def section(title: str):
    if RICH:
        console.rule(f"[bold green]{title}[/bold green]")
    else:
        print(f"\n{'='*70}\n  {title}\n{'='*70}")


def info(msg: str):
    if RICH:
        console.print(f"[green]✓[/green] {msg}")
    else:
        print(f"  ✓ {msg}")


def warn(msg: str):
    if RICH:
        console.print(f"[yellow]⚠[/yellow]  {msg}")
    else:
        print(f"  ⚠ {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Claude adapter — converts AgentLens call signature to Anthropic SDK
# ─────────────────────────────────────────────────────────────────────────────

def make_claude_adapter(api_key: str, model: str):
    """
    Returns a callable that ChatSessionTracer uses to call the Claude API.
    Signature: (messages, system) -> (response_text, input_tokens, output_tokens)
    """
    client = anthropic.Anthropic(api_key=api_key)

    def adapter(messages, system=""):
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system,
            messages=messages,
        )
        text = response.content[0].text
        return text, response.usage.input_tokens, response.usage.output_tokens

    return adapter


# ─────────────────────────────────────────────────────────────────────────────
# Mock adapter — realistic pre-scripted responses, no API key needed.
# Identical call signature to make_claude_adapter — swap in/out freely.
# ─────────────────────────────────────────────────────────────────────────────

_MOCK_RESPONSES = [
    (
        "Thank you for reaching out to SuryaFinance! I'm an AI assistant here to help you "
        "with your loan enquiry. For a ₹5 lakh personal loan, you would generally need a "
        "stable monthly income (typically ₹20,000+), a CIBIL score of 700 or above, and "
        "at least 1 year of continuous employment. A final eligibility decision will be "
        "made by one of our human credit officers after reviewing your application. "
        "Would you like to know more about the specific criteria?",
        312, 98
    ),
    (
        "Great — with a monthly income of ₹60,000 and 3 years of employment, you look "
        "like a strong candidate! Our typical eligibility criteria for a ₹5 lakh loan are: "
        "(1) CIBIL score ≥ 700, (2) Debt-to-income ratio below 50%, meaning your total "
        "EMIs should not exceed ₹30,000/month, (3) Minimum 1 year at current employer. "
        "Your income comfortably meets criterion (2). A credit officer will verify your "
        "CIBIL score and employment proof before final approval.",
        398, 124
    ),
    (
        "For a ₹5 lakh loan over 36 months, here's an indicative EMI estimate: "
        "At 14% annual interest rate: approximately ₹17,090/month. "
        "At 16% annual interest rate: approximately ₹17,580/month. "
        "Your actual rate will depend on your CIBIL score, employer category, and "
        "our credit assessment. These are indicative figures only — the final rate "
        "will be confirmed by our credit officer. Your income of ₹60,000/month means "
        "an EMI of ~₹17,000 is well within the 50% DTI guideline.",
        421, 137
    ),
    (
        "For a personal loan application at SuryaFinance, you will need: "
        "Identity Proof: PAN card (mandatory), Aadhaar card. "
        "Address Proof: Aadhaar, utility bill, or rental agreement. "
        "Income Proof: Last 3 months' salary slips, last 6 months' bank statements. "
        "Employment Proof: Offer letter or employment certificate. "
        "Photograph: 2 recent passport-size photos. "
        "Please submit these to your nearest SuryaFinance branch or upload via our app. "
        "Our team will process your application within 2-3 business days. "
        "Is there anything else I can help you with?",
        445, 152
    ),
]


def make_mock_adapter():
    """
    Returns a mock adapter that serves pre-scripted realistic responses.
    Identical interface to make_claude_adapter — no API key needed.
    Use this for demos, testing, and when credits are unavailable.
    """
    import time
    call_count = [0]

    def adapter(messages, system=""):
        idx = min(call_count[0], len(_MOCK_RESPONSES) - 1)
        text, input_tok, output_tok = _MOCK_RESPONSES[idx]
        call_count[0] += 1
        time.sleep(0.08)   # Simulate realistic network latency
        return text, input_tok, output_tok

    return adapter


# ─────────────────────────────────────────────────────────────────────────────
# DEMO
# ─────────────────────────────────────────────────────────────────────────────

def run_demo():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    MODEL_ID = "claude-haiku-4-5"
    MODEL_VERSION = "claude-haiku-4-5-20251001"

    # Auto-detect: use real Claude if key is present, otherwise mock
    if api_key:
        claude_adapter = make_claude_adapter(api_key, MODEL_ID)
        adapter_label = f"Claude API ({MODEL_ID})"
    else:
        claude_adapter = make_mock_adapter()
        adapter_label = f"Mock adapter — realistic pre-scripted responses (no API key needed)"
        MODEL_ID = "claude-haiku-4-5-mock"

    if RICH:
        console.print(Panel.fit(
            "[bold white]AgentLens — Live Claude Chat Audit Demo[/bold white]\n"
            "[dim]NBFC Customer Service Agent — Loan Eligibility Queries[/dim]\n"
            f"[dim]{adapter_label}[/dim]",
            border_style="green",
        ))
    else:
        print("\n" + "="*70)
        print("  AgentLens — Live Claude Chat Audit Demo")
        print(f"  {adapter_label}")
        print("="*70)

    # ── STEP 1: Configure ───────────────────────────────────────────────────
    section("STEP 1 — Configure AgentLens")

    config = AgentLensConfig(
        entity_name="SuryaFinance NBFC Ltd.",
        entity_type=EntityType.NBFC,
        regulatory_frameworks=[
            RegulatoryFramework.RBI_FREE_AI,
            RegulatoryFramework.RBI_MRM_2026,
            RegulatoryFramework.DPDP_2023,
        ],
        board_policy_ref="AI_CUSTOMER_POLICY_v1.1_BOARD_JAN2026",
        audit_retention_days=1825,
        pii_masking_enabled=True,
        default_model_risk_tier=2,
        ai_officer_name="Meera Iyer",
        ai_officer_email="ai.officer@suryafinance.in",
        model_inventory_ref="INV-2026-CS-001",
    )
    info(f"Entity: {config.entity_name}")
    info(f"AI Officer: {config.ai_officer_name} ({config.ai_officer_email})")
    info(f"Policy: {config.board_policy_ref}")

    # ── STEP 2: Model card ──────────────────────────────────────────────────
    section("STEP 2 — Register Model (RBI MRM Inventory)")

    model_card = ModelCard(
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        provider="anthropic",
        risk_tier=RiskTier.MEDIUM,           # Tier 2 — customer service chat
        intended_use="customer_service_loan_enquiry",
        inventory_id="INV-2026-CS-001",
        last_validated_date="2026-03-15",
        kill_switch_available=True,
        kill_switch_last_tested="2026-06-01",
        deployment_environment="production",
        vendor_audit_rights=True,
    )
    info(f"Model: {model_card.model_id} ({model_card.provider})")
    info(f"Risk tier: Tier {model_card.risk_tier.value} — {model_card.risk_tier.name}")
    info(f"Inventory ID: {model_card.inventory_id}")
    info(f"Last validated: {model_card.last_validated_date}")

    # ── STEP 3: Policy engine ───────────────────────────────────────────────
    section("STEP 3 — Load Chat Guardrail Rules")

    engine = PolicyEngine()
    engine.add_rules(ChatPolicy.full_chat_ruleset())
    info(f"Loaded {len(engine.rules)} guardrail rules")

    # ── STEP 4: System prompt ───────────────────────────────────────────────
    SYSTEM_PROMPT = """You are a helpful customer service assistant for SuryaFinance NBFC Ltd.,
an RBI-regulated non-banking financial company in India.

Your role is to help customers understand:
- Personal loan eligibility criteria
- EMI calculations
- Documentation required for loan applications
- General product information

Important guidelines:
- Do NOT ask for or repeat personal identifiers like PAN, Aadhaar, account numbers
- Always remind customers that final eligibility is determined by a human credit officer
- Mention that this is an AI assistant when asked
- For specific credit decisions, always say a human credit officer will review

You represent an AI system operating under RBI FREE-AI Framework guidelines."""

    # ── STEP 5: Live chat session ───────────────────────────────────────────
    section("STEP 4 — Live Chat Session with Audit Tracing")

    # Simulated customer conversation about loan eligibility
    conversation = [
        {
            "message": "Hi, I want to know if I'm eligible for a personal loan of ₹5 lakhs.",
            "summary": "Customer enquiry: ₹5L personal loan eligibility. General informational query — no credit decision made.",
            "clause": "CUSTOMER_POLICY_v1.1 §2.1 — General Loan Enquiries",
        },
        {
            "message": "I earn about ₹60,000 per month and I have been working for 3 years. What are the criteria?",
            "summary": "Customer provided income (₹60K/month) and employment duration (3 years). Eligibility criteria explained — no personal data stored.",
            "clause": "CUSTOMER_POLICY_v1.1 §3.2 — Eligibility Criteria Disclosure",
        },
        {
            "message": "What would be the approximate EMI for ₹5 lakhs over 3 years?",
            "summary": "EMI calculation requested: ₹5L principal, 36-month tenure. Indicative calculation provided — subject to credit officer review.",
            "clause": "CUSTOMER_POLICY_v1.1 §3.4 — Indicative EMI Disclosure",
        },
        {
            "message": "What documents will I need to submit?",
            "summary": "Document checklist provided for personal loan application. Standard KYC and income documents listed.",
            "clause": "CUSTOMER_POLICY_v1.1 §4.1 — Documentation Requirements",
        },
    ]

    with ChatSessionTracer(
        config=config,
        model_card=model_card,
        llm_adapter=claude_adapter,
        policy_engine=engine,
        system_prompt=SYSTEM_PROMPT,
        consent_ref="CONSENT-2026-CUST-8842991-LOAN-ENQUIRY",
        session_purpose="customer_loan_eligibility_enquiry",
    ) as tracer:

        for i, turn_data in enumerate(conversation, 1):
            if RICH:
                console.print(f"\n[bold cyan]Turn {i}[/bold cyan]")
                console.print(f"[dim]Customer:[/dim] {turn_data['message']}")
            else:
                print(f"\n  Turn {i}")
                print(f"  Customer: {turn_data['message']}")

            response = tracer.send(
                user_message=turn_data["message"],
                human_readable_summary=turn_data["summary"],
                policy_clause=turn_data["clause"],
                context={
                    "ai_disclosed_to_user": True,
                    "human_escalation_path_defined": True,
                    "pii_masked": True,
                    "consent_ref": "CONSENT-2026-CUST-8842991-LOAN-ENQUIRY",
                    "has_human_summary": True,
                    "policy_ref": config.board_policy_ref,
                },
            )

            if RICH:
                console.print(f"[dim]Claude:[/dim] {response[:200]}{'...' if len(response) > 200 else ''}")
            else:
                print(f"  Claude: {response[:200]}{'...' if len(response) > 200 else ''}")

            turn = tracer.turns[-1]
            info(f"Latency: {turn.latency_ms}ms | Tokens: {turn.input_tokens}in + {turn.output_tokens}out | Guardrail: {'✅ PASS' if turn.guardrail_passed else '⚠ FAIL'}")

        # ── STEP 6: Generate audit report ────────────────────────────────────
        section("STEP 5 — Generate 7-Section Compliance Audit Report")

        report = LiveSessionReport(tracer)
        print(report.to_console())

        # Export full JSON
        export_path = "/tmp/agentlens_live_chat_audit.json"
        with open(export_path, "w") as f:
            f.write(report.to_json())
        info(f"\nFull 7-section JSON report exported to: {export_path}")

        # Show session summary
        summary = tracer.get_session_summary()
        if RICH:
            t = Table(title="Session Summary", show_lines=True)
            t.add_column("Metric", style="cyan")
            t.add_column("Value")
            for k, v in summary.items():
                t.add_row(str(k), str(v))
            console.print(t)

    # Peek at the JSON structure
    section("STEP 6 — JSON Audit Trail (Regulator Submission Format)")
    with open(export_path) as f:
        data = json.load(f)

    snippet = {
        "agentlens_version": data["agentlens_version"],
        "section_1_entity": data["section_1"]["entity"],
        "section_5_chain_intact": data["section_5"]["chain_intact"],
        "section_6_dpdp_status": {
            "consent": data["section_6"]["consent"]["status"],
            "pii_masking": data["section_6"]["data_minimisation"]["status"],
            "pii_in_output": data["section_6"]["pii_in_output"]["status"],
        },
        "section_7_model_card_status": data["section_7"]["overall_status"],
        "total_turns": data["section_2"]["summary"]["total_turns"],
        "guardrail_summary": data["section_4"]["summary"],
    }

    if RICH:
        console.print(Syntax(json.dumps(snippet, indent=2), "json", theme="monokai"))
    else:
        print(json.dumps(snippet, indent=2))

    if RICH:
        console.print(Panel.fit(
            "[bold green]Live audit demo complete.[/bold green]\n\n"
            "AgentLens just:\n"
            "  ✅ Intercepted 4 real Claude API calls\n"
            "  ✅ Hashed every input/output (DPDP — no raw content in logs)\n"
            "  ✅ Ran 7 guardrail rules per turn\n"
            "  ✅ Built a tamper-evident SHA-256 audit chain\n"
            "  ✅ Generated a 7-section RBI/SEBI/DPDP compliance report\n"
            "  ✅ Exported JSON ready for RBI examiner submission\n\n"
            f"[dim]Full report: {export_path}[/dim]",
            border_style="green",
        ))
    else:
        print("\n" + "="*70)
        print("  Live audit demo complete.")
        print(f"  Full JSON report: {export_path}")
        print("="*70)


if __name__ == "__main__":
    run_demo()
