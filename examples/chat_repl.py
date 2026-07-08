"""
AgentLens — Interactive Chat REPL
===================================
Type your own messages. Every turn is audited live.
Type 'report' to see the full compliance report.
Type 'quit' or Ctrl+C to exit and export the JSON audit trail.

Run:
    # With real Claude (needs ANTHROPIC_API_KEY with credits):
    ANTHROPIC_API_KEY=sk-ant-... python examples/chat_repl.py

    # Without API key (uses mock responses):
    python examples/chat_repl.py
"""

import os
import sys
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from agentlens import (
    AgentLensConfig, PolicyEngine, RiskTier,
    ChatSessionTracer, ModelCard, LiveSessionReport, ChatPolicy,
)
from agentlens.config import EntityType, RegulatoryFramework

EXPORT_PATH = "/tmp/agentlens_repl_audit.json"

# ── Adapters ─────────────────────────────────────────────────────────────────

def make_claude_adapter(api_key, model):
    client = anthropic.Anthropic(api_key=api_key)
    def adapter(messages, system=""):
        r = client.messages.create(model=model, max_tokens=1024, system=system, messages=messages)
        return r.content[0].text, r.usage.input_tokens, r.usage.output_tokens
    return adapter


def make_mock_adapter():
    """Rotates through generic helpful responses when no API key is available."""
    replies = [
        "Thank you for your question! I'm an AI assistant for SuryaFinance. "
        "For a personal loan, you typically need a CIBIL score of 700+, monthly income ≥ ₹20,000, "
        "and at least 1 year of employment. A human credit officer makes the final decision.",

        "That's a good question. Based on what you've shared, you appear to meet our general "
        "eligibility criteria. However, the final assessment depends on your full credit profile, "
        "which our credit officer will review. Shall I explain the application process?",

        "For documentation, you'll need: PAN card, Aadhaar, last 3 months' salary slips, "
        "6 months' bank statements, and employment certificate. You can submit these at any "
        "SuryaFinance branch or via our app.",

        "I understand your concern. While I can provide general information, specific credit "
        "decisions are made by our human credit officers to ensure fairness and accuracy. "
        "Would you like me to connect you with a credit officer?",

        "Is there anything else I can help you with today? Remember, this is an AI assistant "
        "and for any binding commitments, please speak with our human team.",
    ]
    idx = [0]
    def adapter(messages, system=""):
        text = replies[idx[0] % len(replies)]
        idx[0] += 1
        time.sleep(0.05)
        return text, len(" ".join(m["content"] for m in messages)) // 4, len(text) // 4
    return adapter

# ── Setup ─────────────────────────────────────────────────────────────────────

def build_tracer():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    use_live = bool(api_key and ANTHROPIC_AVAILABLE)

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
        ai_officer_name="Meera Iyer",
        ai_officer_email="ai.officer@suryafinance.in",
        model_inventory_ref="INV-2026-CS-001",
    )

    model_card = ModelCard(
        model_id="claude-haiku-4-5" if use_live else "claude-haiku-4-5-mock",
        model_version="claude-haiku-4-5-20251001",
        provider="anthropic",
        risk_tier=RiskTier.MEDIUM,
        intended_use="customer_service_loan_enquiry",
        inventory_id="INV-2026-CS-001",
        last_validated_date="2026-03-15",
        kill_switch_available=True,
        kill_switch_last_tested="2026-06-01",
    )

    engine = PolicyEngine()
    engine.add_rules(ChatPolicy.full_chat_ruleset())

    system_prompt = (
        "You are a helpful customer service AI assistant for SuryaFinance NBFC Ltd., "
        "an RBI-regulated non-banking financial company in India. Help customers understand "
        "personal loan eligibility, EMI calculations, and documentation. "
        "Never ask for or repeat PAN, Aadhaar, or account numbers. "
        "Always remind customers that final credit decisions are made by human officers. "
        "Disclose that you are an AI when asked."
    )

    adapter = make_claude_adapter(api_key, model_card.model_id) if use_live else make_mock_adapter()

    tracer = ChatSessionTracer(
        config=config,
        model_card=model_card,
        llm_adapter=adapter,
        policy_engine=engine,
        system_prompt=system_prompt,
        consent_ref="CONSENT-REPL-SESSION-001",
        session_purpose="interactive_loan_enquiry",
    )

    return tracer, use_live

# ── REPL ─────────────────────────────────────────────────────────────────────

def print_turn_audit(turn):
    print(f"\n  ┌─ Audit: Turn {turn.turn_index} {'─'*46}")
    print(f"  │  Input hash  : {turn.user_input_hash[:32]}...")
    print(f"  │  Output hash : {turn.assistant_output_hash[:32]}...")
    print(f"  │  Latency     : {turn.latency_ms} ms")
    print(f"  │  Tokens      : {turn.input_tokens} in / {turn.output_tokens} out")
    print(f"  │  Guardrail   : {'✅ PASS' if turn.guardrail_passed else '⚠  FAIL — ' + str(turn.guardrail_rules_failed)}")
    print(f"  └{'─'*51}")


def run_repl():
    print("\n" + "="*60)
    print("  AgentLens Interactive Chat REPL")
    print("  Every message is audited in real time.")
    print()
    print("  Commands:")
    print("    report  — show full 7-section compliance report")
    print("    audit   — show audit trail so far (compact)")
    print("    quit    — exit and export JSON report")
    print("="*60)

    tracer, use_live = build_tracer()
    mode = "Claude API (live)" if use_live else "Mock responses (no API key)"
    print(f"\n  Mode    : {mode}")
    print(f"  Entity  : {tracer.config.entity_name}")
    print(f"  Session : {tracer.session_id[:20]}...")
    print(f"  Export  : {EXPORT_PATH}")
    print("\n  Type your message below. The agent is an NBFC loan assistant.\n")

    try:
        while True:
            try:
                user_input = input("You: ").strip()
            except EOFError:
                break

            if not user_input:
                continue

            if user_input.lower() == "quit":
                break

            if user_input.lower() == "report":
                tracer.close()
                report = LiveSessionReport(tracer)
                print(report.to_console())
                # Re-open isn't possible cleanly; just continue showing report
                print("\n  (Session closed for report. Type 'quit' to exit.)")
                break

            if user_input.lower() == "audit":
                events = tracer.audit_log.get_events()
                print(f"\n  {'─'*56}")
                print(f"  Audit trail — {len(events)} events, chain intact: {tracer.audit_log.verify_integrity()}")
                for e in events:
                    print(f"  [{e.event_type.value:28s}] {e.event_hash[:16]}...")
                print(f"  {'─'*56}\n")
                continue

            # Normal message — send and audit
            response = tracer.send(
                user_message=user_input,
                human_readable_summary=f"Customer enquiry (turn {len(tracer.turns)+1}): general loan information provided.",
                context={
                    "ai_disclosed_to_user": True,
                    "human_escalation_path_defined": True,
                    "pii_masked": True,
                    "consent_ref": tracer.consent_ref,
                    "has_human_summary": True,
                    "policy_ref": tracer.config.board_policy_ref,
                },
            )

            print(f"\nAgent: {response}\n")
            print_turn_audit(tracer.turns[-1])
            print()

    except KeyboardInterrupt:
        print("\n\n  Interrupted.")

    # Always close and export on exit
    tracer.close()
    report = LiveSessionReport(tracer)
    with open(EXPORT_PATH, "w") as f:
        f.write(report.to_json())

    summary = tracer.get_session_summary()
    print("\n" + "="*60)
    print("  Session closed.")
    print(f"  Turns          : {summary['total_turns']}")
    print(f"  Total tokens   : {summary['total_input_tokens']} in / {summary['total_output_tokens']} out")
    print(f"  Guardrail fails: {summary['guardrail_failures']}")
    print(f"  Chain intact   : {'✅ YES' if summary['chain_intact'] else '⚠ NO'}")
    print(f"  JSON report    : {EXPORT_PATH}")
    print("="*60)
    print("\n  Run this to see the full 7-section report:")
    print(f"    python -c \"import json; from agentlens.live_report import *; print(open('{EXPORT_PATH}').read())\"")
    print()


if __name__ == "__main__":
    run_repl()
