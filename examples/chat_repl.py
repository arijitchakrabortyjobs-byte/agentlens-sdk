"""
AgentLens — Interactive Chat REPL
===================================
Type your own messages. Every turn is audited live.
Type 'report' to see the full compliance report.
Type 'audit' to see the raw event chain.
Type 'quit' or Ctrl+C to exit and export the JSON audit trail.

Provider options (pick one — all free):

  1. Ollama  — local models, completely free, no account needed
     brew install ollama
     ollama pull llama3.2          # or mistral, phi3, gemma2, etc.
     python examples/chat_repl.py --ollama llama3.2

  2. Groq    — free cloud API (fast), needs a free account at groq.com
     python examples/chat_repl.py --groq YOUR_GROQ_KEY

  3. Mock    — pre-scripted responses, no install needed (default)
     python examples/chat_repl.py

  4. Claude  — needs paid credits
     ANTHROPIC_API_KEY=sk-ant-... python examples/chat_repl.py --claude
"""

import os
import sys
import json
import time
import argparse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentlens import (
    AgentLensConfig, PolicyEngine, RiskTier,
    ChatSessionTracer, ModelCard, LiveSessionReport, ChatPolicy,
)
from agentlens.config import EntityType, RegulatoryFramework

EXPORT_PATH = "/tmp/agentlens_repl_audit.json"


# ─────────────────────────────────────────────────────────────────────────────
# Adapters  (all share the same signature)
# (messages: list[dict], system: str) -> (text: str, input_tok: int, out_tok: int)
# ─────────────────────────────────────────────────────────────────────────────

def make_ollama_adapter(model: str = "llama3.2", host: str = "http://localhost:11434"):
    """
    Calls a locally running Ollama instance — completely free, no account needed.
    Install: brew install ollama
    Start:   ollama serve   (runs in background automatically after install)
    Model:   ollama pull llama3.2
    """
    def adapter(messages, system=""):
        # Build payload: Ollama uses OpenAI-compatible /v1/chat/completions
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)

        payload = json.dumps({
            "model": model,
            "messages": all_messages,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            f"{host}/v1/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
            text = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            return text, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
        except Exception as e:
            if "Connection refused" in str(e) or "refused" in str(e).lower():
                raise RuntimeError(
                    f"\n\n  Ollama is not running. Start it with:\n"
                    f"    ollama serve\n"
                    f"  And pull the model:\n"
                    f"    ollama pull {model}\n"
                ) from e
            raise

    return adapter


def make_groq_adapter(api_key: str, model: str = "llama-3.1-8b-instant"):
    """
    Calls Groq's free cloud API — very fast inference.
    Free account at: https://console.groq.com
    Free models: llama-3.1-8b-instant, llama-3.3-70b-versatile, mixtral-8x7b-32768
    """
    def adapter(messages, system=""):
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)

        payload = json.dumps({
            "model": model,
            "messages": all_messages,
            "max_tokens": 1024,
        }).encode()

        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return text, usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)

    return adapter


def make_claude_adapter(api_key: str, model: str = "claude-haiku-4-5"):
    """Real Claude API — requires paid credits."""
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("pip install anthropic")

    client = anthropic.Anthropic(api_key=api_key)

    def adapter(messages, system=""):
        try:
            r = client.messages.create(
                model=model, max_tokens=1024, system=system, messages=messages
            )
            return r.content[0].text, r.usage.input_tokens, r.usage.output_tokens
        except Exception as e:
            if "credit balance is too low" in str(e):
                raise RuntimeError(
                    "\n\n  Anthropic account has no credits.\n"
                    "  Use --ollama or --groq instead (both free).\n"
                    "  See: python examples/chat_repl.py --help\n"
                ) from e
            raise

    return adapter


def make_mock_adapter():
    """Pre-scripted realistic responses — no install, no account, no internet."""
    replies = [
        "Thank you for reaching out to SuryaFinance! I'm an AI assistant here to help. "
        "For a personal loan, you typically need a CIBIL score of 700+, monthly income ≥ ₹20,000, "
        "and at least 1 year of continuous employment. Final eligibility is confirmed by a human credit officer.",

        "Based on what you've shared, you appear to be a strong candidate. "
        "Key criteria: (1) CIBIL score ≥ 700, (2) Total EMIs ≤ 50% of monthly income, "
        "(3) Minimum 1 year at current employer. A credit officer will review your full application.",

        "For a ₹5 lakh loan over 36 months, indicative EMI is approximately ₹17,090/month at 14% p.a. "
        "or ₹17,580/month at 16% p.a. Your actual rate depends on your CIBIL score and profile. "
        "These are indicative figures — final rate confirmed by our credit officer.",

        "Documents required: PAN card, Aadhaar, last 3 months' salary slips, 6 months' bank statements, "
        "employment certificate. Submit at any SuryaFinance branch or via our app. "
        "Processing takes 2–3 business days.",

        "I'm an AI assistant, so I can only provide general information. "
        "For a personalised assessment or to start your application, please visit our nearest branch "
        "or call 1800-XXX-XXXX to speak with a human credit officer.",
    ]
    idx = [0]

    def adapter(messages, system=""):
        text = replies[idx[0] % len(replies)]
        idx[0] += 1
        time.sleep(0.05)
        input_chars = sum(len(m["content"]) for m in messages)
        return text, input_chars // 4, len(text) // 4

    return adapter


# ─────────────────────────────────────────────────────────────────────────────
# Tracer setup
# ─────────────────────────────────────────────────────────────────────────────

def build_tracer(adapter, model_id: str, provider: str):
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
        model_id=model_id,
        model_version=model_id,
        provider=provider,
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
        "an RBI-regulated NBFC in India. Help customers with personal loan eligibility, "
        "EMI calculations, and documentation requirements. "
        "Do NOT ask for or repeat PAN, Aadhaar, or account numbers. "
        "Always clarify that final credit decisions are made by human officers. "
        "Disclose that you are an AI when asked."
    )

    return ChatSessionTracer(
        config=config,
        model_card=model_card,
        llm_adapter=adapter,
        policy_engine=engine,
        system_prompt=system_prompt,
        consent_ref="CONSENT-REPL-SESSION-001",
        session_purpose="interactive_loan_enquiry",
    )


# ─────────────────────────────────────────────────────────────────────────────
# REPL
# ─────────────────────────────────────────────────────────────────────────────

def print_turn_audit(turn):
    print(f"\n  ┌─ Audit: Turn {turn.turn_index} {'─'*44}")
    print(f"  │  Input hash  : {turn.user_input_hash[:32]}...")
    print(f"  │  Output hash : {turn.assistant_output_hash[:32]}...")
    print(f"  │  Latency     : {turn.latency_ms} ms")
    print(f"  │  Tokens      : {turn.input_tokens} in / {turn.output_tokens} out")
    status = "✅ PASS" if turn.guardrail_passed else f"⚠  FAIL — {turn.guardrail_rules_failed}"
    print(f"  │  Guardrail   : {status}")
    print(f"  └{'─'*49}")


def parse_args():
    p = argparse.ArgumentParser(description="AgentLens Interactive Chat REPL")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--ollama", metavar="MODEL", nargs="?", const="llama3.2",
                       help="Use local Ollama (default model: llama3.2)")
    group.add_argument("--groq", metavar="API_KEY",
                       help="Use Groq free cloud API (get key at console.groq.com)")
    group.add_argument("--claude", action="store_true",
                       help="Use Claude API (needs ANTHROPIC_API_KEY with credits)")
    group.add_argument("--mock", action="store_true",
                       help="Use pre-scripted mock responses (default, no setup needed)")
    p.add_argument("--groq-model", default="llama-3.1-8b-instant",
                   help="Groq model to use (default: llama-3.1-8b-instant)")
    return p.parse_args()


def run_repl():
    args = parse_args()

    if args.ollama:
        model = args.ollama
        adapter = make_ollama_adapter(model)
        mode_label = f"Ollama local  ({model})"
        provider = "ollama"
    elif args.groq:
        model = args.groq_model
        adapter = make_groq_adapter(args.groq, model)
        mode_label = f"Groq free API ({model})"
        provider = "groq"
    elif args.claude:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print("\nERROR: --claude requires ANTHROPIC_API_KEY to be set.")
            sys.exit(1)
        adapter = make_claude_adapter(api_key)
        mode_label = "Claude API    (claude-haiku-4-5)"
        provider = "anthropic"
        model = "claude-haiku-4-5"
    else:
        adapter = make_mock_adapter()
        mode_label = "Mock          (pre-scripted, no setup needed)"
        provider = "mock"
        model = "mock-assistant"

    print("\n" + "="*60)
    print("  AgentLens Interactive Chat REPL")
    print("  Every message is audited in real time.")
    print()
    print("  Commands:  report | audit | quit")
    print("="*60)

    tracer = build_tracer(adapter, model, provider)

    print(f"\n  Mode    : {mode_label}")
    print(f"  Entity  : {tracer.config.entity_name}")
    print(f"  Session : {tracer.session_id[:24]}...")
    print(f"  Export  : {EXPORT_PATH}")
    print()
    print("  Ask anything about loans, EMIs, or eligibility.")
    print("  Type 'audit' to see the live event chain.")
    print("  Type 'report' for the full compliance report.")
    print("  Type 'quit' to exit.\n")

    try:
        while True:
            try:
                user_input = input("You: ").strip()
            except EOFError:
                break

            if not user_input:
                continue

            cmd = user_input.lower()

            if cmd == "quit":
                break

            if cmd == "report":
                tracer.close()
                print(LiveSessionReport(tracer).to_console())
                break

            if cmd == "audit":
                events = tracer.audit_log.get_events()
                chain_ok = tracer.audit_log.verify_integrity()
                print(f"\n  {'─'*54}")
                print(f"  {len(events)} events  |  chain intact: {'✅ YES' if chain_ok else '⚠ NO'}")
                for e in events:
                    print(f"  [{e.event_type.value:28s}] {e.event_hash[:18]}...")
                print(f"  {'─'*54}\n")
                continue

            try:
                response = tracer.send(
                    user_message=user_input,
                    human_readable_summary=f"Customer enquiry turn {len(tracer.turns)+1}: general loan information provided.",
                    context={
                        "ai_disclosed_to_user": True,
                        "human_escalation_path_defined": True,
                        "pii_masked": True,
                        "consent_ref": tracer.consent_ref,
                        "has_human_summary": True,
                        "policy_ref": tracer.config.board_policy_ref,
                    },
                )
            except RuntimeError as e:
                print(str(e))
                break

            print(f"\nAgent: {response}\n")
            print_turn_audit(tracer.turns[-1])
            print()

    except KeyboardInterrupt:
        print("\n\n  Interrupted.")

    tracer.close()
    report = LiveSessionReport(tracer)
    with open(EXPORT_PATH, "w") as f:
        f.write(report.to_json())

    s = tracer.get_session_summary()
    print("\n" + "="*60)
    print(f"  Session closed  |  Turns: {s['total_turns']}  |  Chain: {'✅' if s['chain_intact'] else '⚠'}")
    print(f"  JSON report → {EXPORT_PATH}")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_repl()
