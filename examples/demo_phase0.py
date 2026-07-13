"""
AgentLens Phase 0 — Offline Demo
=================================
Runs entirely offline, zero external deps required.
Shows all four Phase 0 features in action:
  0a. WORM storage (LocalNDJSONAdapter)
  0b. Pre-model PII firewall
  0c. Cross-session override rate (ComplianceDatabase)
  0d. OTEL export (graceful degradation)

Run:  python examples/demo_phase0.py
"""

import json
import tempfile
import os
import sys

# ── Optional rich terminal output ──────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import print as rprint
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None


def section(title):
    if HAS_RICH:
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    else:
        print(f"\n{'─'*60}")
        print(f"  {title}")
        print('─'*60)


def ok(msg):
    if HAS_RICH:
        console.print(f"  [green]✓[/green] {msg}")
    else:
        print(f"  ✓ {msg}")


def info(msg):
    if HAS_RICH:
        console.print(f"  [dim]{msg}[/dim]")
    else:
        print(f"    {msg}")


def show_json(label, obj):
    if HAS_RICH:
        from rich.syntax import Syntax
        console.print(f"\n  [bold]{label}:[/bold]")
        console.print(Syntax(json.dumps(obj, indent=2, default=str), "json", theme="monokai", word_wrap=True))
    else:
        print(f"\n  {label}:")
        print(json.dumps(obj, indent=2, default=str))


# ──────────────────────────────────────────────────────────────────────────
# Phase 0a — WORM Storage
# ──────────────────────────────────────────────────────────────────────────

def demo_worm_storage(tmp_dir):
    section("Phase 0a — WORM Storage (LocalNDJSONAdapter)")

    from agentlens.storage import LocalNDJSONAdapter, MultiAdapter
    from agentlens.audit_log import AuditLog, AuditEvent, EventType, RiskTier

    store_path = os.path.join(tmp_dir, "worm_store")
    adapter = LocalNDJSONAdapter(base_dir=store_path)
    log = AuditLog(entity_name="DemoBank", storage_adapter=adapter)

    # Record two events
    log.append(AuditEvent(agent_id="credit_agent_v2", event_type=EventType.AGENT_START))
    from agentlens.audit_log import AuditEvent
    decision = AuditEvent(agent_id="credit_agent_v2", event_type=EventType.DECISION)
    decision.risk_tier = RiskTier.HIGH
    decision.human_readable_reasoning = "Approved: CIBIL 724, income 3.2x EMI"
    decision.decision_output = "APPROVED ₹5,00,000 @ 10.5%"
    log.append(decision)

    # Verify
    ndjson_files = list(__import__('pathlib').Path(store_path).rglob("*.ndjson"))
    assert len(ndjson_files) == 1, "Expected exactly one NDJSON file"
    lines = ndjson_files[0].read_text().strip().split("\n")
    assert len(lines) == 2

    ok(f"NDJSON written to: {ndjson_files[0].relative_to(tmp_dir)}")
    ok(f"Events persisted: {len(lines)}")
    ok(f"Chain intact: {log.verify_integrity()}")

    # Show first event
    persisted = json.loads(lines[1])  # decision event
    show_json("Persisted decision event (tamper-evident WORM)", {
        "event_type": persisted["event_type"],
        "risk_tier": persisted["risk_tier"],
        "decision_output": persisted["decision_output"],
        "event_hash": persisted["event_hash"][:16] + "...",
        "prev_event_hash": (persisted.get("prev_event_hash") or "")[:16] + "...",
    })

    hc = adapter.health_check()
    ok(f"Health check: {hc['adapter']} — base_dir exists: {hc.get('base_dir_exists', '?')}")


# ──────────────────────────────────────────────────────────────────────────
# Phase 0b — PII Firewall
# ──────────────────────────────────────────────────────────────────────────

def demo_pii_firewall():
    section("Phase 0b — Pre-Model PII Firewall")

    from agentlens.pii_firewall import tokenize_pii, firewall_messages

    test_inputs = [
        "My PAN is ABCDE1234F and I need a ₹10L home loan.",
        "Aadhaar 1234 5678 9012, phone 9876543210. Call helpline 1800-103-1234.",
        "Send OTP to user@hdfc.co.in, account number 123456789012",
    ]

    if HAS_RICH:
        t = Table("Raw Input", "Tokenized Output", "PII Types Found", title="PII Firewall Results")
        for text in test_inputs:
            clean, vault = tokenize_pii(text)
            t.add_row(text, clean, ", ".join(vault.pii_types_found) or "none")
        console.print(t)
    else:
        for text in test_inputs:
            clean, vault = tokenize_pii(text)
            print(f"\n  IN : {text}")
            print(f"  OUT: {clean}")
            print(f"  PII: {vault.pii_types_found}")

    # Demonstrate round-trip restore
    original = "PAN ABCDE1234F, Aadhaar 1234 5678 9012"
    clean, vault = tokenize_pii(original)
    restored = vault.restore(clean)
    assert restored == original
    ok(f"Round-trip restore: '{original}' → tokenized → restored correctly")

    # Demonstrate firewall_messages (OpenAI-style)
    messages = [
        {"role": "system", "content": "You are a secure banking assistant."},
        {"role": "user",   "content": "My PAN ABCDE1234F. Am I eligible for a loan?"},
    ]
    clean_msgs, vault = firewall_messages(messages)
    assert clean_msgs[0]["content"] == messages[0]["content"], "System message must be unchanged"
    assert "ABCDE1234F" not in clean_msgs[1]["content"], "PAN must be tokenized in user message"
    ok("System message unchanged, user PAN tokenized before LLM call")
    ok(f"Token count: {vault.token_count} — types: {vault.pii_types_found}")


# ──────────────────────────────────────────────────────────────────────────
# Phase 0c — Compliance Database
# ──────────────────────────────────────────────────────────────────────────

def demo_compliance_db(tmp_dir):
    section("Phase 0c — Cross-Session Override Rate (ComplianceDatabase)")

    from agentlens.compliance_db import ComplianceDatabase

    db_path = os.path.join(tmp_dir, "compliance.db")
    db = ComplianceDatabase(db_path=db_path)

    # Simulate 4 sessions — 3 with no overrides (rubber stamp risk), 1 with overrides
    sessions = [
        {"session_id": "sess-001", "entity": "DemoBank", "decisions_recorded": 12, "human_overrides": 0, "chain_intact": True},
        {"session_id": "sess-002", "entity": "DemoBank", "decisions_recorded": 10, "human_overrides": 0, "chain_intact": True},
        {"session_id": "sess-003", "entity": "DemoBank", "decisions_recorded": 8,  "human_overrides": 3, "chain_intact": True},
        {"session_id": "sess-004", "entity": "DemoBank", "decisions_recorded": 9,  "human_overrides": 0, "chain_intact": True},
    ]
    for s in sessions:
        db.record_session(s)

    rate = db.override_rate("DemoBank")
    stamps = db.rubber_stamp_sessions("DemoBank", min_decisions=5)
    summary = db.entity_summary("DemoBank")

    ok(f"Sessions recorded: {summary['total_sessions']}")
    ok(f"Total decisions: {summary['total_decisions']}")
    ok(f"Cross-session override rate: {rate:.1%}  (US SR 26-2 effective challenge metric)")
    ok(f"Rubber-stamp sessions (0 overrides, ≥5 decisions): {stamps}")
    ok(f"Rubber-stamp flag raised: {summary['rubber_stamp_flag']}")

    # Set responsibility chain (UK ICO accountability)
    db.set_responsibility_map(
        entity_name="DemoBank",
        developer="AgentLens Ltd.",
        platform="AWS ap-south-1",
        deployer="DemoBank IT Risk",
        end_user_ref="retail_banking_portal",
    )
    rmap = db.get_responsibility_map("DemoBank")
    ok(f"Responsibility chain set: {[r['role'] for r in rmap]}")

    show_json("entity_summary", summary)


# ──────────────────────────────────────────────────────────────────────────
# Phase 0d — OTEL Export
# ──────────────────────────────────────────────────────────────────────────

def demo_otel():
    section("Phase 0d — OTEL Export (graceful degradation)")

    from agentlens.otel import OTELExporter
    from agentlens.audit_log import AuditLog, AuditEvent, EventType

    exporter = OTELExporter(endpoint="http://localhost:4317", service_name="agentlens-demo")
    hc = exporter.health_check()

    ok(f"OTEL SDK available: {hc.get('otel_sdk_available', False)}")
    ok(f"Initialised: {hc.get('initialised', False)}")

    if not hc.get("otel_sdk_available"):
        info("opentelemetry-sdk not installed → graceful no-op mode")
        info("Install with: pip install 'agentlens[otel]'")
        info("Then point to Grafana/Datadog/Azure Monitor OTLP endpoint")
    else:
        info("OTEL SDK found — spans will be emitted to collector")

    # Even without SDK, emit must not raise
    log = AuditLog("DemoBank", otel_exporter=exporter)
    log.append(AuditEvent(agent_id="credit_agent", event_type=EventType.AGENT_START))
    log.append(AuditEvent(agent_id="credit_agent", event_type=EventType.AGENT_END))
    assert log.verify_integrity()
    ok("emit() called — no exception raised; chain integrity verified")

    show_json("health_check()", hc)


# ──────────────────────────────────────────────────────────────────────────
# Full end-to-end integration demo
# ──────────────────────────────────────────────────────────────────────────

def demo_end_to_end(tmp_dir):
    section("Integration — All Phase 0 components wired together")

    from agentlens.storage import LocalNDJSONAdapter
    from agentlens.otel import OTELExporter
    from agentlens.compliance_db import ComplianceDatabase
    from agentlens import AuditTracer, AgentLensConfig, ComplianceReporter
    from agentlens.config import EntityType, RegulatoryFramework
    from agentlens.audit_log import RiskTier

    config = AgentLensConfig(
        entity_name="DemoNBFC",
        entity_type=EntityType.NBFC,
        board_policy_ref="AI_POLICY_v2.1_JUL2026",
        pii_masking_enabled=True,
        regulatory_frameworks=[RegulatoryFramework.RBI_FREE_AI, RegulatoryFramework.DPDP_2023],
    )

    storage = LocalNDJSONAdapter(base_dir=os.path.join(tmp_dir, "e2e_store"))
    otel    = OTELExporter(endpoint="http://localhost:4317")
    db      = ComplianceDatabase(db_path=os.path.join(tmp_dir, "e2e.db"))

    tracer = AuditTracer(config, storage_adapter=storage, otel_exporter=otel)

    with tracer.trace_agent("loan_approval_agent") as span:
        span.set_model("claude-sonnet-5", "1.0")
        span.set_risk_tier(RiskTier.HIGH)
        span.set_policy("AI_POLICY_v2.1_JUL2026")

        span.record_decision(
            output="APPROVED ₹7,50,000 @ 11.25% for 60 months",
            reasoning="CIBIL 748 > 700 threshold, income ₹1.8L/mo > 3x EMI, existing EMI < 40% NMI",
            context={"pii_masked": True, "cibil_score": 748},
            human_review_required=False,
        )

        span.record_human_override(
            reviewer_id="rm_priya@demonbfc.in",
            reason="Applicant is NRI — requires manual KYC per FEMA 1999",
            original_decision="APPROVED",
            new_decision="PENDING_KYC",
        )

    log = tracer.get_log()
    reporter = ComplianceReporter(log, config, compliance_db=db)

    ok(f"Chain intact: {log.verify_integrity()}")
    ok(f"Events in log: {len(log.get_events())}")

    rbi_report = reporter.rbi_free_ai_summary()
    ok(f"RBI FREE-AI governance: {rbi_report['pillar_status']['governance']['status']}")
    ok(f"RBI FREE-AI assurance: {rbi_report['pillar_status']['assurance']['status']}")
    ok(f"Session override rate: {rbi_report['pillar_status']['protection']['session_override_rate']:.0%}")

    cross_report = reporter.cross_session_report()
    ok(f"Cross-session report entity: {cross_report.get('entity', cross_report.get('error', 'N/A'))}")

    show_json("RBI FREE-AI summary (excerpt)", {
        "entity": rbi_report["entity"],
        "governance_status": rbi_report["pillar_status"]["governance"]["status"],
        "assurance_status": rbi_report["pillar_status"]["assurance"]["status"],
        "session_override_rate": rbi_report["pillar_status"]["protection"]["session_override_rate"],
        "chain_verified": rbi_report["chain_integrity_verified"],
    })


# ──────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────

def main():
    if HAS_RICH:
        console.print(Panel.fit(
            "[bold white]AgentLens[/bold white] [dim]v0.2.0[/dim]  •  [cyan]Phase 0 Demo[/cyan]\n"
            "[dim]Compliance-grade AI audit SDK for Indian regulated entities[/dim]",
            border_style="cyan",
        ))
    else:
        print("=" * 60)
        print("  AgentLens v0.2.0 — Phase 0 Demo")
        print("  Compliance-grade AI audit for Indian regulated entities")
        print("=" * 60)

    with tempfile.TemporaryDirectory() as tmp:
        demo_worm_storage(tmp)
        demo_pii_firewall()
        demo_compliance_db(tmp)
        demo_otel()
        demo_end_to_end(tmp)

    section("Done")
    if HAS_RICH:
        console.print("\n  [bold green]All Phase 0 features working correctly.[/bold green]")
        console.print("  [dim]Next: pip install 'agentlens[otel]' then point to your OTLP endpoint.[/dim]\n")
    else:
        print("\n  All Phase 0 features working correctly.")
        print("  Next: pip install 'agentlens[otel]' then point to your OTLP endpoint.\n")


if __name__ == "__main__":
    main()
