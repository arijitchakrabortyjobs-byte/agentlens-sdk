"""
AgentLens — Fraud & AML Detection Demo
=======================================
Simulates a transaction monitoring agent at a Scheduled Commercial Bank
running AML (Anti-Money Laundering) and fraud screening workflows,
instrumented with AgentLens for full RBI + SEBI compliance.

This demo shows:
  - Multi-tool agent trace (velocity check + sanctions screen + ML score)
  - ESCALATE guardrail on high-risk transaction
  - Human override with immutable audit trail
  - DPDP-compliant PII handling (account numbers hashed)
  - Board-ready compliance report

Run:
    python examples/demo_fraud_detection.py
"""

import sys
import os
import hashlib
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentlens import (
    AuditTracer,
    AgentLensConfig,
    ComplianceReporter,
    PolicyEngine,
    RBIPolicy,
)
from agentlens.config import EntityType, RegulatoryFramework
from agentlens.audit_log import RiskTier
from agentlens.policy import PolicyAction, PolicyRule

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None


def section(title: str):
    if RICH:
        console.rule(f"[bold magenta]{title}[/bold magenta]")
    else:
        print(f"\n{'='*60}\n  {title}\n{'='*60}")


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
# AML-specific policy rules (RBI + PMLA 2002)
# ─────────────────────────────────────────────────────────────────────────────

def aml_policy_rules():
    """
    Transaction monitoring rules under:
      - PMLA 2002 (Prevention of Money Laundering Act)
      - RBI Master Direction on KYC (Jan 2024)
      - RBI FREE-AI Framework (Aug 2025)
    """
    return [
        PolicyRule(
            rule_id="AML_001",
            description="Transaction above ₹10L threshold requires CTR filing (PMLA)",
            regulatory_ref="PMLA_2002_S12 | RBI_KYC_MD_2024 | RBI_FREE_AI_REC_21",
            action_on_fail=PolicyAction.ESCALATE,
            risk_tier_applies=[1],
            version="1.0",
            check_fn=lambda ctx: (
                ctx.get("txn_amount_inr", 0) <= 1_000_000 or
                ctx.get("ctr_flagged", False),
                f"Amount ₹{ctx.get('txn_amount_inr',0):,} — " +
                ("CTR flagged" if ctx.get("ctr_flagged") else "CTR REQUIRED (>₹10L)"),
                {
                    "txn_amount": ctx.get("txn_amount_inr", 0),
                    "ctr_threshold": 1_000_000,
                    "ctr_flagged": ctx.get("ctr_flagged", False),
                }
            ),
        ),
        PolicyRule(
            rule_id="AML_002",
            description="Sanctions screening must be completed before transaction release",
            regulatory_ref="UN_SECURITY_COUNCIL_SANCTIONS | RBI_KYC_MD_2024_PARA_38",
            action_on_fail=PolicyAction.BLOCK,
            risk_tier_applies=[1, 2],
            version="1.0",
            check_fn=lambda ctx: (
                ctx.get("sanctions_check_completed", False),
                "Sanctions screen: " + ("CLEAR" if ctx.get("sanctions_clear") else
                                         "COMPLETED — HIT DETECTED" if ctx.get("sanctions_check_completed") else
                                         "NOT PERFORMED — BLOCK"),
                {
                    "sanctions_check_completed": ctx.get("sanctions_check_completed", False),
                    "sanctions_clear": ctx.get("sanctions_clear", False),
                }
            ),
        ),
        PolicyRule(
            rule_id="AML_003",
            description="High ML risk score (>0.8) requires human review before release",
            regulatory_ref="RBI_FREE_AI_REC_21_ESCALATION | RBI_MRM_2026_HUMAN_OVERSIGHT",
            action_on_fail=PolicyAction.ESCALATE,
            risk_tier_applies=[1],
            version="1.0",
            check_fn=lambda ctx: (
                ctx.get("ml_risk_score", 0) <= 0.8 or
                ctx.get("human_review_requested", False),
                f"ML risk score: {ctx.get('ml_risk_score', 0):.2f} — " +
                ("Human review requested" if ctx.get("human_review_requested") else
                 "ESCALATION REQUIRED (score > 0.8)"),
                {
                    "ml_risk_score": ctx.get("ml_risk_score", 0),
                    "threshold": 0.8,
                    "human_review_requested": ctx.get("human_review_requested", False),
                }
            ),
        ),
        PolicyRule(
            rule_id="AML_004",
            description="PII (account numbers, Aadhaar) must be hashed in audit logs (DPDP)",
            regulatory_ref="DPDP_ACT_2023_S8 | RBI_FREE_AI_PILLAR_5_PROTECTION",
            action_on_fail=PolicyAction.BLOCK,
            risk_tier_applies=[1, 2, 3],
            version="1.0",
            check_fn=lambda ctx: (
                ctx.get("pii_masked", False),
                "PII masking: " + ("COMPLIANT" if ctx.get("pii_masked") else "NON-COMPLIANT"),
                {"pii_masked": ctx.get("pii_masked", False)},
            ),
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Mock AML agent tools
# ─────────────────────────────────────────────────────────────────────────────

class MockAMLAgent:
    """
    Simulates a transaction monitoring agent at a Scheduled Commercial Bank.
    In production: plug in your LangChain / CrewAI / AutoGen agent.
    """
    name = "aml_transaction_monitor_v3"
    version = "3.0.1"
    model = "granite-3.1-8b-instruct"    # Example: IBM Granite, deployable on-premise in India

    def velocity_check(self, account_hash: str, window_hours: int = 24) -> dict:
        """Check transaction velocity for structuring patterns."""
        time.sleep(0.02)
        return {
            "txn_count_24h": 4,
            "total_amount_24h_inr": 380_000,
            "structuring_flag": False,   # No smurfing detected
        }

    def sanctions_screen(self, beneficiary_hash: str) -> dict:
        """Screen against UN, OFAC, and RBI sanctions lists."""
        time.sleep(0.03)
        return {
            "checked_lists": ["UN_SECURITY_COUNCIL", "OFAC_SDN", "RBI_DEBARRED"],
            "hit": False,
            "confidence": 0.99,
        }

    def ml_risk_score(self, features: dict) -> dict:
        """Run ML model to score transaction risk."""
        time.sleep(0.04)
        # Simulate elevated risk due to unusual beneficiary geography
        return {
            "risk_score": 0.87,           # Above 0.8 → escalation required
            "top_features": [
                "unusual_beneficiary_country",
                "night_transaction",
                "new_beneficiary",
            ],
            "model_version": "fraud_gbm_v4.2_jan2026",
        }


# ─────────────────────────────────────────────────────────────────────────────
# DEMO
# ─────────────────────────────────────────────────────────────────────────────

def run_demo():
    if RICH:
        console.print(Panel.fit(
            "[bold white]AgentLens SDK — Fraud & AML Detection Demo[/bold white]\n"
            "[dim]Scheduled Commercial Bank — Transaction Monitoring Agent[/dim]\n"
            "[dim]RBI KYC + PMLA 2002 + FREE-AI Compliance[/dim]",
            border_style="magenta",
        ))
    else:
        print("\n" + "="*60)
        print("  AgentLens SDK — Fraud & AML Detection Demo")
        print("  Scheduled Commercial Bank — Transaction Monitoring")
        print("="*60)

    # ── STEP 1: Configure for an SCB ────────────────────────────────────────
    section("STEP 1 — Configure AgentLens for Scheduled Commercial Bank")

    config = AgentLensConfig(
        entity_name="NationalTrust Bank Ltd.",
        entity_type=EntityType.SCB,
        regulatory_frameworks=[
            RegulatoryFramework.RBI_FREE_AI,
            RegulatoryFramework.RBI_MRM_2026,
            RegulatoryFramework.DPDP_2023,
        ],
        board_policy_ref="AI_AML_POLICY_v2.1_BOARD_JAN2026",
        audit_retention_days=1825,
        pii_masking_enabled=True,
        default_model_risk_tier=1,
    )
    info(f"Entity: {config.entity_name} ({config.entity_type.value})")
    info(f"Board policy: {config.board_policy_ref}")

    # ── STEP 2: AML policy rules ─────────────────────────────────────────────
    section("STEP 2 — Load AML Policy Rules (PMLA + RBI KYC)")

    engine = PolicyEngine()
    rules = aml_policy_rules()
    engine.add_rules(rules)

    if RICH:
        t = Table(title="AML Policy Rules", show_lines=True)
        t.add_column("Rule", style="cyan")
        t.add_column("Description")
        t.add_column("Fail Action", style="yellow")
        for r in rules:
            t.add_row(r.rule_id, r.description[:55], r.action_on_fail.value.upper())
        console.print(t)
    else:
        for r in rules:
            print(f"  [{r.rule_id}] {r.description[:55]} → {r.action_on_fail.value.upper()}")

    # ── STEP 3: Run AML agent ────────────────────────────────────────────────
    section("STEP 3 — Process High-Risk Transaction")

    tracer = AuditTracer(config=config, policy_engine=engine)
    agent = MockAMLAgent()

    TXN_AMOUNT_INR = 750_000
    ACCOUNT_ID = "ACC-8812-4490-2231"
    BENEFICIARY_ID = "BENE-UAE-9942"

    account_hash = hashlib.sha256(ACCOUNT_ID.encode()).hexdigest()[:16]
    bene_hash = hashlib.sha256(BENEFICIARY_ID.encode()).hexdigest()[:16]

    info(f"Transaction: ₹{TXN_AMOUNT_INR:,} international wire")
    info(f"Account (hashed): {account_hash}...")
    info(f"Beneficiary (hashed): {bene_hash}...")

    with tracer.trace_agent(agent.name) as span:
        span.set_model(agent.model, "2026-Q1")
        span.set_risk_tier(RiskTier.HIGH)
        span.set_agent_version(agent.version)
        span.set_policy("AML_POLICY_v2.1_JAN2026")

        # Tool 1: Velocity check
        t0 = time.time()
        velocity = agent.velocity_check(account_hash)
        span.record_tool_call(
            tool_name="velocity_check",
            params={"account_hash": account_hash, "window_hours": 24},
            result=velocity,
            latency_ms=int((time.time() - t0) * 1000),
        )
        info(f"Velocity: {velocity['txn_count_24h']} txns in 24h, "
             f"₹{velocity['total_amount_24h_inr']:,} total. "
             f"Structuring: {'⚠ YES' if velocity['structuring_flag'] else '✓ No'}")

        # Tool 2: Sanctions screening
        t0 = time.time()
        sanctions = agent.sanctions_screen(bene_hash)
        span.record_tool_call(
            tool_name="sanctions_screen",
            params={"beneficiary_hash": bene_hash, "lists": sanctions["checked_lists"]},
            result={"hit": sanctions["hit"], "confidence": sanctions["confidence"]},
            latency_ms=int((time.time() - t0) * 1000),
        )
        info(f"Sanctions: {'⚠ HIT DETECTED' if sanctions['hit'] else '✓ Clear'} "
             f"(lists: {', '.join(sanctions['checked_lists'])})")

        # Tool 3: ML risk score
        t0 = time.time()
        ml_result = agent.ml_risk_score({
            "amount": TXN_AMOUNT_INR,
            "is_international": True,
            "hour_of_day": 23,
        })
        span.record_tool_call(
            tool_name="ml_risk_scorer",
            params={"amount_band": "500k-1M", "is_international": True, "hour_of_day": 23},
            result={"risk_score": ml_result["risk_score"], "model": ml_result["model_version"]},
            latency_ms=int((time.time() - t0) * 1000),
        )
        risk_score = ml_result["risk_score"]
        info(f"ML risk score: {risk_score:.2f} — "
             f"{'⚠ HIGH RISK (>0.8)' if risk_score > 0.8 else '✓ Acceptable'}")
        info(f"Top risk features: {', '.join(ml_result['top_features'])}")

        # Decision: HOLD (escalate for human review — ML score > 0.8)
        decision_output = "HOLD — Transaction escalated for human review"
        reasoning = (
            f"Transaction HELD pending human review. Amount ₹{TXN_AMOUNT_INR:,} (under CTR threshold). "
            f"Sanctions screen: CLEAR. ML risk score: {risk_score:.2f} > 0.80 threshold — "
            f"elevated by unusual_beneficiary_country + night_transaction. "
            f"Policy: AML_POLICY_v2.1 §6.3 — ESCALATE on ML score >0.80. "
            f"Human reviewer required before release."
        )

        span.record_decision(
            output=decision_output,
            reasoning=reasoning,
            context={
                "txn_amount_inr": TXN_AMOUNT_INR,
                "ctr_flagged": TXN_AMOUNT_INR > 1_000_000,
                "sanctions_check_completed": True,
                "sanctions_clear": not sanctions["hit"],
                "ml_risk_score": risk_score,
                "human_review_requested": True,   # Explicitly requested due to high ML score
                "pii_masked": True,
            },
            human_review_required=True,
        )

        warn(f"Decision: {decision_output}")
        info(f"Reasoning: {reasoning[:80]}...")

        # ── Human override ───────────────────────────────────────────────────
        section("STEP 4 — Human Reviewer Override (RBI FREE-AI Rec 21)")

        info("Compliance officer reviews transaction context and approves release...")
        span.record_human_override(
            reviewer_id="COMP_OFFICER_PRIYA_SHARMA_EMP001",
            reason=(
                "Reviewed beneficiary details and transaction purpose. "
                "Customer is exporting software services; beneficiary is known IT company in UAE. "
                "ML model lacks FIRA/LUT context. Approving with enhanced monitoring for 30 days."
            ),
            original_decision="HOLD — Transaction escalated for human review",
            new_decision="APPROVED with enhanced monitoring",
        )
        info("Override recorded. Reviewer ID hashed (DPDP compliant). Immutably logged.")

    # ── STEP 5: Audit trail ──────────────────────────────────────────────────
    section("STEP 5 — Audit Trail Verification")

    audit_log = tracer.get_log()
    summary = audit_log.summary()

    if RICH:
        t = Table(title="AML Agent Audit Events", show_lines=True)
        t.add_column("#", style="dim", width=4)
        t.add_column("Event", style="cyan")
        t.add_column("Detail")
        t.add_column("Hash", style="dim", width=16)
        for i, e in enumerate(audit_log.get_events(), 1):
            detail = e.tool_name or (e.decision_output[:45] if e.decision_output else "") or ""
            t.add_row(str(i), e.event_type.value, detail[:45], e.event_hash[:14] + "...")
        console.print(t)
    else:
        for i, e in enumerate(audit_log.get_events(), 1):
            detail = e.tool_name or (e.decision_output[:30] if e.decision_output else "")
            print(f"  [{i}] {e.event_type.value:30s} | {str(detail)[:30]:30s} | {e.event_hash[:12]}...")

    info(f"Chain integrity: {'✅ VERIFIED' if summary['chain_intact'] else '⚠ BROKEN'}")
    info(f"Total events: {summary['total_events']} | Human overrides: {summary['human_overrides']}")

    # ── STEP 6: Compliance report ────────────────────────────────────────────
    section("STEP 6 — Board-Ready Compliance Report")

    reporter = ComplianceReporter(audit_log, config)
    print(reporter.executive_dashboard())

    if RICH:
        console.print(Panel.fit(
            "[bold green]AML Demo complete.[/bold green]\n\n"
            "AgentLens captured:\n"
            "  ✅ 3 tool calls (velocity + sanctions + ML score)\n"
            "  ✅ ESCALATE guardrail triggered (ML score 0.87 > 0.80)\n"
            "  ✅ Human override — reviewer ID hashed (DPDP)\n"
            "  ✅ Tamper-evident audit chain verified\n"
            "  ✅ Board-ready RBI FREE-AI compliance report\n\n"
            "[dim]Works identically with LangChain, CrewAI, AutoGen, or raw Python.[/dim]",
            border_style="green",
        ))
    else:
        print("\n" + "="*60)
        print("  AML Demo complete.")
        print("  AgentLens captured the full transaction monitoring workflow")
        print("  with PMLA + RBI FREE-AI compliance audit trail.")
        print("="*60)


if __name__ == "__main__":
    run_demo()
