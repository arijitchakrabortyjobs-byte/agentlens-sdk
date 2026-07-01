# AgentLens SDK

**Compliance-grade audit, observability, and reasoning traceability for AI agents deployed in regulated Indian enterprises.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![RBI FREE-AI](https://img.shields.io/badge/RBI-FREE--AI_Aligned-orange.svg)](https://rbidocs.rbi.org.in)

---

## The Problem

Indian banks, NBFCs, and fintech companies are deploying AI agents for credit decisions, fraud detection, customer service, and AML/KYC workflows. Regulators are asking hard questions:

- **RBI (June 2026):** Board-approved AI policy, model risk tiers, mandatory audit trails, kill switches, human oversight for Tier 1 models
- **RBI FREE-AI (Aug 2025):** 26 recommendations across 6 pillars — governance, assurance, protection, explainability
- **SEBI (June 2025):** Algorithm accountability for AI/ML in securities markets
- **DPDP Act 2023:** No PII in logs; data minimisation; 5-year retention for financial records

**Nobody can answer these questions today.** Existing observability tools (LangSmith, Arize, Galileo) are engineering debuggers — not compliance-grade auditors.

AgentLens is the audit layer.

---

## What AgentLens Does

| Pillar | What it provides | Regulatory mapping |
|---|---|---|
| **Observability** | Full execution trace: every tool call, model invocation, cost, latency, outcome | RBI FREE-AI Pillar 6 (Assurance) |
| **Security Layer** | Runtime guardrails against goal hijacking, privilege abuse, insecure inter-agent comms | OWASP ASI Top 10 2026 |
| **Reasoning Traceability** | Policy-execution why-trail, independent of LLM chain-of-thought | RBI FREE-AI Rec 18 (Explainability) |
| **Live Auditing** | Real-time compliance scoring against RBI/SEBI/DPDP frameworks | RBI MRM 2026 Tier classification |
| **Audit Reporting** | Board-ready reports, RBI examiner-ready JSON, SIEM export | RBI FREE-AI Pillar 4 (Governance) |

---

## Quickstart

```bash
pip install agentlens  # coming soon — clone and run directly for now
```

```python
from agentlens import AuditTracer, AgentLensConfig, PolicyEngine, RBIPolicy
from agentlens.config import EntityType, RegulatoryFramework
from agentlens.audit_log import RiskTier

# 1. Configure for your entity
config = AgentLensConfig(
    entity_name="MyBank Ltd.",
    entity_type=EntityType.NBFC,
    regulatory_frameworks=[
        RegulatoryFramework.RBI_FREE_AI,
        RegulatoryFramework.RBI_MRM_2026,
        RegulatoryFramework.DPDP_2023,
    ],
    board_policy_ref="AI_GOVERNANCE_POLICY_v1.0_BOARD_APR2026",
    pii_masking_enabled=True,
)

# 2. Load RBI policy rules
engine = PolicyEngine()
engine.add_rules(RBIPolicy.credit_decision_rules())

# 3. Wrap your agent — works with LangChain, CrewAI, AutoGen, or raw Python
tracer = AuditTracer(config=config, policy_engine=engine)

with tracer.trace_agent("credit_decisioning_agent") as span:
    span.set_model("llama-3.1-70b-instruct")
    span.set_risk_tier(RiskTier.HIGH)       # RBI Tier 1 — credit decision
    span.set_policy("CREDIT_POLICY_v3.2_APR2026")

    # Your agent logic here
    result = my_agent.invoke({"input": user_query})

    # Record decision with human-readable reasoning (NOT LLM chain-of-thought)
    span.record_decision(
        output=result["output"],
        reasoning="Approved: CIBIL 724 ≥ 700, DSCR 4.08x ≥ 2.5x, no DPD. Policy: CREDIT_POLICY_v3.2 §4.2",
        context={"decision_amount_inr": 500_000, "pii_masked": True},
    )

# 4. Export board-ready report
from agentlens import ComplianceReporter
reporter = ComplianceReporter(tracer.get_log(), config)
print(reporter.executive_dashboard())

# 5. Export JSON for RBI examiners / SIEM
audit_json = tracer.export_audit_report(format="json")
```

---

## Run the Live Demo

```bash
git clone https://github.com/arijitchakrabortyjobs-byte/agentlens-sdk
cd agentlens-sdk
pip install rich  # optional, for pretty output
python examples/demo_credit_agent.py
```

The demo simulates a full NBFC credit decisioning workflow with:
- CIBIL bureau tool call (params hashed for DPDP compliance)
- Income verification tool call
- Credit decision with policy why-trail
- Tamper-evident audit chain verification
- Board-ready RBI FREE-AI compliance report
- JSON export for RBI examiner submission

---

## Regulatory Coverage

| Framework | Version | Status |
|---|---|---|
| RBI FREE-AI Framework | August 2025 | ✅ Aligned |
| RBI Draft Model Risk Management | June 2026 | ✅ Aligned |
| SEBI AI/ML Guidelines | June 2025 | ✅ Aligned |
| DPDP Act 2023 | 2023 | ✅ PII masking + data minimisation |
| IRDAI AI Governance | 2025 | 🔄 Coming soon |

---

## Architecture

```
Your Agent (LangChain / CrewAI / AutoGen / Raw Python)
        │
        ▼
┌──────────────────────────────────┐
│         AgentLens SDK            │
│                                  │
│  ┌─────────┐  ┌───────────────┐  │
│  │ Tracer  │  │ Policy Engine │  │
│  │ Context │  │ (RBI/SEBI     │  │
│  │ Manager │  │  rules)       │  │
│  └────┬────┘  └──────┬────────┘  │
│       │              │           │
│       ▼              ▼           │
│  ┌──────────────────────────┐    │
│  │   Audit Log              │    │
│  │   (Tamper-evident chain) │    │
│  └──────────────────────────┘    │
│       │                          │
│       ▼                          │
│  ┌──────────────────────────┐    │
│  │   Compliance Reporter    │    │
│  │   RBI / SEBI / DPDP      │    │
│  └──────────────────────────┘    │
└──────────────────────────────────┘
        │
        ▼
  Board Reports │ RBI Examiners │ SIEM │ Big 4 Auditors
```

---

## Why the Why-Trail Matters

LLM chain-of-thought reasoning is partially performative. A [2025 paper from Goodfire AI and Harvard University](https://arxiv.org/abs/2501.08156) showed that on recall-heavy tasks (which dominate enterprise workflows), models commit to their answer in the first few tokens and generate subsequent "reasoning" as post-hoc justification.

AgentLens's why-trail is different. It captures:
- **Which policy rule fired** (e.g. `RBI_CREDIT_001`)
- **Which version of the rule** (e.g. `v1.0`)
- **What evidence triggered it** (e.g. `{"amount_inr": 500000, "threshold": 1000000}`)
- **What action was taken** (ALLOW / WARN / ESCALATE / BLOCK)

This is deterministic, verifiable, and satisfies RBI FREE-AI Rec 18 and Article 14 of the EU AI Act — independently of what the LLM said in its reasoning trace.

---

## Roadmap

- [ ] v0.1.0 — Core SDK (this release)
- [ ] v0.2.0 — OpenTelemetry export (Grafana, Datadog, Azure Monitor)
- [ ] v0.3.0 — LangChain callback integration (zero-config instrumentation)
- [ ] v0.4.0 — CrewAI and AutoGen native adapters
- [ ] v0.5.0 — WORM storage adapter (S3 Object Lock, Azure Immutable Blob)
- [ ] v1.0.0 — Full RBI MRM 2026 compliance package with examiner-ready templates

---

## License

MIT — free to use, modify, and deploy. Enterprise support and SLA-backed deployment available.

---

## Built for India's Regulated AI Stack

AgentLens is built specifically for the Indian regulatory environment:
- **Language:** Python (dominant in Indian enterprise AI stacks)
- **Models:** Works with Sarvam AI, Krutrim, international models — no lock-in
- **Deployment:** On-premise, private cloud, or SaaS — regulated entities can self-host
- **Regulatory:** RBI, SEBI, IRDAI, DPDP — not a port of EU tooling
