# AgentLens: Global AI Governance Coverage Map

**Research date:** July 2026  
**Source:** *Global Agentic AI Governance Status Report — July 10, 2026*  
**Scope:** 10 regulatory frameworks across 8 jurisdictions assessed against the AgentLens v0.1.0 SDK

---

## Why This Matters

No country has passed a law written *specifically* for agentic AI yet. AgentLens is being built ahead of the regulatory curve — but the curve is moving fast. This document maps where the current codebase already satisfies emerging global standards, and where the three universal gaps are.

---

## Frameworks Assessed

| Framework | Jurisdiction | Status (Jul 2026) | Type |
|---|---|---|---|
| RBI FREE-AI Framework (Aug 2025) | India | Official, 26 recommendations | Binding guidance |
| RBI Model Risk Management (Jun 2026) | India | Draft circular, adoption imminent | Binding |
| SEBI AI/ML Guidelines (Jun 2025) | India | Official consultation paper | Binding for covered entities |
| DPDP Act 2023 | India | Enacted, Rules pending | Binding law |
| Singapore IMDA MGF v1.5 (Jan 2026) | Singapore | Official guidance | Voluntary but expected |
| US SR 26-2 (Fed/OCC/FDIC) | United States | Finalised | Binding (excludes agentic AI explicitly) |
| EU AI Act (Annex III/IV) | European Union | In force; high-risk deadline Dec 2027 | Binding law |
| China CAC / NDRC / MIIT (May 2026) | China | Enacted | Binding law |
| UAE DIFC Regulation 10 | UAE | Binding | Binding law |
| UK ICO / CMA / DRCF | United Kingdom | Non-binding guidance | Voluntary |

> **Note on US SR 26-2:** This framework explicitly excludes agentic AI from scope. Traditional ML models remain in scope. Coverage against SR 26-2 is included for completeness but is not a current compliance requirement for agentic deployments.

---

## Capability Dimensions

Eight dimensions were assessed. Each is mapped to at least one major regulatory requirement.

| # | Dimension | Key Regulatory Anchors |
|---|---|---|
| A | **Audit Trail** | RBI MRM mandatory logging; SEBI ms-precision; DPDP 5-yr retention |
| B | **Model Registry** | RBI MRM model inventory; SEBI algo registration; EU AI Act Annex IV |
| C | **Data & PII** | DPDP Act S8 minimisation; EU GDPR Article 25; PIPL (China) |
| D | **AI Transparency** | RBI FREE-AI Rec 18/22; Singapore MGF Dim 1; EU AI Act Art 13 |
| E | **Bias & Oversight** | RBI FREE-AI Rec 18; Singapore MGF Dim 2; EU AI Act Art 10 |
| F | **Agent Identity** | NIST CAISI; Singapore MGF Dim 3; UAE DIFC Reg 10 |
| G | **Action Scope** | China CAC 3-tier; Singapore MGF tool-use log; NIST CAISI |
| H | **Accountability Chain** | US SR 26-2 effective challenge; UK ICO controller/processor; Singapore MGF Dim 2 |

---

## Coverage Matrix

**Legend:** ✅ Covered · ◐ Partial · ○ Gap · — N/A or out of scope

| Dimension | RBI FREE-AI | RBI MRM | SEBI | DPDP | Singapore MGF | US SR 26-2 | EU AI Act | China CAC | UAE DIFC | UK ICO |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| A · Audit Trail | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ | ◐ |
| B · Model Registry | ✅ | ✅ | ✅ | ✅ | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ |
| C · Data & PII | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ | ✅ |
| D · AI Transparency | ✅ | ✅ | ◐ | ◐ | ✅ | ◐ | ✅ | ◐ | ✅ | ✅ |
| E · Bias & Oversight | ✅ | ✅ | ✅ | ◐ | ✅ | ✅ | ✅ | ◐ | ◐ | ◐ |
| F · Agent Identity | ◐ | ◐ | ○ | ○ | ○ | — | ○ | ◐ | ◐ | ○ |
| G · Action Scope | ○ | ○ | ◐ | ○ | ○ | — | ○ | ○ | ○ | ○ |
| H · Accountability Chain | ○ | ○ | ○ | ○ | ○ | ◐ | ○ | ○ | ◐ | ◐ |

---

## Coverage Scores

Scores computed as: `Σ(coverage mark) / 8`, where ✅ = 1.0, ◐ = 0.5, ○ = 0.0.

| Framework | Raw Score | Weighted Score* |
|---|---|---|
| RBI FREE-AI | 69% | 72% |
| RBI MRM 2026 | 69% | 72% |
| SEBI AIML 2025 | 63% | 66% |
| DPDP Act 2023 | 50% | 57% |
| Singapore IMDA MGF v1.5 | 50% | 48% |
| UAE DIFC Regulation 10 | 56% | 55% |
| EU AI Act | 50% | 52% |
| UK ICO / CMA / DRCF | 44% | 40% |
| China CAC May 2026 | 31% | 29% |
| US SR 26-2 *(out of scope)* | 44% | — |

*Weighted score uses ISO 31000 `likelihood × severity` formula — see [Weighting Methodology](#weighting-methodology) below.

---

## What Is Already Built

The following capabilities are implemented in AgentLens v0.1.0 and drive the coverage scores above:

**Audit & Integrity**
- SHA-256 tamper-evident chained audit log (`AuditLog._compute_hash()`, `verify_integrity()`)
- Millisecond-precision timestamps on every conversation turn (`request_timestamp_utc_ms`, `response_timestamp_utc_ms`)
- Append-only event store with NDJSON export for SIEM ingestion
- Content stored as SHA-256 hashes — never raw text (DPDP data minimisation)

**Model Governance**
- `ModelCard` dataclass: model ID, version, provider, risk tier, intended use, inventory ID, last validation date, kill switch status, vendor audit rights, deployment environment
- `AgentLensConfig`: AI officer name/email, board policy reference, model inventory reference, 5-year retention setting
- `RiskTier` enum: HIGH (Tier 1) / MEDIUM (Tier 2) / LOW (Tier 3) — maps to RBI MRM 2026

**Data & PII**
- `detect_pii()`: HIGH-risk identifiers (PAN, Aadhaar, account numbers, personal mobile numbers)
- `detect_pii_in_user_input()`: Extended detection including email addresses for user messages
- Institutional contact suppressors: grievance emails (`@grievance.`, `@support.`, etc.) and toll-free prefixes (`1800-`, `1860-`) excluded from PII flags
- CHAT_005 (BLOCK if PII masking disabled), CHAT_009 (BLOCK if agent requests PII from user), CHAT_010 (WARN if PII detected in user input)

**AI Transparency & Explainability**
- Analytics-first architecture: `analyse_turn()` runs on actual response text *before* the guardrail evaluates — rules fire on real evidence, not caller assertions
- `check_consumer_protection()`: detects AI disclosure, human escalation mention, grievance channel mention in agent output
- `why_trail` in `PolicyEngine`: per-rule structured evidence independent of LLM chain-of-thought
- `human_readable_reasoning` field on every audit event — set by the calling system, not the LLM

**Bias & Human Oversight**
- `check_bias_indicators()`: automation bias risk (definitive claim without human caveat), demographic assumption, income stereotyping
- CHAT_007 (WARN if financial figures have no human review disclaimer)
- CHAT_008 (WARN if loan/EMI topic response does not mention human escalation)
- `record_human_override()` in `AgentSpan`: logs reviewer SHA-256 hash, reason, and original vs. new decision — immutably chained
- CHAT_006 (WARN if human escalation path not configured for Tier 1 sessions)

**Guardrail Policy Engine**
- 10 runtime rules (CHAT_001 through CHAT_010) covering consent, AI disclosure, explainability, data minimisation, human oversight
- `PolicyAction`: ALLOW / WARN / ESCALATE / BLOCK — severity encoded in the architecture, not just in scores
- `BLOCK` rules are mandatory blockers regardless of overall score (implied weight = ∞)

---

## Addendum — Expanded Indian Rule Sets (v0.2.x)

The agent-decision policy layer (`agentlens/policy.py`) has been extended to cover
the Indian AI-governance stack end-to-end, complementing the conversational checks
in `chat_policy.py`:

- **RBI FREE-AI / MRM** — added `RBIPolicy.fraud_aml_rules()` (STR never auto-closed;
  versioned AML policy), `RBIPolicy.model_governance_rules()` (model inventory,
  ≤365-day validation window, Tier-1 kill switch), and
  `RBIPolicy.data_localization_rules()` (India-region residency, Apr 2018 directive).
- **DPDP Act 2023** — new `DPDPPolicy.data_processing_rules()` enforcing consent (S6),
  purpose limitation (S5/S6), data minimisation (S8), right to erasure (S8(7)/S12),
  children's data (S9), grievance/DPO channel (S13), and breach-notification
  readiness (S8(6)).
- **IRDAI (insurance)** — new `IRDAIPolicy.claims_underwriting_rules()`: human sign-off
  on claim denials, no demographic proxy variables in underwriting, fraud-flag
  escalation, and AI-use disclosure to policyholders.
- **DISHA / ABDM (health)** — new `DISHAPolicy.clinical_rules()`: patient consent,
  identifier tokenization, physician sign-off on AI clinical recommendations,
  a hard block on AI-generated prescriptions, and AI-use disclosure to patients.

`config.py` adds the `RBI_DATA_LOCALIZATION`, `DISHA_HEALTH`, and `MEITY_INDIAAI`
frameworks plus `is_irdai_regulated()` / `is_health_regulated()` entity helpers.
The three universal gaps below (Agent Identity, Action Scope, Accountability Chain)
remain the next build phase.

---

## The Three Universal Gaps

These gaps appear as ○ across nearly every framework. They represent the next required build phase.

### Gap 1 — Agent Identity (Dimension F)

**What is missing:** Every agent run gets a plain string `agent_id` and a random UUID `session_id`. There is no cryptographic fingerprint, no capability manifest (what tools can this agent call?), no authorization scope, and no central agent catalogue.

**Why frameworks require it:**
- Singapore MGF Dimension 3: each deployed agent must have a verifiable identity with declared tool access
- UAE DIFC Regulation 10: Autonomous Systems Officer must maintain a registry of active agents with identity proofs
- NIST CAISI (in progress): OAuth 2.0 / Zero Trust for AI agent authentication

**What needs to be built:**
```python
@dataclass
class AgentIdentity:
    agent_fingerprint: str      # SHA-256(agent_id + version + capability_hash)
    capability_manifest: List[str]   # Declared tools this agent may call
    authorization_scope: str    # e.g. "read_only" | "write" | "financial_decision"
    registered_at: str          # ISO timestamp of registration
    catalogue_ref: str          # Internal agent catalogue entry
```

---

### Gap 2 — Action Scope Classification (Dimension G)

**What is missing:** `AgentSpan.record_tool_call()` logs tool name and hashed params — but does not classify the action by type, reversibility, or decision authority required.

`ChatSessionTracer` has no tool call logging at all.

**Why frameworks require it:**
- China CAC May 2026: Three-tier decision authority — must-human (irreversible, high-value), delegable (reversible, bounded), autonomous (low-risk, reversible)
- Singapore MGF: every tool use must be logged with action type and outcome
- NIST CAISI: action scope must be declared in the capability manifest and enforced at runtime

**What needs to be built:**
```python
@dataclass
class ActionRecord:
    tool_name: str
    action_type: str            # "read" | "write" | "execute" | "communicate"
    reversible: bool
    decision_tier: str          # "must_human" | "delegable" | "autonomous"
    authorized_by: str          # "system" | "human:{reviewer_id_hash}"
    params_hash: str
    result_hash: str
```

---

### Gap 3 — Accountability Chain (Dimension H)

**What is missing:** No cross-session override rate tracking, no developer→platform→deployer→user responsibility chain, and no value chain mapping.

`AuditLog.summary()` counts `human_overrides` within a single session but does not compute an override rate or flag rubber-stamping patterns.

**Why frameworks require it:**
- US SR 26-2: "effective challenge" requires evidence that human reviewers are genuinely engaging with AI recommendations — override rate is a proxy metric
- UK ICO: controller/processor distinction must be documented across the full AI supply chain
- Singapore MGF Dimension 2: human accountability must be tracked at both individual and organisational level

**What needs to be built:**
- Cross-session `human_override_rate` metric (overrides ÷ total decisions)
- `ResponsibilityMap`: developer, platform, deployer, end-user — each with role and contractual reference
- Rubber-stamp detection: flag sessions where human reviewers never override (`override_rate == 0.0` across N sessions)

---

## Weighting Methodology

Equal-weight scoring (each dimension = 12.5%) understates which gaps are load-bearing. The ISO 31000 `likelihood × severity` formula gives a more defensible weighting:

| Dimension | Likelihood (1–5) | Severity (1–5) | Weight | Rationale |
|---|:---:|:---:|:---:|---|
| C · Data & PII | 4 | 5 | **20** | DPDP violation = ₹250 Cr fine; binding today |
| D · AI Transparency | 4 | 4 | **16** | RBI FREE-AI Rec 22 consumer protection; binding |
| A · Audit Trail | 2 | 5 | **10** | Tamper = criminal liability; chain is the evidence |
| E · Bias & Oversight | 3 | 4 | **12** | RBI examination finding risk; fair lending liability |
| B · Model Registry | 2 | 3 | **6** | RBI MRM scrutiny; internal inventory |
| H · Accountability Chain | 2 | 3 | **6** | Governance gap; no penalty today but fast-moving |
| F · Agent Identity | 1 | 2 | **2** | No binding law yet; forward-looking |
| G · Action Scope | 1 | 2 | **2** | No binding law yet; forward-looking |

Under this scheme, India's composite score rises (RBI/DPDP are binding and well-covered), while Agent Identity and Action Scope gaps are correctly ranked as lower urgency *today* — but are flagged as high-priority builds for 2027 when China CAC and Singapore MGF requirements mature.

AgentLens also encodes weights implicitly in its guardrail architecture:
- **BLOCK rule fails** → system stops regardless of any score (implied weight = ∞)
- **WARN rule fails** → compliance flag raised, score deducted
- This means Data & PII (CHAT_005, CHAT_009 are BLOCK rules) is already enforced with infinite weight at runtime

---

## Key Findings

1. **No binding agentic AI law exists yet.** Every framework covering agentic AI specifically is either guidance (Singapore MGF, UK ICO), in-progress (NIST CAISI), or has deferred its high-risk provisions (EU AI Act, Dec 2027). AgentLens is ahead of the regulatory curve.

2. **India is the tightest jurisdiction.** RBI FREE-AI, RBI MRM 2026, SEBI, and DPDP collectively constitute the most detailed binding obligations for AI agents in financial services globally. AgentLens was built for this stack.

3. **The three gaps are universal.** Agent Identity, Action Scope Classification, and Accountability Chain appear as gaps across every framework. These are not India-specific — they are what the next wave of regulation will require globally.

4. **US SR 26-2 explicitly excludes agentic AI.** The US banking regulators (Fed/OCC/FDIC) drew a line: SR 26-2 covers traditional ML models only. Agentic AI is out of scope. This is the most significant policy gap in global AI governance today.

5. **China CAC (May 2026) is the most prescriptive for multi-agent systems.** The three-tier decision authority (must-human / delegable / autonomous) and requirement for every action to be classified by reversibility is the most operationally specific requirement across all frameworks assessed.

---

## Build Priority Roadmap

Based on the coverage gaps and weighting analysis:

| Priority | Gap | Framework driver | Target version |
|---|---|---|---|
| P1 | Action Scope Classification for `AgentSpan` | SEBI (BLOCK threshold), China CAC | v0.3.0 |
| P1 | Tool call logging in `ChatSessionTracer` | Singapore MGF Dim 3, NIST CAISI | v0.3.0 |
| P2 | Agent Identity fingerprint + capability manifest | Singapore MGF, UAE DIFC, NIST CAISI | v0.4.0 |
| P2 | Cross-session override rate tracking | US SR 26-2, UK ICO | v0.4.0 |
| P3 | Responsibility chain / value chain mapping | UK ICO, Singapore MGF Dim 2 | v0.5.0 |
| P3 | China PIPL PII pattern support (ID, WeChat, etc.) | China CAC / PIPL | v0.5.0 |
| P4 | Training data lineage documentation (EU AI Act Annex IV) | EU AI Act (deadline Dec 2027) | v1.0.0 |

---

## References

- RBI FREE-AI Framework: [rbidocs.rbi.org.in](https://rbidocs.rbi.org.in) (August 2025)
- RBI Draft Model Risk Management Guidance (June 2026)
- SEBI Consultation Paper on Responsible AI/ML in Securities Markets (June 2025)
- Digital Personal Data Protection Act 2023, Government of India
- Singapore IMDA Model AI Governance Framework v1.5 (January 2026)
- Federal Reserve / OCC / FDIC SR Letter 26-2 (2026)
- EU Artificial Intelligence Act, Regulation (EU) 2024/1689
- China CAC / NDRC / MIIT Interim Measures on Agentic AI (May 2026)
- UAE DIFC Digital Assets Regulation 10 — Autonomous Systems provisions
- NIST AI 100-1 and CAISI (in progress, 2026)
- UK ICO / CMA / DRCF Joint Statement on AI Accountability (2026)
- Goodfire AI + Harvard University (2025): *LLM chain-of-thought is partially performative on recall-heavy tasks* — [arxiv.org/abs/2501.08156](https://arxiv.org/abs/2501.08156)
