# AgentLens Gateway Plan
**Goal:** Become the compliance gateway through which Indian banks, insurers, and hospitals route AI traffic — the layer they cannot go around.

**Research date:** July 2026  
**Codebase verified:** v0.1.0

---

## The Vision

AgentLens becomes the **mandatory compliance proxy** for any Indian regulated entity deploying AI agents. Banks cannot call GPT-4 directly — they call AgentLens, which enforces policy, strips PII, logs the tamper-evident audit chain, and forwards a clean request to whichever model is approved.

```
Today (SDK)           Target (Proxy)
─────────────         ──────────────────────────────────────
import AuditTracer    POST https://gateway.agentlens.in/v1/chat/completions
wrap your agent  →         ↓
                      PII Firewall → Policy Engine → Audit Log → Approved Model
```

---

## Current Code Gaps (Verified Against v0.1.0)

### Gap 1 — No persistence (`audit_log.py:178`)
`self._events: List[AuditEvent] = []` — in-memory only. If the process dies, the audit trail is gone. The 5-year retention claim is false until this is fixed.

### Gap 2 — PII firewall runs post-model (`chat_tracer.py:274`)
`self.llm_adapter(messages=self._messages)` is called before `analyse_turn()` on line 292. The model sees raw PAN, Aadhaar, and account numbers. PII detection exists in the audit layer but not as a pre-model firewall.

### Gap 3 — `ChatSessionTracer` has no tool call logging
No `record_tool_call()` method exists on `ChatSessionTracer`. `AgentSpan` in `tracer.py` has it; the chat tracer — the primary interface for banking chatbots — does not.

### Gap 4 — Agent identity is a plain string (`tracer.py:56`)
`self.agent_id = agent_id` — just a string. No SHA-256 fingerprint, no capability manifest, no authorization scope, no central agent catalogue.

### Gap 5 — Action scope not classified (`tracer.py:101-127`)
`record_tool_call()` logs `tool_name`, `tool_params_hash`, `tool_result_hash`. No `action_type` (read/write/execute), no `reversible` flag, no `decision_tier` (must-human / delegable / autonomous).

### Gap 6 — Override rate is per-session only (`audit_log.py:228`)
`"human_overrides": sum(...)` counts within a single session. No cross-session database, no override rate (overrides ÷ decisions), no rubber-stamp detection.

### Gap 7 — OTEL export is a stub (`config.py:61`)
`otel_export_enabled: bool = False` and `otel_endpoint` exist in the config but there is zero OTEL code anywhere. No spans emitted to Grafana, Datadog, or Azure Monitor.

### Gap 8 — No override rate in any report (`report.py:77`)
`"human_overrides_logged": len(overrides)` — raw count only. No rate, no trend, no rubber-stamp flag across sessions.

### Gap 9 — No proxy, no data residency, no Indian model routing
Nothing intercepts HTTP. Requires explicit `import AuditTracer` — a DNS/endpoint change cannot replace it yet.

### Gap 10 — IRDAI and healthcare are stubs (`config.py`)
`IRDAI_AI = "IRDAI_AI_Governance"` exists in `RegulatoryFramework` enum but there are no `IRDAIPolicy` rules, no DISHA rules, and `EntityType` has no insurer or hospital types.

---

## Phase 0 — Make It Production-Safe
**Timeline: 4 weeks**  
These gaps make the current SDK unshippable to a real bank.

### 0a. Persistence layer
**File to create:** `agentlens/storage.py`

Write `AuditLog` events to disk as NDJSON on every `append()` call. Add a `WORMStorageAdapter` interface with two implementations: local rotating file (dev / on-prem) and S3 Object Lock in `ap-south-1` (AWS Mumbai). Hook into `AuditLog.append()` so persistence is automatic.

```python
class WORMStorageAdapter:
    def write(self, event: AuditEvent) -> None: ...

class LocalNDJSONAdapter(WORMStorageAdapter): ...
class S3ObjectLockAdapter(WORMStorageAdapter): ...   # AWS Mumbai, ap-south-1
class AzureImmutableBlobAdapter(WORMStorageAdapter): ...  # Azure Central India
```

### 0b. Pre-model PII firewall
**File to fix:** `chat_tracer.py`, before line 274

Before calling `self.llm_adapter()`, run `detect_pii_in_user_input()` on `user_message`. If PII is found and masking is enabled: tokenize (`ABCDE1234F` → `[PAN_1]`), store the mapping in a short-lived local vault, call the model with the clean message, restore tokens in the response. No PII crosses the network.

### 0c. Override rate tracking
**Files to fix:** `audit_log.py`, `report.py`

Add a lightweight `ComplianceDatabase` (SQLite or NDJSON) that accumulates `(session_id, entity, decisions, overrides)` tuples across sessions. `summary()` emits `override_rate`. `ComplianceReporter` flags `override_rate == 0.0` across N sessions as a rubber-stamp risk.

### 0d. Wire OTEL export
**File to create:** `agentlens/otel.py`

Implement what `config.py` already declares. Emit `opentelemetry-sdk` spans from `audit_log.append()` when `otel_export_enabled=True`. Banks already have Grafana or Azure Monitor — this makes AgentLens a native citizen of their observability stack.

---

## Phase 1 — True Proxy Layer
**Timeline: 3 months**  
This is the move from Stripe to Cloudflare.

**What to build:** A FastAPI server exposing an OpenAI-compatible endpoint. Every request passes through the PII firewall, policy engine, and audit log before being forwarded to the approved model. Zero application code changes — only a DNS/endpoint change.

```
Application → POST https://gateway.agentlens.in/v1/chat/completions
                     ↓
               PII Firewall        strip PAN/Aadhaar before model sees it
               Policy Engine       BLOCK / ESCALATE / WARN
               Audit Log           SHA-256 chained, written to WORM storage
               Data Residency      allowlist Indian endpoints only
               Model Router        Sarvam / Krutrim / Azure India / AWS Mumbai
                     ↓
               Forward to approved model
```

**Data residency enforcer:**
```python
APPROVED_ENDPOINTS = {
    "azure_india":  ["centralindia.api.cognitive.microsoft.com", "eastindia.*"],
    "aws_mumbai":   ["ap-south-1.*.amazonaws.com"],
    "sarvam":       ["api.sarvam.ai"],
    "krutrim":      ["cloud.olakrutrim.com"],
}
# Any call to api.openai.com, api.anthropic.com → BLOCK + audit record
```

**Why this is the moat:** Once a bank routes traffic through the AgentLens proxy, every audit log, every policy rule, and every board report is tied to it. Switching cost is extremely high.

---

## Phase 2 — Close the Three SDK Gaps
**Timeline: runs alongside Phase 1**

### Agent identity fingerprint
Add to `AuditEvent` and compute in `AgentSpan.__init__()`:
```python
agent_fingerprint: str = ""           # SHA-256(agent_id + version + capability_hash)
capability_manifest: List[str] = []   # declared tools this agent may call
authorization_scope: str = ""         # "read_only" | "write" | "financial_decision"
```
Satisfies: Singapore MGF Dimension 3, UAE DIFC Regulation 10, NIST CAISI.

### Action scope classification
Add to `record_tool_call()` in both `AgentSpan` and `ChatSessionTracer` (which currently has no `record_tool_call()` at all):
```python
action_type: str = "read"         # "read"|"write"|"execute"|"communicate"
reversible: bool = True
decision_tier: str = "autonomous" # "must_human"|"delegable"|"autonomous"
authorized_by: str = "system"     # "system"|"human:{reviewer_id_hash}"
```
Satisfies: China CAC May 2026 three-tier model, Singapore MGF, NIST CAISI.

### Cross-session accountability chain
Using the `ComplianceDatabase` from Phase 0c, add to `ComplianceReporter`:
```python
def accountability_report(self) -> Dict:
    # override_rate: overrides / total decisions across all sessions
    # rubber_stamp_sessions: sessions where override_rate == 0.0
    # responsibility_map: developer → platform → deployer → end-user
```
Satisfies: US SR 26-2 effective challenge, UK ICO controller/processor, Singapore MGF Dimension 2.

---

## Phase 3 — Sector Expansion
**Timeline: 4–6 months**

### IRDAI (Insurance)
Add `IRDAIPolicy` class to `policy.py`:
- Underwriting: human sign-off required for sum assured > ₹50L (BLOCK threshold)
- Claims: AI fraud flag requires human review before rejection (ESCALATE)
- Disclosure: policyholder must be informed AI was used in premium calculation (WARN)
- Demographic: no proxy variables (gender, PIN code, religion) in premium AI (BLOCK)

Add to `config.py`:
```python
class EntityType(str, Enum):
    INSURER_LIFE    = "Life_Insurance_Company"
    INSURER_GENERAL = "General_Insurance_Company"
    DIAGNOSTIC_LAB  = "Diagnostic_Laboratory"
    HOSPITAL_PRIVATE = "Private_Hospital"
    HOSPITAL_GOVT   = "Government_Hospital"
    PFRDA_ENTITY    = "Pension_Fund"
```

### Healthcare (DISHA / ABDM / NMC)
Add `DISHAPolicy` class — implement against the DISHA draft (mark `version="DISHA_DRAFT_2024"`):
- Clinical: AI diagnostic must have doctor override path (ESCALATE)
- Prescription: AI cannot generate prescription — human-reviewed only (BLOCK)
- Disclosure: patient must be informed AI was used in their care pathway (WARN)
- ABHA: every health record accessed via AI must appear in ABHA audit log (BLOCK if missing)

---

## Phase 4 — Regulatory Certification
**Timeline: start now, runs in parallel — processes take 6–12 months**

| Certification | Why needed | How to start |
|---|---|---|
| CERT-In empanelment | PSU banks and government hospitals cannot deploy unapproved security tooling | Apply via cert-in.org.in empanelment portal |
| MeitY MeghRaj empanelment | Required for NIC-hosted government deployments (AIIMS, state health depts) | Apply via meity.gov.in cloud empanelment |
| RBI Innovation Hub (RBIH) cohort | Direct access to pilot banks, early regulatory feedback before rules finalise | Apply for next RegTech cohort at rbihub.in |
| IRDAI InsurTech sandbox | Pilot with live insurers, regulatory cover during testing | Apply via irdai.gov.in regulatory sandbox |

---

## Phase 5 — Distribution
**How regulated entities actually buy this.**

**System integrators first.** TCS, Infosys, Wipro, and Accenture implement banking AI. If AgentLens is on their approved vendor list, it gets deployed inside their engagements without a direct sales motion. Build an SI partnership programme before enterprise sales.

**Big 4 audit firms.** Deloitte, KPMG, EY, and PwC show up when RBI examiners ask for AI audit evidence. If they recommend AgentLens's JSON export format as the standard, demand becomes regulatory-mandated. Target their financial services risk practices.

**Law firms.** Cyril Amarchand Mangaldas, AZB & Partners advise banks on AI governance. If they recommend AgentLens in their governance frameworks, it becomes a standard ask in every board AI policy.

---

## Build Sequence Summary

```
Now             4 weeks          3 months         6 months         12 months
────────────    ──────────────   ─────────────    ──────────────   ──────────
Current SDK  →  Persistence   →  HTTP Proxy    →  IRDAI +       →  Multi-tenant
               PII firewall      PII firewall      Healthcare        SaaS platform
               OTEL export       (pre-model)       policy packs      Dashboard
               Override rate     Data residency    Sector            Regulatory
               cross-session     Indian model      EntityTypes       certifications
                                 routing                             (running since
                                                                     now)
```

---

## Sectors and Their Regulators

| Sector | Regulator | Key AI obligation | AgentLens status |
|---|---|---|---|
| Banks / NBFCs | RBI FREE-AI, RBI MRM 2026 | Board AI policy, Tier 1 audit trail, kill switch | ✅ Covered (v0.1.0) |
| Securities | SEBI AIML 2025 | Pre-trade risk log, dual approval >₹50L | ✅ Covered (v0.1.0) |
| Insurance | IRDAI AI Governance 2025 | Underwriting explainability, claim rejection audit | ❌ Phase 3 |
| Hospitals (private) | NMC, DISHA draft | Doctor override path, AI disclosure to patient | ❌ Phase 3 |
| Hospitals (govt) | NMC, NHA, ABDM | ABHA audit log, CERT-In approved tooling | ❌ Phase 3 + Cert |
| Pension funds | PFRDA | Fund allocation AI audit | ❌ Phase 3 |
| Fintech / PA | RBI PA Guidelines | Payment AI fraud detection audit | ✅ Partial (v0.1.0) |

---

## References

- RBI FREE-AI Framework (August 2025): rbidocs.rbi.org.in
- RBI Draft Model Risk Management Guidance (June 2026)
- SEBI Consultation Paper on Responsible AI/ML (June 2025)
- Digital Personal Data Protection Act 2023
- IRDAI AI Governance Framework (2025)
- DISHA Draft (Digital Information Security in Healthcare Act)
- Singapore IMDA Model AI Governance Framework v1.5 (January 2026)
- China CAC / NDRC / MIIT Interim Measures on Agentic AI (May 2026)
- NIST CAISI (in progress, 2026)
- AgentLens Global AI Governance Coverage Map: [GLOBAL_AI_GOVERNANCE_COVERAGE.md](GLOBAL_AI_GOVERNANCE_COVERAGE.md)
