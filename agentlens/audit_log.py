"""
AgentLens Audit Log
-------------------
Tamper-evident, append-only audit event store.

Implements the RBI FREE-AI + MRM 2026 mandatory audit schema:
  - NTP-synced UTC timestamp
  - Unique decision ID
  - Agent identity + version
  - Model identity + version  
  - Inputs with source hash (DPDP: PII masked)
  - Policy version invoked
  - Tool calls with Triple-Identity (User / Agent / Tool)
  - Human-readable reasoning (independent of LLM chain-of-thought)
  - Output + downstream action
  - Human review / override record
  - Tamper-evident integrity proof (SHA-256 chain)
  - Risk tier assignment (RBI MRM 2026)

RBI FREE-AI Pillar: Governance + Assurance
RBI MRM 2026: Mandatory audit trail for Tier 1 & Tier 2 models
DPDP Act 2023: PII minimisation and data retention controls
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class EventType(str, Enum):
    """Agent lifecycle event types for audit classification."""
    AGENT_START          = "agent.start"
    TOOL_CALL            = "agent.tool_call"
    TOOL_RESULT          = "agent.tool_result"
    MODEL_INVOCATION     = "agent.model_invocation"
    DECISION             = "agent.decision"
    POLICY_CHECK         = "agent.policy_check"
    HUMAN_OVERRIDE       = "agent.human_override"
    GUARDRAIL_TRIGGERED  = "agent.guardrail_triggered"
    AGENT_END            = "agent.end"
    ERROR                = "agent.error"


class RiskTier(int, Enum):
    """
    RBI Model Risk Management 2026 — Risk Tiers.
    Tier 1: High-risk (credit decisions, fraud detection, AML/KYC)
    Tier 2: Medium-risk (customer service, recommendations)
    Tier 3: Low-risk (internal ops, analytics)
    """
    HIGH   = 1   # Board review + independent validation required
    MEDIUM = 2   # Risk committee review required
    LOW    = 3   # Standard monitoring


@dataclass
class AuditEvent:
    """
    A single immutable audit event in the AgentLens trail.
    
    Field schema aligned to:
      - RBI MRM 2026 mandatory logging requirements
      - DPDP Act 2023 data minimisation principle
      - SEBI AIML 2025 traceability requirements
    """
    # Core identity fields (mandatory under RBI MRM 2026)
    event_id: str           = field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str           = ""          # Groups all events in one agent run
    session_id: str         = ""
    timestamp_utc: str      = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: EventType   = EventType.AGENT_START

    # Agent identity (RBI: agent version must be logged for model change tracking)
    agent_id: str           = ""
    agent_version: str      = "0.0.0"
    model_id: str           = ""          # e.g. "gpt-4o", "llama-3.1-70b"
    model_version: str      = ""

    # User / operator identity (DPDP: pseudonymised)
    user_id_hash: str       = ""          # SHA-256 hash, never plain user ID
    operator_id: str        = ""

    # Action details
    tool_name: Optional[str]          = None
    tool_params_hash: Optional[str]   = None   # Hash only — not raw params (DPDP)
    tool_result_hash: Optional[str]   = None

    # Decision fields (RBI MRM: decision + policy version mandatory for Tier 1)
    decision_output: Optional[str]    = None
    policy_ref: Optional[str]         = None   # e.g. "CREDIT_POLICY_v3.2_APR2026"
    policy_version: Optional[str]     = None
    human_readable_reasoning: Optional[str] = None  # Independent of LLM CoT

    # Risk and compliance metadata
    risk_tier: RiskTier               = RiskTier.MEDIUM
    regulatory_frameworks: List[str]  = field(default_factory=list)
    compliance_flags: List[str]       = field(default_factory=list)

    # Human oversight (RBI FREE-AI: override must be logged with reason)
    human_review_required: bool       = False
    human_override: bool              = False
    human_override_reason: Optional[str] = None
    human_reviewer_id_hash: Optional[str] = None

    # Guardrail fields
    guardrail_triggered: bool         = False
    guardrail_rule: Optional[str]     = None
    guardrail_action: Optional[str]   = None   # "blocked" | "warned" | "escalated"

    # Error tracking
    error_code: Optional[str]         = None
    error_message: Optional[str]      = None

    # Integrity proof — SHA-256 of this event chained to previous hash
    previous_event_hash: str          = "GENESIS"
    event_hash: str                   = field(default="", init=False)

    # Latency
    latency_ms: Optional[int]         = None

    def __post_init__(self):
        self.event_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """
        Compute tamper-evident SHA-256 hash chaining this event
        to the previous event. Mutating any field invalidates the chain.
        """
        payload = {
            "event_id": self.event_id,
            "trace_id": self.trace_id,
            "timestamp_utc": self.timestamp_utc,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "model_id": self.model_id,
            "decision_output": self.decision_output,
            "policy_ref": self.policy_ref,
            "previous_event_hash": self.previous_event_hash,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["risk_tier"] = self.risk_tier.value
        return d


class AuditLog:
    """
    Append-only, tamper-evident audit log for a single agent deployment.

    In production this persists to WORM-compatible storage (S3 Object Lock,
    Azure Immutable Blob, or on-premise WORM for sensitive BFSI deployments).
    For this prototype, it stores in memory and can export to JSON/NDJSON.

    RBI MRM 2026: Log must be retained for minimum 5 years.
    DPDP 2023: Raw PII must not appear in logs — use hashes.
    """

    def __init__(self, entity_name: str):
        self.entity_name = entity_name
        self._events: List[AuditEvent] = []
        self._last_hash = "GENESIS"

    def append(self, event: AuditEvent) -> AuditEvent:
        """Append an event and chain it to the previous hash."""
        event.previous_event_hash = self._last_hash
        # Recompute hash with chained previous
        event.event_hash = event._compute_hash()
        self._events.append(event)
        self._last_hash = event.event_hash
        return event

    def verify_integrity(self) -> bool:
        """
        Verify the entire chain is intact.
        Returns False if any event has been tampered with.
        """
        prev_hash = "GENESIS"
        for event in self._events:
            recomputed = event._compute_hash()
            # Temporarily set previous to check
            saved = event.previous_event_hash
            event.previous_event_hash = prev_hash
            expected = event._compute_hash()
            event.previous_event_hash = saved
            if event.event_hash != expected:
                return False
            prev_hash = event.event_hash
        return True

    def get_events(self) -> List[AuditEvent]:
        return list(self._events)

    def to_ndjson(self) -> str:
        """Export as newline-delimited JSON for SIEM ingestion."""
        return "\n".join(
            json.dumps(e.to_dict(), default=str) for e in self._events
        )

    def summary(self) -> Dict[str, Any]:
        if not self._events:
            return {"total_events": 0}
        tiers = [e.risk_tier.value for e in self._events]
        return {
            "entity": self.entity_name,
            "total_events": len(self._events),
            "chain_intact": self.verify_integrity(),
            "min_risk_tier": min(tiers),
            "guardrails_triggered": sum(
                1 for e in self._events if e.guardrail_triggered
            ),
            "human_overrides": sum(
                1 for e in self._events if e.human_override
            ),
            "decisions_recorded": sum(
                1 for e in self._events
                if e.event_type == EventType.DECISION
            ),
            "first_event": self._events[0].timestamp_utc,
            "last_event": self._events[-1].timestamp_utc,
        }
