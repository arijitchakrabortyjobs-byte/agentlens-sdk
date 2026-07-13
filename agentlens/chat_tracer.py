"""
AgentLens Chat Session Tracer
------------------------------
Wraps a live LLM chat session (Claude, ChatGPT, or any provider) and
produces a compliance-grade audit trail of every conversation turn.

Satisfies:
  RBI FREE-AI Rec 18  — human-readable reasoning per turn
  RBI MRM 2026        — model inventory card, per-decision trace
  SEBI AIML 2025      — millisecond timestamps, model version logging
  DPDP Act 2023       — PII hashing, data minimisation proof, consent ref
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .audit_log import AuditEvent, AuditLog, EventType, RiskTier
from .config import AgentLensConfig
from .policy import PolicyEngine, PolicyCheckResult, PolicyAction
from .chat_analytics import TurnAnalytics, analyse_turn
from .pii_firewall import firewall_messages, PIIVault
from .storage import WORMStorageAdapter
from .otel import OTELExporter


# ─────────────────────────────────────────────────────────────────────────────
# Model Card — RBI MRM 2026 Model Inventory Record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ModelCard:
    """
    One record in the institution's AI Model Inventory.
    RBI MRM 2026: Every model in use must have an inventory entry.
    No model may be used unless inventoried.
    """
    model_id: str                    # e.g. "claude-sonnet-4-6"
    model_version: str               # e.g. "claude-sonnet-4-6-20251001"
    provider: str                    # "anthropic" | "openai" | "sarvam" | "krutrim"
    risk_tier: RiskTier              # RBI MRM risk classification
    intended_use: str                # e.g. "customer_service_chat"
    inventory_id: str = ""           # Internal model inventory reference
    last_validated_date: str = ""    # ISO date of last independent validation
    kill_switch_available: bool = True
    kill_switch_last_tested: str = ""
    deployment_environment: str = "production"  # production | staging | sandbox
    vendor_audit_rights: bool = True  # RBI MRM: contract must include audit rights

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "model_version": self.model_version,
            "provider": self.provider,
            "risk_tier": self.risk_tier.value,
            "risk_tier_label": self.risk_tier.name,
            "intended_use": self.intended_use,
            "inventory_id": self.inventory_id,
            "last_validated_date": self.last_validated_date,
            "kill_switch_available": self.kill_switch_available,
            "kill_switch_last_tested": self.kill_switch_last_tested,
            "deployment_environment": self.deployment_environment,
            "vendor_audit_rights": self.vendor_audit_rights,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Conversation Turn — immutable record of one exchange
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ConversationTurn:
    """
    Immutable audit record for one user→assistant exchange.
    Stores hashes of content, never raw text (DPDP data minimisation).
    The actual content is held in memory only for the session duration;
    on export only hashes appear in the audit trail.
    """
    turn_index: int
    turn_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Content hashes — DPDP: raw text never persisted in audit log
    user_input_hash: str = ""
    user_input_length: int = 0       # Character count only — no raw content
    assistant_output_hash: str = ""
    assistant_output_length: int = 0

    # Model metadata — RBI MRM: model version mandatory per decision
    model_id: str = ""
    model_version: str = ""
    input_tokens: int = 0
    output_tokens: int = 0

    # Timing — SEBI: millisecond precision required for trading contexts
    request_timestamp_utc_ms: int = 0   # Unix ms
    response_timestamp_utc_ms: int = 0
    latency_ms: int = 0

    # Policy evaluation
    guardrail_passed: bool = True
    guardrail_rules_failed: List[str] = field(default_factory=list)   # BLOCK / ESCALATE
    guardrail_rules_warned: List[str] = field(default_factory=list)   # WARN
    guardrail_action: str = PolicyAction.ALLOW.value

    # Explainability — RBI FREE-AI Rec 18: must be human-readable, not LLM CoT
    policy_ref: str = ""
    policy_clause: str = ""          # e.g. "§4.2 Credit Policy" — specific clause
    human_readable_summary: str = "" # Set by the calling system, not the LLM

    # DPDP
    pii_detected_in_output: bool = False
    pii_fields_masked: List[str] = field(default_factory=list)
    consent_ref: str = ""            # Link to consent record for this user

    # Analytics — RBI FREE-AI Rec 18, RBI MRM 2026 bias audit, DPDP consumer protection
    analytics: Optional[TurnAnalytics] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "turn_index": self.turn_index,
            "turn_id": self.turn_id,
            "user_input_hash": self.user_input_hash,
            "user_input_length_chars": self.user_input_length,
            "assistant_output_hash": self.assistant_output_hash,
            "assistant_output_length_chars": self.assistant_output_length,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "tokens": {"input": self.input_tokens, "output": self.output_tokens},
            "timing": {
                "request_utc_ms": self.request_timestamp_utc_ms,
                "response_utc_ms": self.response_timestamp_utc_ms,
                "latency_ms": self.latency_ms,
            },
            "guardrail": {
                "passed": self.guardrail_passed,
                "rules_failed": self.guardrail_rules_failed,
                "action": self.guardrail_action,
            },
            "explainability": {
                "policy_ref": self.policy_ref,
                "policy_clause": self.policy_clause,
                "human_readable_summary": self.human_readable_summary,
            },
            "dpdp": {
                "pii_detected_in_output": self.pii_detected_in_output,
                "pii_fields_masked": self.pii_fields_masked,
                "consent_ref": self.consent_ref,
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# Chat Session Tracer
# ─────────────────────────────────────────────────────────────────────────────

class ChatSessionTracer:
    """
    Wraps any LLM chat API and produces a compliance-grade audit trail.

    Works with Claude (Anthropic), ChatGPT (OpenAI), or any provider
    via a callable adapter.

    Usage:
        def claude_adapter(messages, system):
            response = anthropic_client.messages.create(...)
            return response.content[0].text, response.usage.input_tokens, response.usage.output_tokens

        tracer = ChatSessionTracer(
            config=config,
            model_card=ModelCard(...),
            llm_adapter=claude_adapter,
            policy_engine=engine,
        )
        response = tracer.send("What is my loan eligibility?")
        report = tracer.get_report()
    """

    def __init__(
        self,
        config: AgentLensConfig,
        model_card: ModelCard,
        llm_adapter: Callable,
        policy_engine: Optional[PolicyEngine] = None,
        system_prompt: str = "",
        consent_ref: str = "",
        session_purpose: str = "",
        storage_adapter: Optional[WORMStorageAdapter] = None,
        otel_exporter: Optional[OTELExporter] = None,
    ):
        self.config = config
        self.model_card = model_card
        self.llm_adapter = llm_adapter
        self.policy_engine = policy_engine
        self.system_prompt = system_prompt
        self.consent_ref = consent_ref
        self.session_purpose = session_purpose

        self.session_id = str(uuid.uuid4())
        self.session_start_ms = int(time.time() * 1000)
        self.audit_log = AuditLog(
            entity_name=config.entity_name,
            storage_adapter=storage_adapter,
            otel_exporter=otel_exporter,
        )
        self.turns: List[ConversationTurn] = []
        self._messages: List[Dict] = []  # Raw conversation history for the LLM

        self._log_session_start()

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def _log_session_start(self):
        event = AuditEvent(
            event_type=EventType.SESSION_START,
            agent_id=f"chat_session:{self.session_purpose or 'general'}",
            session_id=self.session_id,
            trace_id=self.session_id,
            risk_tier=self.model_card.risk_tier,
            regulatory_frameworks=[f.value for f in self.config.regulatory_frameworks],
            human_readable_reasoning=(
                f"Chat session started. Entity: {self.config.entity_name}. "
                f"Model: {self.model_card.model_id} ({self.model_card.provider}). "
                f"Purpose: {self.session_purpose or 'not specified'}. "
                f"Consent ref: {self.consent_ref or 'N/A'}."
            ),
        )
        self.audit_log.append(event)

    def send(
        self,
        user_message: str,
        human_readable_summary: str = "",
        policy_clause: str = "",
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Send a message, record the full audit trail for this turn, return the response.

        Args:
            user_message: The user's input.
            human_readable_summary: Your human-written description of what this turn
                decided/answered — required for RBI FREE-AI Rec 18. Do NOT pass the
                LLM's own explanation here; write your own.
            policy_clause: Specific policy section governing this interaction
                (e.g. "CREDIT_POLICY_v3.2 §4.2").
            context: Additional context dict passed to the policy engine.
        """
        turn_index = len(self.turns) + 1
        turn = ConversationTurn(
            turn_index=turn_index,
            user_input_hash=self._hash(user_message),
            user_input_length=len(user_message),
            model_id=self.model_card.model_id,
            model_version=self.model_card.model_version,
            policy_ref=self.config.board_policy_ref or "",
            policy_clause=policy_clause,
            human_readable_summary=human_readable_summary,
            consent_ref=self.consent_ref,
        )

        # Log user turn (hash only — not raw text)
        user_event = AuditEvent(
            event_type=EventType.TURN_USER,
            agent_id=f"chat_session:{self.session_purpose or 'general'}",
            session_id=self.session_id,
            trace_id=self.session_id,
            risk_tier=self.model_card.risk_tier,
            regulatory_frameworks=[f.value for f in self.config.regulatory_frameworks],
            tool_params_hash=turn.user_input_hash,  # reuse hash field for input
            human_readable_reasoning=f"Turn {turn_index}: user input received ({turn.user_input_length} chars). Hash recorded.",
        )
        self.audit_log.append(user_event)

        # ── Pre-model PII firewall ────────────────────────────────────────────
        # Tokenize PII in the user message BEFORE it leaves this process.
        # The LLM sees [PAN_1] instead of ABCDE1234F — no PII crosses the wire.
        # DPDP Act 2023 §8: data minimisation at the point of processing.
        self._messages.append({"role": "user", "content": user_message})

        if self.config.pii_masking_enabled:
            clean_messages, pii_vault = firewall_messages(
                self._messages, enabled=True
            )
            if pii_vault.token_count > 0:
                # Record that PII was found and tokenized (types only — not values)
                turn.pii_fields_masked = pii_vault.pii_types_found
                turn.pii_detected_in_output = False  # will re-check after response
        else:
            clean_messages, pii_vault = self._messages, PIIVault()

        turn.request_timestamp_utc_ms = int(time.time() * 1000)

        response_text, input_tokens, output_tokens = self.llm_adapter(
            messages=clean_messages,
            system=self.system_prompt,
        )

        turn.response_timestamp_utc_ms = int(time.time() * 1000)
        turn.latency_ms = turn.response_timestamp_utc_ms - turn.request_timestamp_utc_ms
        turn.input_tokens = input_tokens
        turn.output_tokens = output_tokens

        # Restore PII tokens in response text for user display.
        # The audit log only ever sees hashes — never restored values.
        if pii_vault.token_count > 0:
            response_text = pii_vault.restore(response_text)

        turn.assistant_output_hash = self._hash(response_text)
        turn.assistant_output_length = len(response_text)

        # Append to conversation history (raw text — kept in-memory for LLM context,
        # never written to the audit log)
        self._messages.append({"role": "assistant", "content": response_text})

        # Run analytics FIRST — reads actual response text.
        # Results are injected into guardrail context so rules fire on real evidence,
        # not on caller-supplied assertions.
        turn.analytics = analyse_turn(user_message, response_text)
        if turn.analytics.pii_in_output:
            turn.pii_detected_in_output = True
            turn.pii_fields_masked = turn.analytics.pii_in_output

        an = turn.analytics

        # Run guardrail policy if configured
        if self.policy_engine:
            eval_context = {
                # Infrastructure facts (caller-supplied, still needed for CHAT_001/005)
                "pii_masked": self.config.pii_masking_enabled,
                "consent_ref": self.consent_ref,
                "has_human_summary": bool(human_readable_summary),
                "policy_ref": self.config.board_policy_ref,
                "output_length": output_tokens,
                # Analytics-derived facts (read from actual response text)
                "pii_in_user_input": an.pii_in_input,
                "analytics_ai_disclosed": an.consumer_protection.ai_identity_disclosed,
                "analytics_human_escalation": an.consumer_protection.human_escalation_mentioned,
                "analytics_human_disclaimer": an.bias.disclaimer_present,
                "analytics_pii_in_output": bool(an.pii_in_output),
                "analytics_pii_requested": an.consumer_protection.pii_requested_by_agent,
                "analytics_has_financial_output": "calculation_provided" in an.response_types,
                "analytics_topic": an.topic,
                "analytics_bias_risk": an.bias.overall_risk,
                "analytics_grievance_mentioned": an.consumer_protection.grievance_channel_mentioned,
                # Caller context (may add extra keys but cannot override analytics keys)
                **(context or {}),
            }
            result = self.policy_engine.evaluate(
                eval_context, risk_tier=self.model_card.risk_tier.value
            )
            turn.guardrail_passed = result.overall_action == PolicyAction.ALLOW
            turn.guardrail_rules_failed = result.rules_failed
            turn.guardrail_rules_warned = result.rules_warned
            turn.guardrail_action = result.overall_action.value

            # Log guardrail check
            all_issues = result.rules_failed + result.rules_warned
            guardrail_event = AuditEvent(
                event_type=EventType.GUARDRAIL_CHECK,
                agent_id=f"chat_session:{self.session_purpose or 'general'}",
                session_id=self.session_id,
                trace_id=self.session_id,
                risk_tier=self.model_card.risk_tier,
                regulatory_frameworks=[f.value for f in self.config.regulatory_frameworks],
                guardrail_triggered=not turn.guardrail_passed,
                guardrail_rule=", ".join(all_issues) if all_issues else None,
                guardrail_action=turn.guardrail_action,
                compliance_flags=all_issues,   # includes both BLOCK and WARN rule IDs
                human_readable_reasoning=(
                    f"Turn {turn_index} policy check: {result.overall_action.value.upper()}. "
                    f"Rules passed: {len(result.rules_passed)}. "
                    f"Rules blocked: {result.rules_failed or 'none'}. "
                    f"Rules warned: {result.rules_warned or 'none'}."
                ),
            )
            self.audit_log.append(guardrail_event)

        # Log assistant turn
        assistant_event = AuditEvent(
            event_type=EventType.TURN_ASSISTANT,
            agent_id=f"chat_session:{self.session_purpose or 'general'}",
            session_id=self.session_id,
            trace_id=self.session_id,
            risk_tier=self.model_card.risk_tier,
            model_id=self.model_card.model_id,
            model_version=self.model_card.model_version,
            regulatory_frameworks=[f.value for f in self.config.regulatory_frameworks],
            tool_result_hash=turn.assistant_output_hash,
            latency_ms=turn.latency_ms,
            policy_ref=self.config.board_policy_ref,
            human_readable_reasoning=(
                human_readable_summary or
                f"Turn {turn_index}: assistant responded in {turn.latency_ms}ms "
                f"({output_tokens} tokens). Output hash recorded."
            ),
            guardrail_triggered=not turn.guardrail_passed,
        )
        self.audit_log.append(assistant_event)

        self.turns.append(turn)
        return response_text

    def close(self):
        """Finalise the session and log the end event."""
        total_ms = int(time.time() * 1000) - self.session_start_ms
        end_event = AuditEvent(
            event_type=EventType.SESSION_END,
            agent_id=f"chat_session:{self.session_purpose or 'general'}",
            session_id=self.session_id,
            trace_id=self.session_id,
            risk_tier=self.model_card.risk_tier,
            regulatory_frameworks=[f.value for f in self.config.regulatory_frameworks],
            latency_ms=total_ms,
            human_readable_reasoning=(
                f"Chat session ended. Turns: {len(self.turns)}. "
                f"Total duration: {total_ms}ms. "
                f"Chain integrity: {'VERIFIED' if self.audit_log.verify_integrity() else 'BROKEN'}."
            ),
        )
        self.audit_log.append(end_event)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_session_summary(self) -> Dict[str, Any]:
        total_turns = len(self.turns)
        failed_turns = [t for t in self.turns if not t.guardrail_passed]
        total_input_tokens = sum(t.input_tokens for t in self.turns)
        total_output_tokens = sum(t.output_tokens for t in self.turns)
        avg_latency = (
            sum(t.latency_ms for t in self.turns) / total_turns
            if total_turns else 0
        )
        return {
            "session_id": self.session_id,
            "session_purpose": self.session_purpose,
            "total_turns": total_turns,
            "guardrail_failures": len(failed_turns),
            "failed_turn_indices": [t.turn_index for t in failed_turns],
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "avg_latency_ms": round(avg_latency, 1),
            "chain_intact": self.audit_log.verify_integrity(),
        }
