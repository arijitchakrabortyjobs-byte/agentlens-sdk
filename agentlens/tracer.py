"""
AgentLens Tracer
----------------
Context manager that wraps any LangChain (or generic Python) agent
and automatically captures the full audit trail.

Works with any framework — LangChain, CrewAI, AutoGen, raw Python.
No framework lock-in. Drop-in instrumentation.

Usage (LangChain):
    tracer = AuditTracer(config)

    with tracer.trace_agent("credit_bot_v2") as span:
        span.set_model("gpt-4o", "2024-11-20")
        span.set_risk_tier(RiskTier.HIGH)
        span.set_policy("CREDIT_POLICY_v3.2_APR2026")

        result = langchain_agent.invoke({"input": user_query})

        span.record_decision(
            output=result["output"],
            reasoning="Approved: applicant income > 3x EMI, CIBIL 720+",
            context={"decision_amount_inr": 500000, "pii_masked": True}
        )
"""

import time
import uuid
import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

from .config import AgentLensConfig
from .audit_log import AuditEvent, AuditLog, EventType, RiskTier
from .policy import PolicyEngine, PolicyCheckResult, PolicyAction


class AgentSpan:
    """
    An active span representing a single agent run.
    Records all events, tool calls, decisions, and policy checks
    into the audit log with full traceability.
    """

    def __init__(
        self,
        agent_id: str,
        config: AgentLensConfig,
        audit_log: AuditLog,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.agent_id = agent_id
        self.config = config
        self.audit_log = audit_log
        self.policy_engine = policy_engine
        self.trace_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self._model_id = ""
        self._model_version = ""
        self._risk_tier = RiskTier(config.default_model_risk_tier)
        self._policy_ref = config.board_policy_ref or ""
        self._agent_version = "1.0.0"
        self._start_time = time.time()
        self._policy_result: Optional[PolicyCheckResult] = None

    # ── Configuration helpers ────────────────────────────────────────────────

    def set_model(self, model_id: str, model_version: str = ""):
        """Record which model is powering this agent."""
        self._model_id = model_id
        self._model_version = model_version

    def set_risk_tier(self, tier: RiskTier):
        """Set RBI MRM risk tier for this agent run."""
        self._risk_tier = tier

    def set_policy(self, policy_ref: str, version: str = ""):
        """Reference the board-approved policy document governing this agent."""
        self._policy_ref = policy_ref

    def set_agent_version(self, version: str):
        self._agent_version = version

    # ── Core recording methods ───────────────────────────────────────────────

    def _base_event(self, event_type: EventType) -> AuditEvent:
        return AuditEvent(
            trace_id=self.trace_id,
            session_id=self.session_id,
            event_type=event_type,
            agent_id=self.agent_id,
            agent_version=self._agent_version,
            model_id=self._model_id,
            model_version=self._model_version,
            risk_tier=self._risk_tier,
            policy_ref=self._policy_ref,
            regulatory_frameworks=[f.value for f in self.config.regulatory_frameworks],
        )

    def record_tool_call(
        self,
        tool_name: str,
        params: Any,
        result: Any = None,
        latency_ms: int = 0,
    ) -> AuditEvent:
        """
        Record a tool invocation with Triple-Identity logging.
        Raw params are hashed — never stored in plain text (DPDP compliance).
        """
        import json
        params_str = json.dumps(params, default=str, sort_keys=True)
        result_str = json.dumps(result, default=str, sort_keys=True) if result else ""

        event = self._base_event(EventType.TOOL_CALL)
        event.tool_name = tool_name
        event.tool_params_hash = hashlib.sha256(params_str.encode()).hexdigest()
        event.tool_result_hash = (
            hashlib.sha256(result_str.encode()).hexdigest() if result_str else None
        )
        event.latency_ms = latency_ms
        # Human readable: tool name + non-PII summary
        event.human_readable_reasoning = (
            f"Tool '{tool_name}' invoked. Params hashed for DPDP compliance."
        )
        return self.audit_log.append(event)

    def record_decision(
        self,
        output: str,
        reasoning: str,
        context: Optional[Dict[str, Any]] = None,
        human_review_required: bool = False,
    ) -> AuditEvent:
        """
        Record an agent decision with:
        1. The output
        2. Human-readable reasoning (your words, NOT LLM chain-of-thought)
        3. Policy check result (why-trail)

        This is the core of RBI FREE-AI Rec 18 explainability compliance.
        The reasoning here is deterministic and auditor-readable — it does
        NOT rely on the LLM's generated chain-of-thought, which research
        shows can be performative on recall-heavy tasks.
        """
        ctx = context or {}
        ctx["human_readable_reasoning"] = reasoning
        ctx["policy_ref"] = self._policy_ref
        ctx["pii_masked"] = self.config.pii_masking_enabled

        # Run policy engine if configured
        policy_result = None
        if self.policy_engine:
            policy_result = self.policy_engine.evaluate(
                context=ctx, risk_tier=self._risk_tier.value
            )
            self._policy_result = policy_result

        event = self._base_event(EventType.DECISION)
        event.decision_output = output
        event.human_readable_reasoning = reasoning
        event.human_review_required = (
            human_review_required or
            (policy_result is not None and policy_result.requires_human_review)
        )

        if policy_result:
            event.guardrail_triggered = (
                policy_result.overall_action != PolicyAction.ALLOW
            )
            event.guardrail_rule = (
                ", ".join(policy_result.rules_failed) if policy_result.rules_failed else None
            )
            event.guardrail_action = policy_result.overall_action.value
            event.compliance_flags = policy_result.rules_failed

        return self.audit_log.append(event)

    def record_human_override(
        self,
        reviewer_id: str,
        reason: str,
        original_decision: str,
        new_decision: str,
    ) -> AuditEvent:
        """
        Log a human override event.
        RBI FREE-AI Rec 21 + MRM 2026: Human overrides must be
        timestamped, attributed, and immutably logged.
        """
        event = self._base_event(EventType.HUMAN_OVERRIDE)
        event.human_override = True
        event.human_override_reason = reason
        event.human_reviewer_id_hash = hashlib.sha256(
            reviewer_id.encode()
        ).hexdigest()
        event.decision_output = f"OVERRIDE: {original_decision} → {new_decision}"
        event.human_readable_reasoning = f"Human reviewer overrode agent decision. Reason: {reason}"
        return self.audit_log.append(event)

    def record_error(self, error_code: str, message: str) -> AuditEvent:
        event = self._base_event(EventType.ERROR)
        event.error_code = error_code
        event.error_message = message
        return self.audit_log.append(event)

    def get_policy_result(self) -> Optional[PolicyCheckResult]:
        return self._policy_result


class AuditTracer:
    """
    Main entry point for AgentLens instrumentation.
    Framework-agnostic — wraps any agent with a context manager.
    """

    def __init__(
        self,
        config: AgentLensConfig,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.config = config
        self.policy_engine = policy_engine
        self.audit_log = AuditLog(entity_name=config.entity_name)

    @contextmanager
    def trace_agent(self, agent_id: str) -> Generator[AgentSpan, None, None]:
        """
        Context manager that wraps an agent run with full audit tracing.

        Example:
            with tracer.trace_agent("loan_approval_agent") as span:
                span.set_model("gpt-4o")
                span.set_risk_tier(RiskTier.HIGH)
                result = agent.run(input)
                span.record_decision(result, reasoning="...")
        """
        span = AgentSpan(
            agent_id=agent_id,
            config=self.config,
            audit_log=self.audit_log,
            policy_engine=self.policy_engine,
        )

        # Log agent start
        start_event = AuditEvent(
            trace_id=span.trace_id,
            session_id=span.session_id,
            event_type=EventType.AGENT_START,
            agent_id=agent_id,
            risk_tier=span._risk_tier,
            regulatory_frameworks=[f.value for f in self.config.regulatory_frameworks],
            human_readable_reasoning=f"Agent '{agent_id}' started under "
                f"{self.config.entity_name} ({self.config.entity_type.value}). "
                f"Frameworks: {[f.value for f in self.config.regulatory_frameworks]}",
        )
        self.audit_log.append(start_event)

        try:
            yield span
        except Exception as e:
            span.record_error("AGENT_EXCEPTION", str(e))
            raise
        finally:
            # Log agent end with elapsed time
            elapsed_ms = int((time.time() - span._start_time) * 1000)
            end_event = AuditEvent(
                trace_id=span.trace_id,
                session_id=span.session_id,
                event_type=EventType.AGENT_END,
                agent_id=agent_id,
                latency_ms=elapsed_ms,
                risk_tier=span._risk_tier,
                regulatory_frameworks=[f.value for f in self.config.regulatory_frameworks],
                human_readable_reasoning=f"Agent '{agent_id}' completed in {elapsed_ms}ms.",
            )
            self.audit_log.append(end_event)

    def get_log(self) -> AuditLog:
        return self.audit_log

    def export_audit_report(self, format: str = "json") -> str:
        """Export full audit trail for regulatory submission."""
        if format == "ndjson":
            return self.audit_log.to_ndjson()
        import json
        return json.dumps(
            {
                "agentlens_version": "0.1.0",
                "entity": self.config.entity_name,
                "entity_type": self.config.entity_type.value,
                "regulatory_frameworks": [
                    f.value for f in self.config.regulatory_frameworks
                ],
                "board_policy_ref": self.config.board_policy_ref,
                "audit_summary": self.audit_log.summary(),
                "events": [e.to_dict() for e in self.audit_log.get_events()],
                "chain_verified": self.audit_log.verify_integrity(),
            },
            indent=2,
            default=str,
        )
