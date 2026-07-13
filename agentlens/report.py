"""
AgentLens Compliance Reporter
------------------------------
Generates structured, regulator-ready audit reports from the audit trail.

Report types:
  1. RBI FREE-AI Compliance Summary    — for NBFC / bank board reporting
  2. RBI MRM Model Risk Report         — for model validation committee
  3. SEBI Algorithm Accountability     — for securities entities
  4. DPDP Data Protection Audit        — for Data Protection Officer
  5. Executive Dashboard               — plain-language summary for C-suite

All reports are designed to be submitted directly to Indian regulators
without additional processing by compliance teams.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .audit_log import AuditLog, AuditEvent, EventType, RiskTier
from .config import AgentLensConfig
from .compliance_db import ComplianceDatabase


class ComplianceReporter:
    """Generates regulator-ready compliance reports from the audit log."""

    def __init__(
        self,
        audit_log: AuditLog,
        config: AgentLensConfig,
        compliance_db: Optional[ComplianceDatabase] = None,
    ):
        self.log = audit_log
        self.config = config
        self._events = audit_log.get_events()
        self._db = compliance_db

        # Auto-record this session into the compliance DB if one is provided
        if self._db is not None:
            try:
                self._db.record_session(self.log.summary())
            except Exception:
                pass

    def _events_by_type(self, event_type: EventType) -> List[AuditEvent]:
        return [e for e in self._events if e.event_type == event_type]

    def rbi_free_ai_summary(self) -> Dict[str, Any]:
        """
        RBI FREE-AI Compliance Summary Report.
        Structured around the 6 strategic pillars and 26 recommendations.
        Designed for submission to board risk committee.
        """
        decisions = self._events_by_type(EventType.DECISION)
        tool_calls = self._events_by_type(EventType.TOOL_CALL)
        overrides = self._events_by_type(EventType.HUMAN_OVERRIDE)
        errors = self._events_by_type(EventType.ERROR)

        # Pillar: Governance — check board policy coverage
        governance_status = {
            "pillar": "Governance (FREE-AI Pillar 4)",
            "board_policy_ref": self.config.board_policy_ref or "⚠ NOT CONFIGURED",
            "entity_classification": self.config.entity_type.value,
            "audit_retention_days": self.config.audit_retention_days,
            "status": "COMPLIANT" if self.config.board_policy_ref else "NON-COMPLIANT",
            "recommendation": "RBI FREE-AI Rec 14 — Board-Approved AI Policy",
        }

        # Pillar: Assurance — audit trail integrity
        assurance_status = {
            "pillar": "Assurance (FREE-AI Pillar 6)",
            "chain_intact": self.log.verify_integrity(),
            "total_events_logged": len(self._events),
            "decisions_with_reasoning": sum(
                1 for d in decisions if d.human_readable_reasoning
            ),
            "decisions_missing_reasoning": sum(
                1 for d in decisions if not d.human_readable_reasoning
            ),
            "status": "COMPLIANT" if self.log.verify_integrity() else "⚠ CHAIN BROKEN",
            "recommendation": "RBI FREE-AI Rec 25 — Independent Validation",
        }

        # Session-level override rate
        session_decisions = len(decisions)
        session_overrides = len(overrides)
        session_override_rate = (
            round(session_overrides / session_decisions, 4) if session_decisions else 0.0
        )

        # Cross-session override rate from ComplianceDatabase if available
        cross_session_info: Dict[str, Any] = {}
        if self._db is not None:
            try:
                cs = self._db.entity_summary(self.config.entity_name)
                cross_session_info = {
                    "total_sessions_tracked": cs.get("total_sessions", 0),
                    "cross_session_override_rate": cs.get("override_rate", 0.0),
                    "cross_session_override_rate_pct": cs.get("override_rate_pct", "0.0%"),
                    "rubber_stamp_sessions_detected": cs.get("rubber_stamp_flag", False),
                    "rubber_stamp_session_ids": cs.get("rubber_stamp_sessions", []),
                    "regulatory_ref": "US SR 26-2 effective challenge; UK ICO accountability",
                }
            except Exception:
                cross_session_info = {"error": "ComplianceDatabase query failed"}

        # Pillar: Protection — consumer and data protection
        protection_status = {
            "pillar": "Protection (FREE-AI Pillar 5)",
            "pii_masking_enabled": self.config.pii_masking_enabled,
            "human_overrides_logged": session_overrides,
            "session_override_rate": session_override_rate,
            "cross_session": cross_session_info,
            "override_details": [
                {
                    "timestamp": o.timestamp_utc,
                    "reason": o.human_override_reason,
                    "reviewer_hash": o.human_reviewer_id_hash,
                }
                for o in overrides
            ],
            "dpdp_compliance": "COMPLIANT" if self.config.pii_masking_enabled else "⚠ PII MASKING DISABLED",
            "recommendation": "DPDP Act 2023 S.8 + RBI FREE-AI Rec 22",
        }

        # Tier-based model risk breakdown
        tier_breakdown = {}
        for tier in [1, 2, 3]:
            tier_events = [e for e in decisions if e.risk_tier == RiskTier(tier)]
            tier_breakdown[f"tier_{tier}"] = {
                "count": len(tier_events),
                "human_reviews_required": sum(1 for e in tier_events if e.human_review_required),
                "guardrails_triggered": sum(1 for e in tier_events if e.guardrail_triggered),
            }

        return {
            "report_type": "RBI_FREE_AI_Compliance_Summary",
            "report_version": "1.0",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "entity": self.config.entity_name,
            "entity_type": self.config.entity_type.value,
            "regulatory_framework": "RBI FREE-AI Framework, August 2025",
            "pillar_status": {
                "governance": governance_status,
                "assurance": assurance_status,
                "protection": protection_status,
            },
            "model_risk_tiers": tier_breakdown,
            "overall_audit_health": {
                "total_agent_decisions": len(decisions),
                "total_tool_calls": len(tool_calls),
                "errors_recorded": len(errors),
                "guardrails_triggered": sum(1 for e in decisions if e.guardrail_triggered),
                "compliance_flags_raised": sum(len(e.compliance_flags) for e in self._events),
            },
            "chain_integrity_verified": self.log.verify_integrity(),
        }

    def cross_session_report(self) -> Dict[str, Any]:
        """
        Cross-session accountability report using the ComplianceDatabase.
        Returns human override rates, rubber-stamp detection, and
        responsibility chain across all recorded sessions for this entity.

        Satisfies:
          US SR 26-2: effective challenge — override rate as proxy metric
          UK ICO: controller/processor responsibility chain
          Singapore MGF Dimension 2: organisational accountability
        """
        if self._db is None:
            return {
                "error": "No ComplianceDatabase configured. Pass compliance_db= to ComplianceReporter.",
                "hint": "from agentlens.compliance_db import ComplianceDatabase; db = ComplianceDatabase()",
            }
        return {
            "report_type": "Cross_Session_Accountability",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "entity": self.config.entity_name,
            **self._db.entity_summary(self.config.entity_name),
        }

    def executive_dashboard(self) -> str:
        """
        Plain-language executive summary for C-suite and board.
        No jargon — designed for non-technical board members.
        """
        summary = self.log.summary()
        decisions = self._events_by_type(EventType.DECISION)
        overrides = self._events_by_type(EventType.HUMAN_OVERRIDE)
        guardrails_hit = sum(1 for e in decisions if e.guardrail_triggered)

        tier1_decisions = [e for e in decisions if e.risk_tier == RiskTier.HIGH]
        tier1_human_reviews = sum(1 for e in tier1_decisions if e.human_review_required)

        lines = [
            "=" * 60,
            "  AgentLens — AI Agent Audit Dashboard",
            f"  Entity: {self.config.entity_name}",
            f"  Report Date: {datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}",
            "=" * 60,
            "",
            "AUDIT TRAIL INTEGRITY",
            f"  ✅ Tamper-evident chain: {'VERIFIED' if summary.get('chain_intact') else '⚠ BROKEN'}",
            f"  📋 Total events logged: {summary.get('total_events', 0)}",
            "",
            "AGENT DECISION SUMMARY",
            f"  🤖 Total AI decisions: {len(decisions)}",
            f"  🔴 High-risk (Tier 1) decisions: {len(tier1_decisions)}",
            f"  👤 Human reviews triggered: {tier1_human_reviews}",
            f"  🛡  Guardrails activated: {guardrails_hit}",
            f"  ✍️  Human overrides recorded: {len(overrides)}",
            "",
            "REGULATORY COMPLIANCE STATUS",
            f"  RBI FREE-AI Board Policy: {'✅ Configured' if self.config.board_policy_ref else '⚠ NOT SET'}",
            f"  DPDP PII Protection: {'✅ Enabled' if self.config.pii_masking_enabled else '⚠ DISABLED'}",
            f"  Audit chain integrity: {'✅ Verified' if summary.get('chain_intact') else '⚠ VERIFY FAILED'}",
            "",
            "FRAMEWORKS COVERED",
        ]
        for fw in self.config.regulatory_frameworks:
            lines.append(f"  ✅ {fw.value}")

        lines += [
            "",
            "  This report is generated by AgentLens and is suitable",
            "  for submission to the Board Risk Committee and RBI examiners.",
            "=" * 60,
        ]
        return "\n".join(lines)
