"""
AgentLens Live Session Report
------------------------------
Generates the 7-section compliance audit report from a ChatSessionTracer.

Sections:
  1. Session Header        — entity, AI officer, model card, policy ref
  2. Turn-by-Turn Log      — hashes, latency, token counts per turn
  3. Explainability Block  — human-authored summaries per turn
  4. Guardrail Log         — all policy checks with pass/fail + why-trail
  5. Chain Integrity       — SHA-256 tamper-evident verification
  6. DPDP Compliance Block — PII masking, data minimisation, consent
  7. RBI MRM Model Card    — model inventory reference
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from .audit_log import AuditLog, EventType, RiskTier
from .config import AgentLensConfig
from .chat_tracer import ChatSessionTracer, ConversationTurn, ModelCard


class LiveSessionReport:
    """
    Generates regulatorily complete audit reports from a completed
    or in-progress ChatSessionTracer session.
    """

    def __init__(self, session: ChatSessionTracer):
        self.session = session
        self.config = session.config
        self.model_card = session.model_card
        self.turns: List[ConversationTurn] = session.turns
        self.audit_log: AuditLog = session.audit_log
        self._generated_at = datetime.now(timezone.utc).isoformat()

    # ─────────────────────────────────────────────────────────────────────────
    # Section builders
    # ─────────────────────────────────────────────────────────────────────────

    def _section_1_header(self) -> Dict[str, Any]:
        """Session Header — entity identity, governance, model reference."""
        return {
            "section": "1_SESSION_HEADER",
            "report_type": "AgentLens_Live_Chat_Audit_Report",
            "report_version": "1.0",
            "generated_at_utc": self._generated_at,
            "entity": {
                "name": self.config.entity_name,
                "type": self.config.entity_type.value,
                "is_rbi_regulated": self.config.is_rbi_regulated(),
                "is_sebi_regulated": self.config.is_sebi_regulated(),
            },
            "governance": {
                "board_policy_ref": self.config.board_policy_ref or "⚠ NOT SET",
                "ai_officer_name": self.config.ai_officer_name or "⚠ NOT SET",
                "ai_officer_email": self.config.ai_officer_email or "⚠ NOT SET",
                "model_inventory_ref": self.config.model_inventory_ref or "⚠ NOT SET",
                "audit_retention_days": self.config.audit_retention_days,
                "pii_masking_enabled": self.config.pii_masking_enabled,
            },
            "session": {
                "session_id": self.session.session_id,
                "session_purpose": self.session.session_purpose,
                "consent_ref": self.session.consent_ref or "⚠ NOT SET",
                "total_turns": len(self.turns),
            },
            "regulatory_frameworks": [f.value for f in self.config.regulatory_frameworks],
        }

    def _section_2_turn_log(self) -> Dict[str, Any]:
        """Turn-by-Turn Log — per-exchange hashes, latency, token counts."""
        turn_records = []
        for t in self.turns:
            turn_records.append({
                "turn": t.turn_index,
                "turn_id": t.turn_id,
                "user_input": {
                    "hash_sha256": t.user_input_hash,
                    "length_chars": t.user_input_length,
                    "note": "Raw content not stored — DPDP data minimisation",
                },
                "assistant_output": {
                    "hash_sha256": t.assistant_output_hash,
                    "length_chars": t.assistant_output_length,
                    "note": "Raw content not stored — DPDP data minimisation",
                },
                "model": {
                    "model_id": t.model_id,
                    "model_version": t.model_version,
                },
                "tokens": {
                    "input": t.input_tokens,
                    "output": t.output_tokens,
                    "total": t.input_tokens + t.output_tokens,
                },
                "timing": {
                    "request_utc_ms": t.request_timestamp_utc_ms,
                    "response_utc_ms": t.response_timestamp_utc_ms,
                    "latency_ms": t.latency_ms,
                },
                "guardrail_passed": t.guardrail_passed,
            })

        avg_latency = (
            sum(t.latency_ms for t in self.turns) / len(self.turns)
            if self.turns else 0
        )
        total_tokens = sum(t.input_tokens + t.output_tokens for t in self.turns)

        return {
            "section": "2_TURN_BY_TURN_LOG",
            "summary": {
                "total_turns": len(self.turns),
                "total_tokens": total_tokens,
                "avg_latency_ms": round(avg_latency, 1),
                "turns_with_guardrail_failure": sum(1 for t in self.turns if not t.guardrail_passed),
            },
            "turns": turn_records,
        }

    def _section_3_explainability(self) -> Dict[str, Any]:
        """
        Explainability Block — human-authored reasoning per turn.
        RBI FREE-AI Rec 18: independent of LLM chain-of-thought.
        """
        entries = []
        missing_count = 0
        for t in self.turns:
            has_summary = bool(t.human_readable_summary)
            if not has_summary:
                missing_count += 1
            entries.append({
                "turn": t.turn_index,
                "policy_ref": t.policy_ref,
                "policy_clause": t.policy_clause or "not specified",
                "human_readable_summary": t.human_readable_summary or "⚠ NOT PROVIDED",
                "compliant": has_summary,
                "regulatory_ref": "RBI_FREE_AI_REC_18_EXPLAINABILITY",
            })

        return {
            "section": "3_EXPLAINABILITY",
            "regulatory_ref": "RBI FREE-AI Recommendation 18 — Explainability and Bias Audit",
            "note": (
                "These summaries are authored by the operating entity, not generated by the LLM. "
                "They constitute the deterministic why-trail required for regulatory examination."
            ),
            "compliance_status": "COMPLIANT" if missing_count == 0 else f"⚠ {missing_count} turns missing human summary",
            "turns": entries,
        }

    def _section_4_guardrails(self) -> Dict[str, Any]:
        """Guardrail Log — all policy checks across all turns."""
        events = self.audit_log.get_events()
        guardrail_events = [e for e in events if e.event_type == EventType.GUARDRAIL_CHECK]

        checks = []
        total_failures = 0
        for e in guardrail_events:
            failed = e.guardrail_triggered
            if failed:
                total_failures += 1
            checks.append({
                "event_id": e.event_id,
                "timestamp_utc": e.timestamp_utc,
                "guardrail_triggered": failed,
                "rules_failed": e.compliance_flags or [],
                "guardrail_rule": e.guardrail_rule,
                "action_taken": e.guardrail_action,
                "reasoning": e.human_readable_reasoning,
            })

        return {
            "section": "4_GUARDRAIL_LOG",
            "summary": {
                "total_checks": len(checks),
                "total_failures": total_failures,
                "failure_rate_pct": round(total_failures / len(checks) * 100, 1) if checks else 0,
                "overall_status": "CLEAN" if total_failures == 0 else f"⚠ {total_failures} GUARDRAIL FAILURES",
            },
            "checks": checks,
        }

    def _section_5_chain_integrity(self) -> Dict[str, Any]:
        """Chain Integrity — tamper-evident SHA-256 verification."""
        events = self.audit_log.get_events()
        intact = self.audit_log.verify_integrity()

        chain = []
        for e in events:
            chain.append({
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "timestamp_utc": e.timestamp_utc,
                "previous_hash": e.previous_event_hash[:16] + "...",
                "event_hash": e.event_hash[:16] + "...",
            })

        return {
            "section": "5_CHAIN_INTEGRITY",
            "regulatory_ref": "RBI FREE-AI Pillar 6 (Assurance) — Tamper-Evident Audit Trail",
            "chain_intact": intact,
            "status": "✅ VERIFIED — audit trail has not been tampered with" if intact else "⚠ CHAIN BROKEN — integrity check failed",
            "total_events": len(events),
            "algorithm": "SHA-256 chained hash (each event hashes the previous event's hash)",
            "chain": chain,
        }

    def _section_6_dpdp(self) -> Dict[str, Any]:
        """DPDP Compliance Block — PII, data minimisation, consent."""
        turns_with_pii = [t for t in self.turns if t.pii_detected_in_output]
        consent_present = bool(self.session.consent_ref)

        return {
            "section": "6_DPDP_COMPLIANCE",
            "regulatory_ref": "Digital Personal Data Protection Act 2023",
            "consent": {
                "consent_ref": self.session.consent_ref or "⚠ NOT SET",
                "status": "COMPLIANT" if consent_present else "⚠ NO CONSENT REFERENCE — review required",
                "regulatory_basis": "DPDP Act 2023, Section 6 — Consent",
            },
            "data_minimisation": {
                "pii_masking_enabled": self.config.pii_masking_enabled,
                "raw_user_content_stored": False,
                "raw_assistant_content_stored": False,
                "storage_format": "SHA-256 hashes only",
                "status": "COMPLIANT" if self.config.pii_masking_enabled else "⚠ PII MASKING DISABLED",
                "regulatory_basis": "DPDP Act 2023, Section 8 — Data Minimisation",
            },
            "pii_in_output": {
                "turns_with_detected_pii": len(turns_with_pii),
                "affected_turns": [t.turn_index for t in turns_with_pii],
                "pii_types_found": list({p for t in turns_with_pii for p in t.pii_fields_masked}),
                "status": "CLEAN" if not turns_with_pii else "⚠ PII DETECTED IN MODEL OUTPUT — review required",
            },
            "audit_retention": {
                "configured_days": self.config.audit_retention_days,
                "minimum_required_days": 1825,
                "compliant": self.config.audit_retention_days >= 1825,
                "regulatory_basis": "RBI MRM 2026 — 5 year minimum retention; 10 years for decommissioned models",
            },
        }

    def _section_7_model_card(self) -> Dict[str, Any]:
        """RBI MRM Model Card — inventory record for this session's model."""
        mc = self.model_card
        validated = bool(mc.last_validated_date)
        kill_switch_tested = bool(mc.kill_switch_last_tested)

        gaps = []
        if not mc.inventory_id:
            gaps.append("inventory_id not set — model may not be in institutional inventory")
        if not validated:
            gaps.append("last_validated_date not set — independent validation status unknown")
        if not kill_switch_tested:
            gaps.append("kill_switch_last_tested not set — RBI MRM 2026 requires tested kill switch")

        return {
            "section": "7_MODEL_CARD",
            "regulatory_ref": "RBI Model Risk Management Guidance June 2026",
            "model_card": mc.to_dict(),
            "compliance_gaps": gaps,
            "inventory_status": "IN_INVENTORY" if mc.inventory_id else "⚠ NOT IN INVENTORY",
            "validation_status": "VALIDATED" if validated else "⚠ VALIDATION DATE NOT RECORDED",
            "kill_switch_status": "TESTED" if kill_switch_tested else "⚠ KILL SWITCH NOT TESTED",
            "overall_status": "COMPLIANT" if not gaps else f"⚠ {len(gaps)} GAP(S) FOUND",
        }

    # ─────────────────────────────────────────────────────────────────────────
    # Full report export
    # ─────────────────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Export the full 7-section compliance report as a dict."""
        return {
            "agentlens_version": "0.1.0",
            "report_generated_at_utc": self._generated_at,
            **{f"section_{i+1}": s for i, s in enumerate([
                self._section_1_header(),
                self._section_2_turn_log(),
                self._section_3_explainability(),
                self._section_4_guardrails(),
                self._section_5_chain_integrity(),
                self._section_6_dpdp(),
                self._section_7_model_card(),
            ])},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_console(self) -> str:
        """
        Human-readable executive summary for terminal output.
        Board/examiner ready — no jargon.
        """
        s1 = self._section_1_header()
        s2 = self._section_2_turn_log()
        s4 = self._section_4_guardrails()
        s5 = self._section_5_chain_integrity()
        s6 = self._section_6_dpdp()
        s7 = self._section_7_model_card()

        lines = [
            "=" * 70,
            "  AgentLens — Live Chat Session Audit Report",
            f"  Entity  : {s1['entity']['name']} ({s1['entity']['type']})",
            f"  AI Officer: {s1['governance']['ai_officer_name']}",
            f"  Policy  : {s1['governance']['board_policy_ref']}",
            f"  Session : {s1['session']['session_id'][:20]}...",
            f"  Purpose : {s1['session']['session_purpose']}",
            f"  Generated: {self._generated_at[:19]} UTC",
            "=" * 70,
            "",
            "── SECTION 1: SESSION SUMMARY ──────────────────────────────────────",
            f"  Turns          : {s2['summary']['total_turns']}",
            f"  Total tokens   : {s2['summary']['total_tokens']:,}",
            f"  Avg latency    : {s2['summary']['avg_latency_ms']} ms",
            f"  Guardrail fails: {s2['summary']['turns_with_guardrail_failure']}",
            "",
            "── SECTION 5: CHAIN INTEGRITY ──────────────────────────────────────",
            f"  {s5['status']}",
            f"  Total events chained: {s5['total_events']}",
            "",
            "── SECTION 4: GUARDRAIL STATUS ─────────────────────────────────────",
            f"  Checks run   : {s4['summary']['total_checks']}",
            f"  Failures     : {s4['summary']['total_failures']}",
            f"  Status       : {s4['summary']['overall_status']}",
        ]
        if s4["checks"]:
            for check in s4["checks"]:
                if check["guardrail_triggered"]:
                    lines.append(f"  ⚠ Rules failed: {check['rules_failed']}")

        lines += [
            "",
            "── SECTION 6: DPDP COMPLIANCE ──────────────────────────────────────",
            f"  Consent ref    : {s6['consent']['consent_ref']}",
            f"  Consent status : {s6['consent']['status']}",
            f"  PII masking    : {'✅ ENABLED' if s6['data_minimisation']['pii_masking_enabled'] else '⚠ DISABLED'}",
            f"  Raw content stored: {'No ✅' if not s6['data_minimisation']['raw_user_content_stored'] else '⚠ YES'}",
            f"  PII in output  : {s6['pii_in_output']['status']}",
            f"  Retention      : {s6['audit_retention']['configured_days']} days ({'✅' if s6['audit_retention']['compliant'] else '⚠ BELOW MINIMUM'})",
            "",
            "── SECTION 7: RBI MRM MODEL CARD ───────────────────────────────────",
            f"  Model          : {s7['model_card']['model_id']} v{s7['model_card']['model_version']}",
            f"  Provider       : {s7['model_card']['provider']}",
            f"  Risk tier      : Tier {s7['model_card']['risk_tier']} ({s7['model_card']['risk_tier_label']})",
            f"  Intended use   : {s7['model_card']['intended_use']}",
            f"  Inventory      : {s7['inventory_status']}",
            f"  Last validated : {s7['model_card']['last_validated_date'] or '⚠ NOT SET'}",
            f"  Kill switch    : {s7['kill_switch_status']}",
        ]
        if s7["compliance_gaps"]:
            lines.append("  Gaps:")
            for gap in s7["compliance_gaps"]:
                lines.append(f"    ⚠ {gap}")

        lines += [
            "",
            "  This report is produced by AgentLens and is suitable for",
            "  submission to RBI examiners, Board Risk Committees, and",
            "  Data Protection Officers under DPDP Act 2023.",
            "=" * 70,
        ]
        return "\n".join(lines)
