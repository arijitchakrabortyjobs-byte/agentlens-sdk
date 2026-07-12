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
            an = t.analytics
            turn_rec = {
                "turn": t.turn_index,
                "turn_id": t.turn_id,
                "user_input": {
                    "hash_sha256": t.user_input_hash,
                    "length_chars": t.user_input_length,
                    "pii_detected": an.pii_in_input if an else [],
                    "topic_classified": an.topic if an else "unknown",
                    "note": "Raw content not stored — DPDP data minimisation",
                },
                "assistant_output": {
                    "hash_sha256": t.assistant_output_hash,
                    "length_chars": t.assistant_output_length,
                    "pii_detected": an.pii_in_output if an else [],
                    "response_types": an.response_types if an else [],
                    "note": "Raw content not stored — DPDP data minimisation",
                },
                "model": {
                    "model_id": t.model_id,
                    "model_version": t.model_version,
                    "regulatory_ref": "RBI MRM 2026 — model version mandatory per decision",
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
                    "precision": "millisecond — SEBI AIML 2025 requirement",
                },
                "guardrail_passed": t.guardrail_passed,
                "guardrail_action": t.guardrail_action,
                "guardrail_rules_failed": t.guardrail_rules_failed,
                "turn_risk_summary": an.risk_summary if an else "UNKNOWN",
            }
            if an:
                turn_rec["bias_check"] = {
                    "automation_bias_risk": an.bias.automation_bias_risk,
                    "demographic_assumption": an.bias.demographic_assumption,
                    "human_disclaimer_present": an.bias.disclaimer_present,
                    "overall_risk": an.bias.overall_risk,
                    "flags": an.bias.flags,
                    "regulatory_ref": "RBI FREE-AI Rec 18 — Bias Audit",
                }
                turn_rec["consumer_protection"] = {
                    "ai_identity_disclosed": an.consumer_protection.ai_identity_disclosed,
                    "human_escalation_mentioned": an.consumer_protection.human_escalation_mentioned,
                    "grievance_channel_mentioned": an.consumer_protection.grievance_channel_mentioned,
                    "pii_requested_by_agent": an.consumer_protection.pii_requested_by_agent,
                    "flags": an.consumer_protection.flags,
                    "regulatory_ref": "RBI FREE-AI Rec 22/23 — Consumer Protection",
                }
            turn_records.append(turn_rec)

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

        # Aggregate analytics across all turns
        all_topics = []
        bias_high = 0
        cp_missing_disclosure = 0
        cp_missing_escalation = 0
        for t in self.turns:
            if t.analytics:
                all_topics.append(t.analytics.topic)
                if t.analytics.bias and t.analytics.bias.overall_risk == "HIGH":
                    bias_high += 1
                if t.analytics.consumer_protection:
                    if not t.analytics.consumer_protection.ai_identity_disclosed:
                        cp_missing_disclosure += 1
                    if not t.analytics.consumer_protection.human_escalation_mentioned:
                        cp_missing_escalation += 1

        lines = [
            "=" * 70,
            "  AgentLens — Live Chat Session Audit Report",
            f"  Entity     : {s1['entity']['name']} ({s1['entity']['type']})",
            f"  AI Officer : {s1['governance']['ai_officer_name']} <{s1['governance']['ai_officer_email']}>",
            f"  Policy ref : {s1['governance']['board_policy_ref']}",
            f"  Inv. ref   : {s1['governance']['model_inventory_ref']}",
            f"  Session    : {s1['session']['session_id'][:20]}...",
            f"  Purpose    : {s1['session']['session_purpose']}",
            f"  Consent    : {s1['session']['consent_ref']}",
            f"  Generated  : {self._generated_at[:19]} UTC",
            f"  Frameworks : {', '.join(s1['regulatory_frameworks'])}",
            "=" * 70,
            "",
            "── SEC 1  SESSION OVERVIEW ──────────────────────────────────────────",
            f"  Turns            : {s2['summary']['total_turns']}",
            f"  Total tokens     : {s2['summary']['total_tokens']:,}",
            f"  Avg latency      : {s2['summary']['avg_latency_ms']} ms",
            f"  Guardrail failures: {s2['summary']['turns_with_guardrail_failure']}",
            "",
            "── SEC 2  PER-TURN LOG ──────────────────────────────────────────────",
        ]
        for t in s2["turns"]:
            lines.append(f"")
            lines.append(f"  Turn {t['turn']}  [{t['turn_id'][:16]}...]")
            lines.append(f"    Timestamp (req) : {t['timing']['request_utc_ms']} ms UTC")
            lines.append(f"    Latency         : {t['timing']['latency_ms']} ms")
            lines.append(f"    Model           : {t['model']['model_id']} ({t['model']['model_version']})")
            lines.append(f"    Tokens          : {t['tokens']['input']} in / {t['tokens']['output']} out")
            lines.append(f"    Input hash      : {t['user_input']['hash_sha256'][:32]}...")
            lines.append(f"    Output hash     : {t['assistant_output']['hash_sha256'][:32]}...")
            lines.append(f"    Topic           : {t['user_input'].get('topic_classified','—')}")
            lines.append(f"    Response type   : {', '.join(t['assistant_output'].get('response_types',['—']))}")
            lines.append(f"    Turn risk       : {t.get('turn_risk_summary','—')}")
            lines.append(f"    Guardrail       : {'✅ PASS' if t['guardrail_passed'] else '⚠ FAIL — '+str(t['guardrail_rules_failed'])}")
            pii_o = t['assistant_output'].get('pii_detected', [])
            lines.append(f"    PII in output   : {pii_o if pii_o else 'NONE ✅'}")
            if "bias_check" in t:
                b = t["bias_check"]
                lines.append(f"    Bias risk       : {b['overall_risk']}  (auto-bias:{b['automation_bias_risk']} | disclaimer:{b['human_disclaimer_present']})")
            if "consumer_protection" in t:
                cp = t["consumer_protection"]
                lines.append(f"    AI disclosed    : {'✅' if cp['ai_identity_disclosed'] else '⚠ NOT DETECTED'}")
                lines.append(f"    Human escalation: {'✅' if cp['human_escalation_mentioned'] else '⚠ NOT MENTIONED'}")

        lines += [
            "",
            "── SEC 3  EXPLAINABILITY                         [RBI FREE-AI Rec 18]─",
        ]
        s3 = self._section_3_explainability()
        lines.append(f"  Status : {s3['compliance_status']}")
        for e in s3["turns"]:
            lines.append(f"  Turn {e['turn']}  Clause: {e['policy_clause']}")
            lines.append(f"         Summary: {(e['human_readable_summary'] or '⚠ MISSING')[:80]}")

        lines += [
            "",
            "── SEC 4  GUARDRAIL LOG ─────────────────────────────────────────────",
            f"  Checks run : {s4['summary']['total_checks']}",
            f"  Failures   : {s4['summary']['total_failures']}",
            f"  Status     : {s4['summary']['overall_status']}",
        ]
        if s4["checks"]:
            for check in s4["checks"]:
                if check["guardrail_triggered"]:
                    lines.append(f"  ⚠ Rules failed: {check['rules_failed']}")

        lines += [
            "",
            "── SEC 5  CHAIN INTEGRITY                    [RBI FREE-AI Pillar 6]──",
            f"  {s5['status']}",
            f"  Total events : {s5['total_events']}",
            f"  Algorithm    : {s5['algorithm']}",
            "",
            "── SEC 6  DPDP COMPLIANCE                        [DPDP Act 2023]──────",
            f"  Consent ref       : {s6['consent']['consent_ref']}",
            f"  Consent status    : {s6['consent']['status']}",
            f"  PII masking       : {'✅ ENABLED' if s6['data_minimisation']['pii_masking_enabled'] else '⚠ DISABLED'}",
            f"  Raw content stored: {'No ✅' if not s6['data_minimisation']['raw_user_content_stored'] else '⚠ YES'}",
            f"  PII in output     : {s6['pii_in_output']['status']}",
            f"  Retention days    : {s6['audit_retention']['configured_days']} ({'✅ compliant' if s6['audit_retention']['compliant'] else '⚠ BELOW MINIMUM 1825 days'})",
            "",
            "── SEC 7  RBI MRM MODEL CARD                     [RBI MRM 2026]───────",
            f"  Model          : {s7['model_card']['model_id']}",
            f"  Version        : {s7['model_card']['model_version']}",
            f"  Provider       : {s7['model_card']['provider']}",
            f"  Risk tier      : Tier {s7['model_card']['risk_tier']} ({s7['model_card']['risk_tier_label']})",
            f"  Intended use   : {s7['model_card']['intended_use']}",
            f"  Inventory ref  : {s7['model_card']['inventory_id'] or '⚠ NOT SET'}",
            f"  Inventory status: {s7['inventory_status']}",
            f"  Last validated : {s7['model_card']['last_validated_date'] or '⚠ NOT SET'}",
            f"  Kill switch    : {s7['kill_switch_status']}  (last tested: {s7['model_card']['kill_switch_last_tested'] or '⚠ NEVER'})",
            f"  Vendor audit rights: {'✅ YES' if s7['model_card']['vendor_audit_rights'] else '⚠ NOT IN CONTRACT'}",
            f"  Deployment env : {s7['model_card']['deployment_environment']}",
            f"  Overall status : {s7['overall_status']}",
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
