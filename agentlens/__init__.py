__version__ = "0.2.0"

from .tracer import AuditTracer, AgentSpan
from .config import AgentLensConfig
from .audit_log import AuditLog, AuditEvent, RiskTier, EventType
from .policy import (
    PolicyEngine, PolicyRule, PolicyCheckResult, PolicyAction,
    RBIPolicy, SEBIPolicy, DPDPPolicy, IRDAIPolicy, DISHAPolicy,
)
from .report import ComplianceReporter
from .chat_tracer import ChatSessionTracer, ModelCard, ConversationTurn
from .chat_policy import ChatPolicy, detect_pii, detect_pii_in_user_input
from .live_report import LiveSessionReport
from .chat_analytics import TurnAnalytics, analyse_turn
# Phase 0 additions
from .storage import (
    WORMStorageAdapter,
    LocalNDJSONAdapter,
    S3ObjectLockAdapter,
    AzureImmutableBlobAdapter,
    MultiAdapter,
)
from .pii_firewall import tokenize_pii, firewall_messages, PIIVault
from .compliance_db import ComplianceDatabase
from .otel import OTELExporter

__all__ = [
    # Core
    "AuditTracer",
    "AgentSpan",
    "AgentLensConfig",
    "AuditLog",
    "AuditEvent",
    "RiskTier",
    "EventType",
    # Policy
    "PolicyEngine",
    "PolicyRule",
    "PolicyCheckResult",
    "RBIPolicy",
    "SEBIPolicy",
    "DPDPPolicy",
    "IRDAIPolicy",
    "DISHAPolicy",
    "PolicyAction",
    # Reporting
    "ComplianceReporter",
    "LiveSessionReport",
    # Chat
    "ChatSessionTracer",
    "ModelCard",
    "ConversationTurn",
    "ChatPolicy",
    "detect_pii",
    "TurnAnalytics",
    "analyse_turn",
    # Phase 0: Storage
    "WORMStorageAdapter",
    "LocalNDJSONAdapter",
    "S3ObjectLockAdapter",
    "AzureImmutableBlobAdapter",
    "MultiAdapter",
    # Phase 0: PII Firewall
    "tokenize_pii",
    "firewall_messages",
    "PIIVault",
    # Phase 0: Compliance DB
    "ComplianceDatabase",
    # Phase 0: OTEL
    "OTELExporter",
]
