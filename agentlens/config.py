"""
AgentLens Configuration
-----------------------
Entity-level configuration binding AgentLens to the correct
regulatory framework for the deploying institution.

RBI FREE-AI Pillar: Governance
Requirement: Board-approved AI policy; entity classification
             determines applicable obligations.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class EntityType(str, Enum):
    """Regulated entity types across supported jurisdictions."""
    SCB = "Scheduled_Commercial_Bank"             # RBI jurisdiction
    NBFC = "NBFC"                                 # RBI jurisdiction
    PAYMENT_OPERATOR = "Payment_System_Operator"  # RBI jurisdiction
    FINTECH = "Fintech"                           # RBI jurisdiction
    SECURITIES_BROKER = "Securities_Broker"       # SEBI jurisdiction
    ASSET_MANAGER = "Asset_Manager"               # SEBI jurisdiction
    INSURER = "Insurer"                           # IRDAI jurisdiction
    HOSPITAL = "Hospital"                         # DISHA / NHA jurisdiction
    OTHER = "Other"


class RegulatoryFramework(str, Enum):
    """Supported Indian regulatory frameworks."""
    RBI_FREE_AI = "RBI_FREE_AI_AUG2025"
    RBI_MRM_2026 = "RBI_Model_Risk_Mgmt_JUNE2026"
    RBI_DATA_LOCALIZATION = "RBI_Data_Localization_APR2018"
    SEBI_AIML_2025 = "SEBI_AIML_Guidelines_JUNE2025"
    DPDP_2023 = "DPDP_Act_2023"
    IRDAI_AI = "IRDAI_AI_Governance"
    DISHA_HEALTH = "DISHA_ABDM_Health_Data"
    MEITY_INDIAAI = "MeitY_IndiaAI_Governance_Guidelines"


@dataclass
class AgentLensConfig:
    """
    Configuration for an AgentLens deployment.

    Maps to RBI FREE-AI Pillar 4 (Governance):
    Board-Approved AI Policy must specify:
      - Entity name and classification
      - Applicable regulatory frameworks
      - Model risk tier assignment
      - Audit retention period (RBI: minimum 5 years for BFSI)
    """
    entity_name: str
    entity_type: EntityType = EntityType.OTHER
    regulatory_frameworks: List[RegulatoryFramework] = field(
        default_factory=lambda: [RegulatoryFramework.RBI_FREE_AI]
    )
    # Board policy reference — RBI FREE-AI Pillar 4, Recommendation 14
    board_policy_ref: Optional[str] = None
    # Audit retention in days (RBI mandates minimum 5 years = 1825 days)
    audit_retention_days: int = 1825
    # Whether to mask PII in audit logs (DPDP Act 2023 compliance)
    pii_masking_enabled: bool = True
    # Whether to enable OTEL export
    otel_export_enabled: bool = False
    otel_endpoint: Optional[str] = None
    # Model risk tier — RBI MRM June 2026
    # Tier 1: High-risk (credit, fraud, AML), Tier 2: Medium, Tier 3: Low
    default_model_risk_tier: int = 2
    # Named AI Officer — required by SEBI AI/ML 2025 and RBI FREE-AI Governance Pillar
    ai_officer_name: Optional[str] = None
    ai_officer_email: Optional[str] = None
    # Internal model inventory reference — RBI MRM 2026
    model_inventory_ref: Optional[str] = None

    def is_rbi_regulated(self) -> bool:
        return self.entity_type in [
            EntityType.SCB, EntityType.NBFC,
            EntityType.PAYMENT_OPERATOR, EntityType.FINTECH
        ]

    def is_sebi_regulated(self) -> bool:
        return self.entity_type in [
            EntityType.SECURITIES_BROKER, EntityType.ASSET_MANAGER
        ]

    def is_irdai_regulated(self) -> bool:
        """IRDAI jurisdiction — insurers and insurance intermediaries."""
        return self.entity_type == EntityType.INSURER

    def is_health_regulated(self) -> bool:
        """DISHA / ABDM / NHA jurisdiction — health data fiduciaries."""
        return self.entity_type == EntityType.HOSPITAL

    def requires_board_policy(self) -> bool:
        """RBI FREE-AI: All REs must have board-approved AI policy.

        IRDAI and SEBI also expect a named-officer-owned AI governance
        policy for covered entities.
        """
        return (
            self.is_rbi_regulated()
            or self.is_sebi_regulated()
            or self.is_irdai_regulated()
        )

    def __post_init__(self):
        if self.requires_board_policy() and not self.board_policy_ref:
            import warnings
            warnings.warn(
                f"[AgentLens] RBI FREE-AI requires a board-approved AI policy "
                f"for {self.entity_type.value}. Set board_policy_ref to your "
                f"policy document reference (e.g. 'AI_POLICY_v1.0_BOARD_APR2026').",
                stacklevel=2,
            )
