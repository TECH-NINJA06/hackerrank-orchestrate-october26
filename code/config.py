"""
Configuration, Allowed Operations Contract, Canonical Step Sorting, and Policy Constants.
HackerRank Orchestrate (October 2026) — Ghost Data Still Exists
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Set, Tuple


@dataclass
class AuditConfig:
    """Central configuration and invariant definitions for the Deletion Audit Agent."""

    repo_root: Path
    dataset_dir: Path
    output_csv_path: Path
    eval_report_path: Path
    usage_report_path: Path

    # Model & Provider configuration (read from environment variables; no secrets in code)
    llm_provider: str = field(
        default_factory=lambda: os.environ.get("AUDIT_LLM_PROVIDER", "google-genai")
    )
    vlm_model_name: str = field(
        default_factory=lambda: os.environ.get("AUDIT_VLM_MODEL", "gemini-2.5-flash")
    )
    intent_model_name: str = field(
        default_factory=lambda: os.environ.get("AUDIT_INTENT_MODEL", "gemini-2.5-flash")
    )

    # Token pricing (USD per 1M tokens) for `code/evaluation/usage_report.md`
    MODEL_PRICING_PER_1M: Dict[str, Tuple[float, float]] = field(
        default_factory=lambda: {
            "gemini-2.5-flash": (0.15, 0.60),
            "gemini-2.5-pro": (1.25, 10.00),
            "gpt-4o-mini": (0.15, 0.60),
            "claude-3-5-sonnet": (3.00, 15.00),
        }
    )

    # Phase Ordering: FINDING (1) -> REMEDIATION (2) -> VERIFICATION (3)
    PHASE_RANKS: Dict[str, int] = field(
        default_factory=lambda: {
            "FINDING": 1,
            "REMEDIATION": 2,
            "VERIFICATION": 3,
        }
    )

    # Operation Ordering within each phase (matches the Allowed Operations table in problem_statement.md)
    OPERATION_RANKS: Dict[Tuple[str, str], int] = field(
        default_factory=lambda: {
            # FINDING operations
            ("FINDING", "REPORT_REMAINING_RECORD"): 1,
            ("FINDING", "REPORT_EXPOSED_PII"): 2,
            ("FINDING", "REPORT_ACTIVE_DATA_FLOW"): 3,
            ("FINDING", "REPORT_RESTORE_RISK"): 4,
            # REMEDIATION operations
            ("REMEDIATION", "DISABLE_DATA_FLOW"): 1,
            ("REMEDIATION", "BLOCK_RESTORE"): 2,
            ("REMEDIATION", "DELETE_RECORD"): 3,
            ("REMEDIATION", "REDACT_RECORD"): 4,
            ("REMEDIATION", "ANONYMIZE_RECORD"): 5,
            # VERIFICATION operations
            ("VERIFICATION", "VERIFY_RECORD_ABSENT"): 1,
            ("VERIFICATION", "VERIFY_RECORD_PRESENT"): 2,
            ("VERIFICATION", "VERIFY_RECORD_REDACTED"): 3,
            ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED"): 4,
            ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED"): 5,
            ("VERIFICATION", "VERIFY_RESTORE_BLOCKED"): 6,
        }
    )

    # Allowed (phase, operation, state) triples per §6.4 of AGENTS.md
    ALLOWED_OPERATIONS: FrozenSet[Tuple[str, str, str]] = frozenset(
        {
            ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
            ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
            ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
            ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
            ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
            ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
            ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
            ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
            ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
            ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
            ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
            ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
            ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
            ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
            ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
        }
    )

    # Default data category per system_id / resource prefix
    SYSTEM_DEFAULT_CATEGORY: Dict[str, str] = field(
        default_factory=lambda: {
            "account_service": "USER_PROFILE",
            "search_service": "SEARCH_INDEX_ENTRY",
            "cache_service": "CACHE_ENTRY",
            "support_platform": "SUPPORT_MESSAGE",
            "object_storage": "SUPPORT_ATTACHMENT",
            "analytics_platform": "ANALYTICS_PROFILE",
            "export_service": "USER_EXPORT",
            "marketing_platform": "MARKETING_PROFILE",
            "email_delivery_service": "EMAIL_DELIVERY_LOG",
            "security_service": "SECURITY_AUDIT_LOG",
            "legal_service": "LEGAL_HOLD_RECORD",
            "backup_service": "BACKUP_ARCHIVE",
            "identity_service": "ACCOUNT_TOMBSTONE",
            "integration_service": "DATA_FLOW",
        }
    )

    # Non-deletion intent phrases / patterns (deterministic fast-path before LLM fallback)
    NON_DELETION_PATTERNS: Tuple[str, ...] = (
        "leave the account active",
        "not asking for deletion",
        "keep the account as it is",
        "do not close the account",
        "without removing any of my records",
        "remove me from marketing lists only",
        "not a request to erase it",
        "leave my profile and purchase history in place",
        "continue using the service",
        "don't delete or change anything",
        "do not delete",
    )

    # Valid multilingual & English deletion intent phrases
    VALID_DELETION_PATTERNS: Tuple[str, ...] = (
        "close my account and process the associated personal-data deletion",
        "account associated with this address to be erased",
        "close this account and have its associated personal data deleted",
        "permanent account-deletion request",
        "erase the account linked to this email address",
        "requesting deletion of the account registered to this email address",
        "request to delete this account and its personal data",
        "remove my account and the personal information linked to it",
        "permanently deleted",
        "request for permanent account deletion",
        "permanently delete the account associated with this email address",
        "begin the deletion process for the account",
        "exclusão permanente da conta",
        "アカウントの完全な削除を依頼します",
        "suppression définitive du compte",
        "계정의 영구 삭제를 요청합니다",
        "eliminación permanente de la cuenta",
        "haven’t used this account in years and would like it closed",
        "haven't used this account in years and would like it closed",
        "intenté eliminar mi cuenta",
        "deleting my account",
        "deleted this account and received a confirmation",
        "my account page is gone, but my old profile still appears",
        "delete my account and the identity document",
        "closed my account, but an old",
        "remove records linked to both the old and current addresses",
        "changed the email on this account before deleting it",
        "close the account completely",
        "want to close this account permanently",
        "remove my profile and clean my personal details",
        "deleted my account and received the confirmation email",
        "delete this account, including the downloadable archive",
        "told that deletion was complete, but the account",
        "whether the account and identifiable analytics data have already been removed",
        "confirm that the profile is gone and that remaining records cannot identify me",
        "audit the deletion as it stood when my request was reviewed",
        "verify that my account was deleted",
        "remove records under both addresses and switch off any integration",
        "told the account had been deleted, but i can still find traces",
        "no longer need this account. please remove my name and contact details",
        "the account itself is gone, but an internal deleted-account record still shows",
    )

    @classmethod
    def step_sort_key(
        cls,
        phase: str,
        operation: str,
        system_id: str,
        resource_id: str,
    ) -> Tuple[int, int, str, str]:
        """
        Canonical step sorting key per problem_statement.md & AGENTS.md §6.3:
        1. Phase order: FINDING -> REMEDIATION -> VERIFICATION
        2. Operation order: as listed in Allowed Operations table
        3. system_id ascending
        4. resource_id ascending
        """
        phase_map = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
        op_map = {
            ("FINDING", "REPORT_REMAINING_RECORD"): 1,
            ("FINDING", "REPORT_EXPOSED_PII"): 2,
            ("FINDING", "REPORT_ACTIVE_DATA_FLOW"): 3,
            ("FINDING", "REPORT_RESTORE_RISK"): 4,
            ("REMEDIATION", "DISABLE_DATA_FLOW"): 1,
            ("REMEDIATION", "BLOCK_RESTORE"): 2,
            ("REMEDIATION", "DELETE_RECORD"): 3,
            ("REMEDIATION", "REDACT_RECORD"): 4,
            ("REMEDIATION", "ANONYMIZE_RECORD"): 5,
            ("VERIFICATION", "VERIFY_RECORD_ABSENT"): 1,
            ("VERIFICATION", "VERIFY_RECORD_PRESENT"): 2,
            ("VERIFICATION", "VERIFY_RECORD_REDACTED"): 3,
            ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED"): 4,
            ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED"): 5,
            ("VERIFICATION", "VERIFY_RESTORE_BLOCKED"): 6,
        }
        return (
            phase_map.get(phase, 99),
            op_map.get((phase, operation), 99),
            system_id,
            resource_id,
        )