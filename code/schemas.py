"""
Typed Data Schemas for Cases, Identity Graph, Evidence Observations, Activity Events, and Output Steps.
HackerRank Orchestrate (October 2026) — Ghost Data Still Exists
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass(frozen=True)
class AuditCaseInput:
    """Represents one row from `deletion_requests.csv` or `sample_deletion_requests.csv`."""

    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str

    @property
    def normalized_email(self) -> str:
        return self.email.strip().lower()


@dataclass
class StepObject:
    """Represents a single finding, remediation action, or verification check in `steps_json`."""

    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str = ""

    def to_OrderedDict(self) -> OrderedDict[str, Any]:
        """Serialize with canonical key ordering matching problem_statement.md."""
        return OrderedDict(
            [
                ("step_no", self.step_no),
                ("phase", self.phase),
                ("system_id", self.system_id),
                ("resource_id", self.resource_id),
                ("operation", self.operation),
                ("state", self.state),
                ("evidence_id", self.evidence_id),
            ]
        )


@dataclass
class AuditCaseOutput:
    """Represents the final decision and ordered steps for one `case_id`."""

    case_id: str
    deletion_status: str  # "COMPLETE" | "INCOMPLETE" | "NOT_APPLICABLE"
    steps: List[StepObject] = field(default_factory=list)


@dataclass
class IdentityCluster:
    """All current and historical identifiers resolved for a single deletion subject."""

    user_id: str
    primary_name: Optional[str] = None
    emails: Set[str] = field(default_factory=set)          # lowercased emails
    raw_emails: Set[str] = field(default_factory=set)      # original case emails
    phones: Set[str] = field(default_factory=set)          # normalized & raw phone strings
    email_hashes: Set[str] = field(default_factory=set)    # lowercased SHA-256 hex strings
    names: Set[str] = field(default_factory=set)           # known full_name variants
    audit_ids: List[str] = field(default_factory=list)     # audit_id references from user_audit_log.csv
    linked_resources: Dict[str, str] = field(default_factory=dict)  # resource_id -> system_id from LINK_RESOURCE_IDENTITY

    def matches_identifier(self, candidate: Optional[str]) -> bool:
        """Return True if `candidate` matches any known identifier for this user (excluding `.jr@` decoys)."""
        if not candidate:
            return False
        val = str(candidate).strip()
        if not val or val.lower() == "null" or val.lower() == "no direct identifier":
            return False
        low = val.lower()
        if low == self.user_id.lower():
            return True
        if low in self.emails:
            return True
        if low in self.email_hashes:
            return True
        if val in self.phones or self._norm_phone(val) in {self._norm_phone(p) for p in self.phones}:
            return True
        return False

    @staticmethod
    def _norm_phone(phone: str) -> str:
        return "".join(ch for ch in phone if ch.isdigit() or ch == "+")


@dataclass
class ResourceObservation:
    """
    A single grounded observation of a resource inside an evidence artifact (`evidence_files.csv`).
    """

    file_id: str
    file_captured_at: str        # `captured_at` from evidence_files.csv
    observed_at: str             # specific record/snapshot timestamp (or file_captured_at)
    system_id: str               # e.g., 'account_service', 'search_service', 'analytics_platform'
    resource_id: str             # e.g., 'account_005', 'search_001', 'analytics_901'
    data_category: str           # e.g., 'USER_PROFILE', 'SEARCH_INDEX_ENTRY', 'SUPPORT_MESSAGE'
    state: str                   # 'PRESENT', 'ABSENT', 'REDACTED', 'ANONYMIZED', 'ACTIVE', 'DISABLED', 'BLOCKED'
    user_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    email_hash: Optional[str] = None
    full_name: Optional[str] = None
    has_exposed_pii: bool = False
    is_replica_only: bool = False
    source_table_or_collection: str = ""
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActivityEvent:
    """Represents one row from `dataset/system_activity.csv`."""

    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True)
class DeletionRule:
    """Represents one policy rule from `dataset/deletion_rules.csv`."""

    rule_id: str
    data_category: str
    condition: str
    required_action: str  # "DELETE" | "REDACT" | "ANONYMIZE" | "RETAIN"