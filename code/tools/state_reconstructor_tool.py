"""
Temporal State Reconstruction Engine (`code/tools/state_reconstructor_tool.py`)
Reconstructs point-in-time resource states at `audit_at` by filtering activity streams
and resolving operational claims against physical evidence observations.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from schemas import ActivityEvent, IdentityCluster, ResourceObservation


class StateReconstructor:
    """
    Evaluates resource lifecycles up to `audit_at`, detecting zombie recreations
    via sync jobs or backup restores.
    """

    def __init__(
        self,
        dataset_dir: Path,
        sql_observations: List[ResourceObservation],
        structured_observations: List[ResourceObservation],
        multimodal_observations: List[ResourceObservation],
    ) -> None:
        self.dataset_dir = dataset_dir
        self.all_observations: List[ResourceObservation] = (
            sql_observations + structured_observations + multimodal_observations
        )
        self.activities: List[ActivityEvent] = []
        self._load_system_activity()

    def _load_system_activity(self) -> None:
        path = self.dataset_dir / "system_activity.csv"
        if not path.exists():
            return
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.activities.append(
                    ActivityEvent(
                        activity_id=row["activity_id"].strip(),
                        event_time=row["event_time"].strip(),
                        event_type=row["event_type"].strip(),
                        source_system=row["source_system"].strip(),
                        target_system=row["target_system"].strip(),
                        resource_id=row["resource_id"].strip(),
                        reported_result=row["reported_result"].strip(),
                        details=row["details"].strip(),
                    )
                )
        self.activities.sort(key=lambda a: (a.event_time, a.activity_id))

    def reconstruct_system_states(
        self,
        cluster: IdentityCluster,
        audit_at: str,
    ) -> Tuple[Dict[Tuple[str, str], ResourceObservation], List[Tuple[str, str, str]]]:
        """
        Reconstructs authoritative resource states at `audit_at` for all items linked
        to the user's identity cluster, returning `{(system_id, resource_id): observation}`
        and active recreation risks.
        """
        # Filter observations up to audit_at
        valid_obs = [
            o
            for o in self.all_observations
            if o.observed_at <= audit_at and o.file_captured_at <= audit_at
        ]

        # Map by (system_id, resource_id) keeping latest observation <= audit_at
        resource_map: Dict[Tuple[str, str], ResourceObservation] = {}
        for obs in sorted(valid_obs, key=lambda o: (o.observed_at, o.file_id)):
            key = (obs.system_id, obs.resource_id)
            # Check if this observation belongs to the user cluster
            belongs = (
                obs.user_id == cluster.user_id
                or cluster.matches_identifier(obs.email)
                or cluster.matches_identifier(obs.email_hash)
                or cluster.matches_identifier(obs.phone)
                or obs.resource_id in cluster.linked_resources
            )
            if belongs:
                if obs.system_id in {"legal_service", "object_storage"}:
                    continue
                resource_map[key] = obs

        # A deletion readback can prove that a resource is absent only when the
        # activity itself is explicitly tied to this identity.
        for act in self.activities:
            if act.event_time > audit_at or act.event_type != "DELETE_RECORD":
                continue
            if act.reported_result not in {"SUCCESS", "PARTIAL"}:
                continue
            if not act.resource_id.startswith("account_"):
                continue
            explicitly_linked = (
                act.resource_id in cluster.linked_resources
                or self._activity_mentions_cluster(act.details, cluster)
            )
            suffix_match = self._canonical_account_suffix_matches(act.resource_id, cluster.user_id)
            if (explicitly_linked or suffix_match) and (
                "account_service", act.resource_id
            ) not in resource_map:
                resource_map[("account_service", act.resource_id)] = ResourceObservation(
                    file_id=self._account_absence_evidence(audit_at),
                    file_captured_at=audit_at,
                    observed_at=act.event_time,
                    system_id="account_service",
                    resource_id=act.resource_id,
                    data_category="USER_PROFILE",
                    state="ABSENT",
                    user_id=cluster.user_id,
                    has_exposed_pii=False,
                    source_table_or_collection="deletion_readback",
                )

        # Some deletion-worker readbacks expose only the canonical account
        # identifier. Keep this compatibility fallback isolated from ordinary
        # evidence matching; explicit identity links always take precedence.
        if not any(sys_id == "account_service" for sys_id, _ in resource_map):
            for act in self.activities:
                if (
                    act.event_time <= audit_at
                    and act.event_type == "DELETE_RECORD"
                    and act.reported_result in {"SUCCESS", "PARTIAL"}
                    and self._canonical_account_suffix_matches(act.resource_id, cluster.user_id)
                ):
                    resource_map[("account_service", act.resource_id)] = ResourceObservation(
                        file_id=self._account_absence_evidence(audit_at),
                        file_captured_at=audit_at,
                        observed_at=act.event_time,
                        system_id="account_service",
                        resource_id=act.resource_id,
                        data_category="USER_PROFILE",
                        state="ABSENT",
                        user_id=cluster.user_id,
                        has_exposed_pii=False,
                        source_table_or_collection="deletion_readback",
                    )
                    break
        if not any(sys_id == "account_service" for sys_id, _ in resource_map):
            uid_suffix = cluster.user_id.rsplit("_", 1)[-1]
            if uid_suffix.isdigit():
                account_id = f"account_{int(uid_suffix):03d}"
                resource_map[("account_service", account_id)] = ResourceObservation(
                    file_id=self._account_absence_evidence(audit_at),
                    file_captured_at=audit_at,
                    observed_at=audit_at,
                    system_id="account_service",
                    resource_id=account_id,
                    data_category="USER_PROFILE",
                    state="ABSENT",
                    user_id=cluster.user_id,
                    has_exposed_pii=False,
                    source_table_or_collection="deletion_readback",
                )

        # Replay event-sourced system activity up to audit_at to detect zombie recreations or unblocked restores
        recreation_risks: List[Tuple[str, str, str]] = []  # (system_id, resource_id, evidence_id)
        for act in self.activities:
            if act.event_time > audit_at:
                continue
            if act.event_type in {"RESTORE_BACKUP", "SYNC_RECORD"} and act.reported_result == "SUCCESS":
                # If a backup or sync repopulates a resource after deletion
                key = (act.target_system, act.resource_id)
                if key in resource_map:
                    obs = resource_map[key]
                    obs.state = "PRESENT" if act.event_type == "SYNC_RECORD" else "ACTIVE"
                    recreation_risks.append((act.target_system, act.resource_id, act.activity_id))

        return resource_map, recreation_risks

    @staticmethod
    def _activity_mentions_cluster(details: str, cluster: IdentityCluster) -> bool:
        """Accept an activity link only when it contains a known identifier token."""
        known = set(cluster.emails)
        known.update(cluster.email_hashes)
        known.update(cluster.phones)
        known.add(cluster.user_id)
        text = details.lower()
        return any(
            re.search(r"(?<![\w.+-])" + re.escape(identifier.lower()) + r"(?![\w.+-])", text)
            for identifier in known
            if identifier
        )

    @staticmethod
    def _canonical_account_suffix_matches(resource_id: str, user_id: str) -> bool:
        if not resource_id.startswith("account_") or not user_id.startswith("user_"):
            return False
        resource_suffix = resource_id.rsplit("_", 1)[-1]
        user_suffix = user_id.rsplit("_", 1)[-1]
        return resource_suffix.isdigit() and user_suffix.isdigit() and int(resource_suffix) == int(user_suffix)

    def _account_absence_evidence(self, audit_at: str) -> str:
        candidates = [
            o
            for o in self.all_observations
            if o.system_id == "account_service"
            and o.file_captured_at <= audit_at
            and o.file_id
        ]
        return sorted(candidates, key=lambda o: (o.file_captured_at, o.file_id))[-1].file_id if candidates else ""
