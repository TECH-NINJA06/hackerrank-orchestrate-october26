"""
Policy Evaluator & Step Compiler (`code/agents/temporal_policy_subagent.py`, `verifier_subagent.py`)
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import AuditConfig
from schemas import DeletionRule, IdentityCluster, ResourceObservation, StepObject


class TemporalAndPolicySubagent:
    """Evaluates reconstructed resource states against `deletion_rules.csv`."""

    def __init__(self, dataset_dir: Path) -> None:
        self.rules: List[DeletionRule] = []
        self._load_rules(dataset_dir)

    def _load_rules(self, dataset_dir: Path) -> None:
        path = dataset_dir / "deletion_rules.csv"
        if not path.exists():
            return
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.rules.append(
                    DeletionRule(
                        rule_id=row["rule_id"].strip(),
                        data_category=row["data_category"].strip(),
                        condition=row["condition"].strip(),
                        required_action=row["required_action"].strip(),
                    )
                )

    def evaluate_case(
        self,
        cluster: IdentityCluster,
        resource_map: Dict[Tuple[str, str], ResourceObservation],
        recreation_risks: List[Tuple[str, str, str]],
    ) -> List[StepObject]:
        """Generate findings and remediation steps when data remains or risks exist."""
        steps: List[StepObject] = []

        # 1. Evaluate resource violations
        for (sys_id, rid), obs in sorted(resource_map.items(), key=lambda x: (x[0][0], x[0][1])):
            action = self._determine_required_action(obs.data_category)
            if obs.data_category == "DATA_FLOW" and obs.state == "ACTIVE":
                steps.append(
                    StepObject(0, "FINDING", sys_id, rid, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", obs.file_id)
                )
                steps.append(
                    StepObject(0, "REMEDIATION", sys_id, rid, "DISABLE_DATA_FLOW", "DISABLED", "")
                )
                continue
            if obs.data_category == "BACKUP_ARCHIVE" and obs.state == "ACTIVE":
                steps.append(
                    StepObject(0, "FINDING", sys_id, rid, "REPORT_RESTORE_RISK", "ACTIVE", obs.file_id)
                )
                steps.append(
                    StepObject(0, "REMEDIATION", sys_id, rid, "BLOCK_RESTORE", "BLOCKED", "")
                )
                continue
            if action is None:
                continue

            if action == "DELETE" and obs.state != "ABSENT":
                if obs.has_exposed_pii:
                    if not obs.file_id:
                        continue
                    steps.append(
                        StepObject(
                            step_no=0,
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=rid,
                            operation="REPORT_REMAINING_RECORD",
                            state="PRESENT",
                            evidence_id=obs.file_id,
                        )
                    )
                    steps.append(
                        StepObject(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=rid,
                            operation="DELETE_RECORD",
                            state="ABSENT",
                            evidence_id="",
                        )
                    )
            elif action == "REDACT" and obs.state != "REDACTED":
                if obs.has_exposed_pii:
                    if not obs.file_id:
                        continue
                    steps.append(
                        StepObject(
                            step_no=0,
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=rid,
                            operation="REPORT_EXPOSED_PII",
                            state="PRESENT",
                            evidence_id=obs.file_id,
                        )
                    )
                    steps.append(
                        StepObject(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=rid,
                            operation="REDACT_RECORD",
                            state="REDACTED",
                            evidence_id="",
                        )
                    )
            elif action == "ANONYMIZE" and obs.state != "ANONYMIZED":
                if obs.has_exposed_pii:
                    if not obs.file_id:
                        continue
                    steps.append(
                        StepObject(
                            step_no=0,
                            phase="FINDING",
                            system_id=sys_id,
                            resource_id=rid,
                            operation="REPORT_EXPOSED_PII",
                            state="PRESENT",
                            evidence_id=obs.file_id,
                        )
                    )
                    steps.append(
                        StepObject(
                            step_no=0,
                            phase="REMEDIATION",
                            system_id=sys_id,
                            resource_id=rid,
                            operation="ANONYMIZE_RECORD",
                            state="ANONYMIZED",
                            evidence_id="",
                        )
                    )
            elif action == "RETAIN" and sys_id == "backup_service" and obs.state == "ACTIVE":
                if not obs.file_id:
                    continue
                steps.append(
                    StepObject(
                        step_no=0,
                        phase="FINDING",
                        system_id=sys_id,
                        resource_id=rid,
                        operation="REPORT_RESTORE_RISK",
                        state="ACTIVE",
                        evidence_id=obs.file_id,
                    )
                )
                steps.append(
                    StepObject(
                        step_no=0,
                        phase="REMEDIATION",
                        system_id=sys_id,
                        resource_id=rid,
                        operation="BLOCK_RESTORE",
                        state="BLOCKED",
                        evidence_id="",
                    )
                )

        # 2. Evaluate active data flows / sync risks
        for rid, sys_id in sorted(cluster.linked_resources.items()):
            if sys_id == "integration_service":
                linked_observation = resource_map.get((sys_id, rid))
                if linked_observation is None or not linked_observation.file_id:
                    continue
                steps.append(
                    StepObject(
                        step_no=0,
                        phase="FINDING",
                        system_id=sys_id,
                        resource_id=rid,
                        operation="REPORT_ACTIVE_DATA_FLOW",
                        state="ACTIVE",
                        evidence_id=linked_observation.file_id,
                    )
                )
                steps.append(
                    StepObject(
                        step_no=0,
                        phase="REMEDIATION",
                        system_id=sys_id,
                        resource_id=rid,
                        operation="DISABLE_DATA_FLOW",
                        state="DISABLED",
                        evidence_id="",
                    )
                )

        for sys_id, rid, ev_id in recreation_risks:
            steps.append(
                StepObject(
                    step_no=0,
                    phase="FINDING",
                    system_id=sys_id,
                    resource_id=rid,
                    operation="REPORT_RESTORE_RISK",
                    state="ACTIVE",
                    evidence_id=ev_id,
                )
            )
            steps.append(
                StepObject(
                    step_no=0,
                    phase="REMEDIATION",
                    system_id=sys_id,
                    resource_id=rid,
                    operation="BLOCK_RESTORE",
                    state="BLOCKED",
                    evidence_id="",
                )
            )

        return steps

    def _determine_required_action(self, data_category: str) -> Optional[str]:
        for r in self.rules:
            if r.data_category == data_category:
                if "delete" in r.required_action.lower():
                    return "DELETE"
                if "redact" in r.required_action.lower():
                    return "REDACT"
                if "anonymize" in r.required_action.lower():
                    return "ANONYMIZE"
        return None


class VerifierSubagent:
    """Compiles post-remediation verification checks and canonical step sorts."""

    def compile_final_steps(
        self,
        findings_and_remediations: List[StepObject],
        resource_map: Dict[Tuple[str, str], ResourceObservation],
        is_complete: bool,
        proven_evidence_id: Optional[str],
    ) -> List[StepObject]:
        """
        Assemble final ordered steps:
        - COMPLETE cases: only VERIFICATION steps citing proving evidence.
        - INCOMPLETE cases: FINDING + REMEDIATION + post-remediation VERIFICATION (evidence_id="" for proposed work).
        """
        raw_steps: List[StepObject] = []

        if is_complete:
            # Emit verification steps proving current compliant state
            seen_res: Set[Tuple[str, str]] = set()
            for (sys_id, rid), obs in sorted(resource_map.items()):
                if (sys_id, rid) in seen_res:
                    continue
                seen_res.add((sys_id, rid))
                op = "VERIFY_RECORD_ABSENT"
                st = "ABSENT"
                if obs.data_category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
                    op = "VERIFY_RECORD_PRESENT"
                    st = "PRESENT"
                elif obs.data_category == "ACCOUNT_TOMBSTONE":
                    op = "VERIFY_RECORD_REDACTED"
                    st = "REDACTED"
                elif obs.state == "ANONYMIZED":
                    op = "VERIFY_RECORD_ANONYMIZED"
                    st = "ANONYMIZED"

                raw_steps.append(
                    StepObject(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=rid,
                        operation=op,
                        state=st,
                        evidence_id=obs.file_id or proven_evidence_id or "",
                    )
                )
        else:
            # Include findings and remediations
            raw_steps.extend(findings_and_remediations)

            # Add corresponding verification checks for every remediation
            remediated_keys: Set[Tuple[str, str, str]] = set()
            for step in findings_and_remediations:
                if step.phase == "REMEDIATION":
                    key = (step.system_id, step.resource_id, step.operation)
                    if key in remediated_keys:
                        continue
                    remediated_keys.add(key)

                    v_op, v_st = "VERIFY_RECORD_ABSENT", "ABSENT"
                    if step.operation == "REDACT_RECORD":
                        v_op, v_st = "VERIFY_RECORD_REDACTED", "REDACTED"
                    elif step.operation == "ANONYMIZE_RECORD":
                        v_op, v_st = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
                    elif step.operation == "DISABLE_DATA_FLOW":
                        v_op, v_st = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
                    elif step.operation == "BLOCK_RESTORE":
                        v_op, v_st = "VERIFY_RESTORE_BLOCKED", "BLOCKED"

                    raw_steps.append(
                        StepObject(
                            step_no=0,
                            phase="VERIFICATION",
                            system_id=step.system_id,
                            resource_id=step.resource_id,
                            operation=v_op,
                            state=v_st,
                            evidence_id="",
                        )
                    )

            remediated_resources = {
                (step.system_id, step.resource_id)
                for step in findings_and_remediations
                if step.phase == "REMEDIATION"
            }
            for (sys_id, rid), obs in sorted(resource_map.items()):
                if (sys_id, rid) in remediated_resources:
                    continue
                verification = self._verification_for_observation(obs)
                if verification is None:
                    continue
                operation, state = verification
                raw_steps.append(
                    StepObject(
                        step_no=0,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=rid,
                        operation=operation,
                        state=state,
                        evidence_id="",
                    )
                )

        # Canonical sort by (phase_rank, operation_rank, system_id, resource_id)
        raw_steps.sort(
            key=lambda s: AuditConfig.step_sort_key(
                phase=s.phase,
                operation=s.operation,
                system_id=s.system_id,
                resource_id=s.resource_id,
            )
        )

        # Assign consecutive step numbers starting at 1
        for idx, s in enumerate(raw_steps, start=1):
            s.step_no = idx

        return raw_steps

    @staticmethod
    def _verification_for_observation(
        obs: ResourceObservation,
    ) -> Optional[Tuple[str, str]]:
        if obs.data_category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
            return "VERIFY_RECORD_PRESENT", "PRESENT"
        if obs.state == "ABSENT":
            return "VERIFY_RECORD_ABSENT", "ABSENT"
        if obs.state == "REDACTED" or obs.data_category == "ACCOUNT_TOMBSTONE":
            return "VERIFY_RECORD_REDACTED", "REDACTED"
        if obs.state == "ANONYMIZED":
            return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
        if obs.state == "DISABLED":
            return "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
        if obs.state == "BLOCKED":
            return "VERIFY_RESTORE_BLOCKED", "BLOCKED"
        return None