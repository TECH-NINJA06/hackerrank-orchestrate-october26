"""
Tier-2 Subagent 3: Adversarial Verifier & Canonical Step Compiler (`code/agents/verifier_subagent.py`)
Assembles findings, remediation, and verification steps in exact canonical order.
"""

from __future__ import annotations

from typing import Dict, List, Tuple
from config import AuditConfig
from schemas import ResourceObservation, StepObject


class AdversarialVerifierSubagent:
    """Compiles and sorts steps in strict phase, operation, system_id, and resource_id order."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config

    def compile_steps(
        self,
        findings: List[Tuple[str, str, str, str, str]],
        state_map: Dict[Tuple[str, str], ResourceObservation],
        is_complete_case: bool,
    ) -> List[StepObject]:
        steps: List[StepObject] = []
        step_no = 1

        if is_complete_case:
            # Include verification steps for compliant resources
            for (sys_id, rid), obs in sorted(state_map.items(), key=lambda x: (x[0][0], x[0][1])):
                op = "VERIFY_RECORD_ABSENT"
                st = "ABSENT"
                if obs.data_category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"} or obs.state == "PRESENT":
                    op = "VERIFY_RECORD_PRESENT"
                    st = "PRESENT"
                elif obs.state == "REDACTED" or obs.data_category == "ACCOUNT_TOMBSTONE":
                    op = "VERIFY_RECORD_REDACTED"
                    st = "REDACTED"
                elif obs.state == "ANONYMIZED" or obs.data_category == "ANALYTICS_PROFILE":
                    op = "VERIFY_RECORD_ANONYMIZED"
                    st = "ANONYMIZED"
                elif obs.state == "DISABLED":
                    op = "VERIFY_DATA_FLOW_DISABLED"
                    st = "DISABLED"
                elif obs.state == "BLOCKED":
                    op = "VERIFY_RESTORE_BLOCKED"
                    st = "BLOCKED"

                steps.append(
                    StepObject(
                        step_no=step_no,
                        phase="VERIFICATION",
                        system_id=sys_id,
                        resource_id=rid,
                        operation=op,
                        state=st,
                        evidence_id=obs.file_id or proven_evidence_id or "",
                    )
                )
                step_no += 1
            return steps

        # INCOMPLETE case: Findings -> Remediation -> Verification
        raw_findings = []
        for sys_id, rid, op, st, ev_id in findings:
            raw_findings.append({
                "phase": "FINDING",
                "system_id": sys_id,
                "resource_id": rid,
                "operation": op,
                "state": st,
                "evidence_id": ev_id,
            })

        raw_remediation = []
        for sys_id, rid, op, st, _ in findings:
            rem_op = "DELETE_RECORD"
            rem_st = "ABSENT"
            if "EXPOSED_PII" in op:
                obs = state_map.get((sys_id, rid))
                redact = bool(
                    obs
                    and obs.data_category
                    in {"ACCOUNT_TOMBSTONE", "SUPPORT_ATTACHMENT", "SUPPORT_MESSAGE"}
                )
                rem_op = "REDACT_RECORD" if redact else "ANONYMIZE_RECORD"
                rem_st = "REDACTED" if rem_op == "REDACT_RECORD" else "ANONYMIZED"
            elif "ACTIVE_DATA_FLOW" in op:
                rem_op = "DISABLE_DATA_FLOW"
                rem_st = "DISABLED"
            elif "RESTORE_RISK" in op:
                rem_op = "BLOCK_RESTORE"
                rem_st = "BLOCKED"

            raw_remediation.append({
                "phase": "REMEDIATION",
                "system_id": sys_id,
                "resource_id": rid,
                "operation": rem_op,
                "state": rem_st,
                "evidence_id": "",
            })

        raw_verification = []
        for sys_id, rid, op, st, _ in findings:
            ver_op = "VERIFY_RECORD_ABSENT"
            ver_st = "ABSENT"
            if "EXPOSED_PII" in op:
                ver_op = "VERIFY_RECORD_REDACTED" if "TOMBSTONE" in rid or "support" in sys_id else "VERIFY_RECORD_ANONYMIZED"
                ver_st = "REDACTED" if ver_op == "VERIFY_RECORD_REDACTED" else "ANONYMIZED"
            elif "ACTIVE_DATA_FLOW" in op:
                ver_op = "VERIFY_DATA_FLOW_DISABLED"
                ver_st = "DISABLED"
            elif "RESTORE_RISK" in op:
                ver_op = "VERIFY_RESTORE_BLOCKED"
                ver_st = "BLOCKED"

            raw_verification.append({
                "phase": "VERIFICATION",
                "system_id": sys_id,
                "resource_id": rid,
                "operation": ver_op,
                "state": ver_st,
                "evidence_id": "",
            })

        all_raw = raw_findings + raw_remediation + raw_verification
        all_raw.sort(
            key=lambda x: AuditConfig.step_sort_key(
                phase=x["phase"],
                operation=x["operation"],
                system_id=x["system_id"],
                resource_id=x["resource_id"],
            )
        )

        for item in all_raw:
            steps.append(
                StepObject(
                    step_no=step_no,
                    phase=item["phase"],
                    system_id=item["system_id"],
                    resource_id=item["resource_id"],
                    operation=item["operation"],
                    state=item["state"],
                    evidence_id=item["evidence_id"],
                )
            )
            step_no += 1

        return steps