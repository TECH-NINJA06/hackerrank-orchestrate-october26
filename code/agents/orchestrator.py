"""
DeepAgents Supervisor / Orchestrator (`code/agents/orchestrator.py`, `telemetry.py`, `prompt_templates.py`)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List

from config import AuditConfig
from schemas import AuditCaseInput, AuditCaseOutput, ResourceObservation
from telemetry import TokenUsageTracker
from agents.intent_identity_subagent import IntentAndIdentitySubagent
from agents.multimodal_subagent import MultimodalForensicsSubagent
from agents.temporal_policy_subagent import TemporalAndPolicySubagent, VerifierSubagent
from tools.identity_graph_tool import IdentityGraphResolver
from tools.sql_evidence_tool import SqlEvidenceIngestor
from tools.structured_evidence_tool import StructuredEvidenceIngestor


class AuditOrchestrator:
    """Supervises corpus ingestion and coordinates subagents across all audit cases."""

    def __init__(self, config: AuditConfig, tracker: TokenUsageTracker) -> None:
        self.config = config
        self.tracker = tracker
        self.identity_resolver = IdentityGraphResolver(config.dataset_dir)
        self.sql_ingestor = SqlEvidenceIngestor(self.identity_resolver)
        self.structured_ingestor = StructuredEvidenceIngestor(self.identity_resolver, self.sql_ingestor)
        self.multimodal_subagent = MultimodalForensicsSubagent(config, self.identity_resolver, tracker)
        self.intent_identity_subagent = IntentAndIdentitySubagent(config, self.identity_resolver, tracker)
        self.policy_subagent = TemporalAndPolicySubagent(config.dataset_dir)
        self.verifier_subagent = VerifierSubagent()

        self.sql_observations: List[ResourceObservation] = []
        self.structured_observations: List[ResourceObservation] = []
        self.multimodal_observations: List[ResourceObservation] = []

    def ingest_corpus(self) -> None:
        """Tier-1 Ingestion: Process all 94 evidence files once."""
        evidence_manifest = self.config.dataset_dir / "evidence_files.csv"
        if not evidence_manifest.exists():
            return

        import csv
        with evidence_manifest.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                file_id = row["file_id"].strip()
                rel_path = row["file_path"].strip()
                captured_at = row["captured_at"].strip()
                fpath = self.config.dataset_dir / rel_path
                if not fpath.exists():
                    continue

                ext = fpath.suffix.lower()
                if ext == ".sql":
                    self.sql_observations.extend(
                        self.sql_ingestor.parse_sql_file(file_id, fpath, captured_at)
                    )
                elif ext == ".json":
                    self.structured_observations.extend(
                        self.structured_ingestor.parse_json_file(file_id, fpath, captured_at)
                    )
                elif ext == ".log":
                    self.structured_observations.extend(
                        self.structured_ingestor.parse_log_file(file_id, fpath, captured_at)
                    )
                elif ext == ".txt":
                    self.structured_observations.extend(
                        self.structured_ingestor.parse_handover_txt(file_id, fpath, captured_at)
                    )
                elif ext in {".pdf", ".png"}:
                    self.multimodal_observations.extend(
                        self.multimodal_subagent.parse_multimodal_file(file_id, fpath, captured_at)
                    )

    def audit_single_case(self, case: AuditCaseInput) -> AuditCaseOutput:
        """Run the audit pipeline for a single request."""
        is_deletion, cluster = self.intent_identity_subagent.run(case)
        if not is_deletion or cluster is None:
            return AuditCaseOutput(case_id=case.case_id, deletion_status="NOT_APPLICABLE", steps=[])

        from tools.state_reconstructor_tool import StateReconstructor
        reconstructor = StateReconstructor(
            dataset_dir=self.config.dataset_dir,
            sql_observations=self.sql_observations,
            structured_observations=self.structured_observations,
            multimodal_observations=self.multimodal_observations,
        )
        resource_map, recreation_risks = reconstructor.reconstruct_system_states(cluster, case.audit_at)

        findings_and_rems = self.policy_subagent.evaluate_case(cluster, resource_map, recreation_risks)
        is_complete = len(findings_and_rems) == 0

        proven_file_id = None
        for obs in resource_map.values():
            if obs.file_id:
                proven_file_id = obs.file_id
                break

        steps = self.verifier_subagent.compile_final_steps(
            findings_and_remediations=findings_and_rems,
            resource_map=resource_map,
            is_complete=is_complete,
            proven_evidence_id=proven_file_id,
        )

        status = "COMPLETE" if is_complete else "INCOMPLETE"
        return AuditCaseOutput(case_id=case.case_id, deletion_status=status, steps=steps)

    def audit_batch(self, cases: List[AuditCaseInput], is_evaluation_run: bool = False) -> List[AuditCaseOutput]:
        return [self.audit_single_case(c) for c in cases]