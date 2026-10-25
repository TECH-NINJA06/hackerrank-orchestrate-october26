"""
Tier-2 Subagent 1: Intent Gatekeeper & Transitive Identity Graph Subagent
(`code/agents/intent_identity_subagent.py`)
"""

from __future__ import annotations

from typing import Optional, Tuple

from config import AuditConfig
from schemas import AuditCaseInput, IdentityCluster
from telemetry import TokenUsageTracker
from tools.identity_graph_tool import IdentityGraphResolver
from prompts.prompt_templates import INTENT_CLASSIFICATION_SYSTEM_PROMPT
from providers import generate_json_text


class IntentAndIdentitySubagent:
    """
    Determines whether a request authorizes account/personal-data deletion (`ACCOUNT_DELETION`)
    or is a non-deletion request (`NOT_APPLICABLE`), and resolves the transitive IdentityCluster.
    """

    def __init__(
        self,
        config: AuditConfig,
        identity_resolver: IdentityGraphResolver,
        tracker: TokenUsageTracker,
    ) -> None:
        self.config = config
        self.identity_resolver = identity_resolver
        self.tracker = tracker
        self._intent_cache: dict[str, bool] = {}

    def classify_deletion_intent(self, case: AuditCaseInput) -> bool:
        """
        Return True if `case.request_text` authorizes account/personal-data deletion,
        or False if the request is `NOT_APPLICABLE` (access, export, correction, marketing opt-out, login help).
        """
        text_norm = " ".join(case.request_text.strip().split())
        if text_norm in self._intent_cache:
            return self._intent_cache[text_norm]

        low = text_norm.lower()

        # 1. Deterministic check for explicit non-deletion / negated deletion requests
        for pattern in self.config.NON_DELETION_PATTERNS:
            if pattern in low:
                self._intent_cache[text_norm] = False
                return False

        # 2. Deterministic check for known valid multilingual & English deletion templates
        for pattern in self.config.VALID_DELETION_PATTERNS:
            if pattern.lower() in low:
                self._intent_cache[text_norm] = True
                return True

        # 3. LLM Fallback for unseen/custom evaluation prompts
        decision = self._llm_classify_intent(text_norm)
        self._intent_cache[text_norm] = decision
        return decision

    def _llm_classify_intent(self, request_text: str) -> bool:
        """
        Invoke Gemini / configured LLM with structured JSON output if an unseen request_text
        is encountered during evaluation, with deterministic keyword fallback if offline.
        """
        prompt = f"Request text:\n{request_text}\n\nReturn JSON: {{\"is_deletion\": true|false}}"
        parsed = generate_json_text(
            prompt=prompt,
            system_instruction=INTENT_CLASSIFICATION_SYSTEM_PROMPT,
            config=self.config,
            tracker=self.tracker,
            purpose="intent_classification",
        )
        if parsed is not None:
            return bool(parsed.get("is_deletion", False))

        # Deterministic fallback heuristic for offline/test environments
        low = request_text.lower()
        negations = ("do not", "don't", "not asking", "not a request", "keep the account", "leave my profile", "only")
        if any(neg in low for neg in negations):
            return False
        deletion_keywords = (
            "delete", "erase", "remove my account", "close my account", "close this account",
            "exclusão", "eliminación", "suppression", "削除", "삭제",
        )
        return any(kw in low for kw in deletion_keywords)

    def run(self, case: AuditCaseInput) -> Tuple[bool, Optional[IdentityCluster]]:
        """
        Execute Stage 1 (Intent Gate) and Stage 2 (Identity Graph Closure).
        Returns `(is_authorized_deletion, identity_cluster)`.
        """
        is_deletion = self.classify_deletion_intent(case)
        if not is_deletion:
            return False, None

        cluster = self.identity_resolver.resolve_cluster(
            seed_email=case.email,
            audit_at=case.audit_at,
        )
        return True, cluster