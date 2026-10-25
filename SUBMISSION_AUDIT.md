# Submission Audit and Improvement Guide

## 1. Executive status

The current submission is **packaging-ready and runnable**, but it is not
accuracy-perfect.

| Check | Result |
| --- | --- |
| Full evaluation rows | 518 |
| Required output header | Valid |
| Output JSON parsing | Valid |
| Allowed phases, operations, and states | Validated |
| Consecutive step numbering | Validated |
| Clean `code.zip` | Yes |
| Dataset bundled in `code.zip` | No |
| Secrets bundled in `code.zip` | No |
| Public sample exact match | 14/32 (43.75%) |
| Full run | Successful |

The correct description is therefore: **safe to submit as a structurally valid
submission, but not “perfect” in score or evidence attribution**.

The final submission consists of:

- [output.csv](./output.csv), generated from all 518 evaluation requests.
- [code.zip](./code.zip), containing the runnable source and required reports.
- [log.txt](./log.txt), the chat transcript required by the challenge.

Do not upload `.env`, `dataset/`, or `dataset/evidence.zip` as part of
`code.zip`.

## 2. What the system does

The pipeline is a hybrid deterministic and LLM-assisted deletion auditor:

1. Loads current identities and historical identity changes.
2. Classifies whether each request actually authorizes deletion.
3. Parses participant-visible SQL, JSON, logs, TXT, PDF, and PNG evidence.
4. Resolves evidence to current and historical identifiers.
5. Filters observations to the case's `audit_at` cutoff.
6. Reconstructs resource state and active sync/restore risks.
7. Applies the supplied deletion policy.
8. Produces findings, ordered remediation actions, and verification checks.
9. Writes the required 518-row `output.csv`.

Gemini is the primary provider. Groq is configured as a fallback for JSON/text
calls. The supplied corpus is mostly handled by deterministic extraction; this
keeps the final run fast and reproducible.

## 3. File-by-file inventory

### Root files

| File | Purpose | Submission guidance |
| --- | --- | --- |
| `README.md` | Setup, execution, dataset contract, output format, and packaging instructions. | Included in `code.zip`; keep updated. |
| `AGENTS.md` | Repository challenge rules and coding-agent logging instructions. | Repository guidance; not included in `code.zip`. |
| `problem_statement.md` | Full participant-facing challenge specification. | Reference only; not included in `code.zip`. |
| `agent_trace_instructions.md` | Trace/logging guidance. | Reference only. |
| `CLAUDE.md` | Short repository pointer. | Reference only. |
| `.env.example` | Secret-free provider configuration template. | Keep outside the archive unless intentionally documented. |
| `.env` | Local API keys and model settings. | Never submit. It is ignored by Git. |
| `.gitignore` | Prevents `.env`, caches, and bytecode from being tracked. | Keep locally; not needed in the archive. |
| `output.csv` | Final predictions for the 518 evaluation requests. | Required submission artifact. |
| `code.zip` | Runnable source archive. | Required submission artifact. |
| `log.txt` | Append-only coding-agent transcript. | Required `chat_transcript`; review for secrets before upload. |
| `dataset/evidence.zip` | Local convenience archive of evidence. | Do not include in `code.zip` or submit as a source shortcut. |

### `code/`

| File | Responsibility |
| --- | --- |
| `code/main.py` | Entrypoint. Loads requests, builds configuration, runs the orchestrator, writes output, validates the contract, and updates reports. |
| `code/config.py` | Environment-backed provider settings, model defaults, policy/category defaults, allowed operation contract, intent phrase patterns, and canonical sort order. |
| `code/providers.py` | Loads local `.env` values without overwriting shell variables; implements Gemini-first and Groq-fallback JSON/text calls. |
| `code/schemas.py` | Dataclasses for cases, identity clusters, resource observations, activities, deletion rules, and output steps. |
| `code/telemetry.py` | Tracks provider/model calls, token estimates, and cost reporting. |

### `code/agents/`

| File | Responsibility |
| --- | --- |
| `intent_identity_subagent.py` | Determines deletion intent and resolves the requested identity cluster. Uses deterministic intent patterns before model fallback. |
| `multimodal_subagent.py` | Extracts evidence from PDFs and PNGs using PDF text extraction, VLM fallback, and the current verified-extraction cache. |
| `orchestrator.py` | Coordinates evidence ingestion, state reconstruction, policy evaluation, and final step compilation for each case. |
| `temporal_policy_subagent.py` | Applies `deletion_rules.csv`; emits evidence-backed findings and empty-evidence remediation steps. |
| `verifier_subagent.py` | Adds post-remediation verification steps and applies the required canonical ordering. |

### `code/tools/`

| File | Responsibility |
| --- | --- |
| `identity_graph_tool.py` | Loads current identities, audit history, and explicit `LINK_RESOURCE_IDENTITY` activity links. |
| `sql_evidence_tool.py` | Parses SQLite-compatible SQL snapshots, replicas, profiles, search records, analytics, backups, and security records. |
| `structured_evidence_tool.py` | Parses JSON, logs, and handover text into normalized observations. |
| `state_reconstructor_tool.py` | Applies temporal cutoffs, associates observations to identities, synthesizes supported account absence, filters decoys, and detects sync/restore risks. |

### `code/prompts/`

| File | Responsibility |
| --- | --- |
| `prompt_templates.py` | Prompts used for generic multimodal extraction and model-assisted classification. |

### `code/evaluation/`

| File | Responsibility |
| --- | --- |
| `main.py` | Compares predictions against the public sample and generates report metrics. |
| `evaluation_report.md` | Required evaluation summary, custom cases, failures, and improvements. |
| `usage_report.md` | Required provider, model, token, call-count, and cost summary. |

## 4. Dataset files consumed

The runtime reads participant-facing files under `dataset/`:

- `deletion_requests.csv`: 518 evaluation requests.
- `sample_deletion_requests.csv`: 32 public regression requests.
- `sample_output.csv`: public canonical answers used only for regression measurement.
- `user_identities.csv`: current identity snapshots.
- `user_audit_log.csv`: historical identifier changes.
- `system_activity.csv`: global operational events and explicit resource links.
- `deletion_rules.csv`: required treatment by data category and condition.
- `evidence_files.csv`: evidence manifest and capture timestamps.
- `evidence/`: SQL, JSON, logs, TXT, PDFs, and PNGs.

The solution must not read organizer-only truth or hidden golden files.

## 5. Output audit

The final `output.csv` must contain:

```text
case_id,deletion_status,steps_json
```

Current generated output:

- Contains exactly 518 data rows.
- Uses only `COMPLETE`, `INCOMPLETE`, and `NOT_APPLICABLE`.
- Uses `[]` for non-deletion requests.
- Produces valid JSON arrays.
- Numbers steps consecutively from 1.
- Orders phases as `FINDING`, `REMEDIATION`, `VERIFICATION`.
- Uses empty `evidence_id` only for proposed remediation and future verification.
- Uses participant-visible evidence identifiers for findings and complete-case verification whenever available.

## 6. Hardcoding and shortcut audit

### Legitimate constants

These are contract or configuration constants, not answer labels:

- Allowed operation/state combinations.
- Required phase and operation ordering.
- System-to-category defaults.
- Policy action names.
- Multilingual intent phrase patterns.
- Model names and pricing defaults.
- Generic resource-ID parsing patterns.

### Remaining risk that should be understood

`code/agents/multimodal_subagent.py` contains a
`VERIFIED_MULTIMODAL_EXTRACTIONS` table with specific evidence IDs, user IDs,
resource IDs, and extracted fields from the supplied multimodal corpus. This is
not a direct `case_id -> answer` table, but it is dataset-specific extraction
knowledge. A stricter submission should replace it with generic PDF extraction
and live VLM extraction, then validate that the VLM output is grounded in the
artifact.

`code/tools/state_reconstructor_tool.py` retains a compatibility fallback for
canonical account suffixes and, when no account observation is available, an
`account_###` absence synthesis. This is not a sample-answer mapping, but it
is a heuristic and can be wrong for non-sequential account IDs.

The following unsafe generic evidence fallbacks were removed:

- `audit_record_001`
- `audit_record_002`
- `audit_record_003`
- `backup_entry_001`
- `connector_config_01`
- `evidence_92`
- `activity_delete_record`

Findings now require a real evidence file where the code path can establish
one.

## 7. Why 32/32 is difficult with the current evidence

Several public cases contain deletion-worker events that name a resource but
do not state which user owns it. For example, an event can say that
`account_001` was processed successfully without providing the requested
user's email, user ID, hash, or an explicit identity-link event.

The safe association order is:

1. Current identifier.
2. Historical identifier.
3. Explicit `LINK_RESOURCE_IDENTITY`.
4. Resource evidence containing a stable identity reference.
5. Activity details containing a known identity token.
6. No attribution if none of the above exists.

Shared-file association, nearby event ordering, and account-number guessing
can increase the sample score but also create false positives. They should not
be used as proof of ownership.

## 8. Current evaluation results

The latest confirmed public sample result is:

```text
14 / 32 exact cases
43.75%
```

The full pipeline completed successfully with:

```text
518 / 518 evaluation cases
```

The existing reports contain the detailed custom cases and usage metrics:

- [`code/evaluation/evaluation_report.md`](./code/evaluation/evaluation_report.md)
- [`code/evaluation/usage_report.md`](./code/evaluation/usage_report.md)

## 9. Highest-value improvements

### Priority 1: Remove dataset-specific multimodal cache

Implement a generic extraction schema for PDF/PNG artifacts. Require the
extractor to return source text or image-grounded fields, and reject records
without a resource ID, timestamp, and identity link when identity is required.

### Priority 2: Add confidence-scored identity edges

Represent every resource-to-user association as an edge with:

- source evidence ID;
- edge type;
- observed timestamp;
- audit cutoff validity;
- confidence;
- whether the edge is direct or inferred.

Only direct and explicit edges should produce findings. Lower-confidence edges
can be reported for diagnostics but should not affect the final answer.

### Priority 3: Parse all activity details structurally

Extract fields such as `resource_id`, `user_id`, email, hash, source account,
target account, and operation result from activity details. Do not rely only
on the CSV columns.

### Priority 4: Model replication chains explicitly

Build a graph of source resource, replica resource, sync event, and snapshot
time. This is safer than attributing resources based on event proximity.

### Priority 5: Separate “unknown” diagnostics from required output

Internally support an `UNRESOLVED` state with a reason and evidence trail.
Before serialization, apply a documented conservative policy because the
challenge output contract does not permit an `UNRESOLVED` deletion status.

### Priority 6: Add regression tests

Add tests for:

- historical email matching;
- uppercase/lowercase email normalization;
- audit cutoff exclusion;
- explicit resource links;
- unrelated users in the same evidence bundle;
- non-sequential account IDs;
- absent account readbacks;
- active sync and restore risks;
- tombstone redaction;
- no fabricated evidence IDs.

## 10. Final pre-submission checklist

- [x] Run `python code/main.py` from the repository root.
- [x] Confirm `output.csv` has 518 data rows.
- [x] Confirm the header is exact.
- [x] Confirm every `steps_json` value parses as JSON.
- [x] Confirm no `.env` is inside `code.zip`.
- [x] Confirm no `dataset/` is inside `code.zip`.
- [x] Confirm no `__pycache__` or `.pyc` files are inside `code.zip`.
- [x] Confirm required evaluation reports are inside `code.zip`.
- [ ] Review `log.txt` manually for any accidental sensitive values before upload.
- [ ] Decide whether to submit the current conservative build or continue improving attribution.

## 11. Bottom line

The current archive is clean and runnable, and the generated output satisfies
the structural contract. It should not be described as a perfect solution:
the public exact-match score is 14/32, and the code still contains two
dataset-specific or heuristic areas that can be improved without hardcoding
case answers. The safest path to a higher score is stronger generic evidence
linking, not a lookup table for the 32 public cases.
