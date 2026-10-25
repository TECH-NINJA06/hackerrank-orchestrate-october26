# Evaluation Report — Ghost Data Still Exists

## 1. Case-Level Status & Sequence Accuracy
- **Sample Dataset Evaluation**: Achieved **43.8%** exact-match accuracy (14/32 sample cases matched canonical outputs).
- **Step-Level and Field-Level Contract Accuracy**: All generated evaluation rows passed the output validator for allowed operations, valid states, evidence-ID rules, and consecutive numbering.
- **Sequence Accuracy**: All generated rows passed strict monotonic enforcement of `(phase_rank, operation_rank, system_id, resource_id)`. Exact canonical sequence accuracy is represented by the sample exact-match metric above.

## 2. Custom Adversarial Evaluation Test Cases
1. **Multi-Hop Identity Chain with Zombie Sync**: A user migrated across three email aliases before deletion while an active sync job recreated records in a secondary read replica; correctly resolved via transitive identity closure and temporal state reconstruction.
2. **Negated Non-Deletion Trap**: Request text included *"Please remove me from marketing lists only, do not close my account"* and was successfully gated to `NOT_APPLICABLE` with `[]`.
3. **Multimodal PDF Attachment Redaction Failure**: Support attachment containing exposed PII was correctly detected as `REPORT_EXPOSED_PII` and remediated with `REDACT_RECORD`.

## 3. Failures Found and Improvements Made
- **Failure**: Naive string matching on uppercase emails caused case-sensitive join mismatches against lowercase database records.
- **Improvement**: Implemented case-insensitive normalization and dual SHA-256 hash checks across all identity resolvers.
- **Failure**: Evidence bundles can contain unrelated users and identifier-free post-deletion records.
- **Improvement**: Added conservative timestamp filtering, evidence-backed absent-account reconstruction, policy-aware flow/backup handling, and decoy filtering without attributing shared bundle rows by file alone.
