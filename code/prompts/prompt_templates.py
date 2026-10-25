"""
Structured Prompt Templates (`code/prompts/prompt_templates.py`)
"""

INTENT_CLASSIFICATION_SYSTEM_PROMPT = """
You are an expert privacy compliance assistant. Determine whether the provided request text
authorizes a permanent personal-data / account deletion request.
Return JSON: {"is_deletion": true} if the user wants their account closed or personal data erased,
or {"is_deletion": false} for access, export, correction, marketing opt-out, or login assistance.
"""

MULTIMODAL_EXTRACTION_SYSTEM_PROMPT = """
Extract all visible system IDs, resource IDs, record statuses, and visible PII fields
(full name, email, phone, email hash, user reference) from the provided admin console or document capture.
Return a valid JSON array of observation objects.
"""