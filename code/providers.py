"""Provider helpers for Gemini-primary, Groq-fallback model calls."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional, Tuple

from config import AuditConfig
from telemetry import TokenUsageTracker


def load_local_env(repo_root: Path) -> None:
    """Load simple KEY=VALUE entries from a local .env without overwriting the shell."""
    env_path = repo_root / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


def generate_json_text(
    prompt: str,
    system_instruction: str,
    config: AuditConfig,
    tracker: TokenUsageTracker,
    purpose: str,
) -> Optional[dict[str, Any]]:
    """Call Gemini first, then Groq, returning a parsed JSON object when available."""
    gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if gemini_key:
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=gemini_key)
            response = client.models.generate_content(
                model=config.intent_model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    temperature=0.0,
                    response_mime_type="application/json",
                ),
            )
            usage = getattr(response, "usage_metadata", None)
            tracker.record_call(
                provider="google-genai",
                model=config.intent_model_name,
                input_tokens=getattr(usage, "prompt_token_count", 0) or 0,
                output_tokens=getattr(usage, "candidates_token_count", 0) or 0,
                purpose=purpose,
            )
            parsed = json.loads(response.text)
            return parsed if isinstance(parsed, dict) else None
        except Exception as exc:
            config.last_provider_error = f"Gemini failed: {exc}"

    groq_key = os.environ.get("GROQ_API_KEY")
    if groq_key:
        try:
            from groq import Groq

            client = Groq(api_key=groq_key)
            response = client.chat.completions.create(
                model=config.groq_model_name,
                messages=[
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            usage = getattr(response, "usage", None)
            tracker.record_call(
                provider="groq",
                model=config.groq_model_name,
                input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                output_tokens=getattr(usage, "completion_tokens", 0) or 0,
                purpose=purpose,
            )
            content = response.choices[0].message.content or "{}"
            parsed = json.loads(content)
            return parsed if isinstance(parsed, dict) else None
        except Exception as exc:
            config.last_provider_error = f"Groq failed: {exc}"

    return None
