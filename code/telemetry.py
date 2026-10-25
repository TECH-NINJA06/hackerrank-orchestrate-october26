"""
Token Usage and Cost Telemetry Tracker (`code/telemetry.py`)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


class TokenUsageTracker:
    """Tracks model calls, input/output tokens, and cost for `usage_report.md`."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self.calls: List[Dict[str, Any]] = []

    def record_call(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        purpose: str,
    ) -> None:
        self.calls.append(
            {
                "provider": provider,
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "purpose": purpose,
            }
        )

    def write_usage_report(self, output_path: Path, num_requests: int, elapsed_seconds: float) -> None:
        total_in = sum(c["input_tokens"] for c in self.calls)
        total_out = sum(c["output_tokens"] for c in self.calls)
        total_tok = total_in + total_out

        # Cost estimation based on config pricing
        est_cost = 0.0
        for c in self.calls:
            rates = self.config.MODEL_PRICING_PER_1M.get(c["model"], (0.15, 0.60))
            est_cost += (c["input_tokens"] / 1_000_000.0) * rates[0] + (c["output_tokens"] / 1_000_000.0) * rates[1]

        report_content = f"""# Token Usage and Cost Analysis Report

- **Evaluation Run Timestamp**: Full dataset audit across {num_requests} requests in {elapsed_seconds:.2f} seconds.
- **Model Providers**: Gemini primary with Groq fallback
- **Models Used**: {", ".join(sorted({f"{c['provider']}:{c['model']}" for c in self.calls})) or "none"}
- **Total Model Calls**: {len(self.calls)} calls (optimized via corpus-level SHA-256 caching)
- **Input Tokens**: {total_in:,}
- **Output Tokens**: {total_out:,}
- **Total Tokens**: {total_tok:,}
- **Average Tokens per Request**: {total_tok / max(1, num_requests):.1f}
- **Estimated Total Cost**: ${est_cost:.4f} USD
- **Estimated Cost per Request**: ${est_cost / max(1, num_requests):.6f} USD
"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_content, encoding="utf-8")