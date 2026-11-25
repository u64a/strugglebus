"""What a worker session spent, read from the Copilot CLI session log.

The log is `<home>/.copilot/session-state/<session_id>/events.jsonl`, one JSON object per line. Only
`session.usage_record` events are summed: credits (AIC) are `copilotUsage.totalNanoAiu / 1e9`. The log is read
once, line by line; a torn last line, a line that is not an object and unknown event types are skipped.
"""
from __future__ import annotations

import json
from pathlib import Path

NANO = 1e9


def _num(v) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def read_usage(session_id: str, home: Path | str | None = None) -> dict | None:
    path = Path(home or Path.home()) / ".copilot" / "session-state" / str(session_id) / "events.jsonl"
    nano: dict[str, float] = {}
    calls = tokens_in = tokens_out = 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if '"session.usage_record"' not in line:
                    continue
                try:
                    ev = json.loads(line)
                    if ev.get("type") != "session.usage_record":
                        continue
                    usage = ev["data"]["usage"]
                    model = usage.get("model")
                    model = model if isinstance(model, str) and model else "unknown"
                    cost = _num((usage.get("copilotUsage") or {}).get("totalNanoAiu"))
                    t_in, t_out = int(_num(usage.get("inputTokens"))), int(_num(usage.get("outputTokens")))
                except (ValueError, KeyError, TypeError, AttributeError):
                    continue
                nano[model] = nano.get(model, 0.0) + cost
                calls += 1
                tokens_in += t_in
                tokens_out += t_out
    except OSError:
        return None
    return {"aic": round(sum(nano.values()) / NANO, 1), "calls": calls, "input_tokens": tokens_in,
            "output_tokens": tokens_out, "by_model": {m: round(n / NANO, 1) for m, n in nano.items()},
            "model_observed": max(nano, key=nano.get) if nano else None}
