"""
llm_processor.py — Ollama interface for FozamiMail.

Sends email content to a locally-running Ollama model and returns a
validated analysis dict with these guaranteed keys:

    category         str   one of: work | newsletter | personal | spam |
                                   finance | support | social | other
    urgency          str   one of: low | medium | high | critical
    summary          str   1–2 sentence plain-text summary (≤ 500 chars)
    requires_action  bool  True if the recipient must do something
    importance_score float 0.0–10.0

The function raises RuntimeError on connection problems (Ollama not running)
and ValueError on persistent JSON parse failures.
"""

import json
import logging
import re

import requests

import config

logger = logging.getLogger(__name__)

# ── Prompt templates ───────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are an email analysis assistant.

Analyse the email provided by the user and reply with ONLY a single valid \
JSON object — no prose, no markdown fences, no extra keys.

Required JSON schema:
{
  "category":         string,   // work | newsletter | personal | spam | finance | support | social | other
  "urgency":          string,   // low | medium | high | critical
  "summary":          string,   // 1-2 sentence plain-text summary
  "requires_action":  boolean,  // true if the recipient must do something
  "importance_score": number    // float 0.0 (irrelevant) to 10.0 (critical)
}
"""

_USER_TEMPLATE = """\
From:    {sender}
Date:    {received_at}
Subject: {subject}

{body}
"""

# ── Valid field values ─────────────────────────────────────────────────────

_VALID_CATEGORIES = frozenset(
    {"work", "newsletter", "personal", "spam", "finance", "support", "social", "other"}
)
_VALID_URGENCIES = frozenset({"low", "medium", "high", "critical"})


# ── Public API ─────────────────────────────────────────────────────────────

def analyze_email(
    subject: str,
    sender: str,
    received_at: str,
    body: str,
) -> tuple[dict, str]:
    """
    Send email to Ollama and return ``(analysis, raw_response)``.

    ``analysis`` is a validated dict (see module docstring).
    ``raw_response`` is the model's raw text output (stored for debugging).

    Raises
    ------
    RuntimeError  — Ollama is unreachable or the request timed out.
    ValueError    — The model returned something that cannot be parsed as JSON
                    after all extraction attempts.
    """
    user_content = _USER_TEMPLATE.format(
        sender=sender,
        received_at=received_at,
        subject=subject,
        body=body,
    )

    payload = {
        "model": config.OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
        "stream": False,
        # "json" mode forces Ollama to only emit valid JSON tokens.
        # This eliminates markdown fences and prose wrapping entirely.
        # Supported by all models in Ollama >= 0.1.24.
        "format": "json",
        "options": {
            # Low temperature → deterministic, structured output.
            "temperature": 0.1,
            "top_p": 0.9,
        },
    }

    raw_response = _call_ollama(payload)
    analysis = _parse_and_validate(raw_response)
    logger.debug("Analysis: %s", analysis)
    return analysis, raw_response


# ── Ollama HTTP call ───────────────────────────────────────────────────────

def _call_ollama(payload: dict) -> str:
    """POST to Ollama /api/chat and return the assistant message content."""
    url = f"{config.OLLAMA_BASE_URL}/api/chat"
    try:
        resp = requests.post(url, json=payload, timeout=config.OLLAMA_TIMEOUT)
        resp.raise_for_status()
    except requests.ConnectionError as exc:
        raise RuntimeError(
            f"Cannot connect to Ollama at {config.OLLAMA_BASE_URL}. "
            "Make sure Ollama is running: `ollama serve`"
        ) from exc
    except requests.Timeout as exc:
        raise RuntimeError(
            f"Ollama request timed out after {config.OLLAMA_TIMEOUT}s. "
            "Try a smaller model or increase OLLAMA_TIMEOUT."
        ) from exc
    except requests.HTTPError as exc:
        raise RuntimeError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}") from exc

    body = resp.json()
    content: str = body.get("message", {}).get("content", "")
    if not content:
        raise ValueError("Ollama returned an empty response body.")
    return content


# ── JSON extraction ────────────────────────────────────────────────────────

def _extract_json(text: str) -> dict:
    """
    Try to extract a JSON object from ``text``.

    Attempts (in order):
    1. Direct json.loads on the full text.
    2. Strip a markdown code fence (```json ... ```) then parse.
    3. Regex scan for the first {...} block and parse.
    """
    # 1 — direct
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2 — strip markdown fences
    fenced = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    fenced = re.sub(r"\s*```$", "", fenced)
    try:
        return json.loads(fenced)
    except json.JSONDecodeError:
        pass

    # 3 — grab first {...} blob
    match = re.search(r"\{[\s\S]+\}", text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"No valid JSON found in model response: {text[:300]!r}")


# ── Validation & normalisation ─────────────────────────────────────────────

def _parse_and_validate(raw: str) -> dict:
    """Parse raw LLM output and return a normalised, validated analysis dict."""
    data = _extract_json(raw)

    category = str(data.get("category", "other")).lower().strip()
    urgency = str(data.get("urgency", "low")).lower().strip()

    try:
        score = float(data.get("importance_score", 0.0))
    except (TypeError, ValueError):
        score = 0.0

    try:
        requires_action = bool(data.get("requires_action", False))
    except (TypeError, ValueError):
        requires_action = False

    summary = str(data.get("summary", "")).strip()[:500]
    if not summary:
        summary = "No summary available."

    return {
        "category": category if category in _VALID_CATEGORIES else "other",
        "urgency": urgency if urgency in _VALID_URGENCIES else "low",
        "summary": summary,
        "requires_action": requires_action,
        "importance_score": round(max(0.0, min(10.0, score)), 1),
    }
