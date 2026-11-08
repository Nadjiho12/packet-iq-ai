"""AI investigation agent: enriches a detection alert with a structured ThreatReport.

Design rules (Week 3):
  * Send only minimum alert metadata (allow-list) - never PCAPs, payloads, credentials.
  * Credentials come from environment variables only; never logged.
  * Any failure is contained: investigate_alert() never raises and always returns
    the original alert untouched.

Environment variables:
  AI_API_KEY      (required) provider API key
  AI_API_URL      (optional) OpenAI-compatible chat-completions endpoint
                  default: https://api.openai.com/v1/chat/completions
  AI_MODEL        (optional) default: gpt-4o-mini
  AI_TIMEOUT_SEC  (optional) default: 20
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import requests
from pydantic import BaseModel, Field, ValidationError, field_validator

logger = logging.getLogger("packetiq.ai_agent")

DEFAULT_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT = 20.0

# Allow-lists: only these fields ever leave the machine. They match the Alert
# record produced by detection.py (Week 2). Deliberately excluded: `summary`
# (RULE-004 summaries embed the DNS query name), evidence["query"] and
# evidence["entropy_label"] (DNS names can reveal browsing), raw packets/payloads.
ALLOWED_ALERT_FIELDS = (
    "rule_id", "rule_name", "severity", "timestamp_iso", "src_ip", "dst_ip",
)
ALLOWED_EVIDENCE_FIELDS = (
    "unique_dst_ports", "ports_sample", "connection_attempts", "attempt_definition",
    "syn_without_ack_packets", "total_tcp_packets", "syn_ratio", "half_open_flows",
    "established_flows", "byte_count", "packet_count", "duration_seconds", "flow",
    "reasons", "query_length", "entropy_bits", "threshold", "threshold_bytes",
    "threshold_ratio", "length_threshold", "window_seconds",
)
_SCALARS = (str, int, float, bool)

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant. Given minimal metadata about one network "
    "detection alert, reply with ONLY a JSON object with exactly these keys: "
    "summary (string), observed_behavior (string), severity_recommendation "
    "(one of: low, medium, high, critical), confidence_score (number 0.0-1.0), "
    "benign_explanations (array of strings), next_steps (array of strings). "
    "Do not invent data that is not in the metadata."
)


# --------------------------------------------------------------------- schema
class ThreatReport(BaseModel):
    summary: str = Field(min_length=1)
    observed_behavior: str = Field(min_length=1)
    severity_recommendation: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    benign_explanations: List[str]
    next_steps: List[str]

    @field_validator("severity_recommendation")
    @classmethod
    def _severity(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in {"low", "medium", "high", "critical"}:
            raise ValueError("severity_recommendation must be low|medium|high|critical")
        return v


# --------------------------------------------------------------------- errors
class AIAgentError(Exception):
    """Base class; message must never contain secrets."""


class AIConfigError(AIAgentError): ...
class AITimeoutError(AIAgentError): ...
class AIProviderError(AIAgentError): ...
class AIInvalidJSONError(AIAgentError): ...
class AISchemaError(AIAgentError): ...


# -------------------------------------------------------------------- helpers
def _clean(value: Any, depth: int = 0) -> Any:
    """Keep only short scalars / small lists / one-level dicts of scalars."""
    if isinstance(value, _SCALARS) or value is None:
        return value if not isinstance(value, str) else value[:200]
    if isinstance(value, (list, tuple)) and depth < 2:
        return [_clean(v, depth + 1) for v in value[:50] if isinstance(v, _SCALARS)]
    if isinstance(value, dict) and depth < 1:
        return {str(k): _clean(v, depth + 1) for k, v in value.items() if isinstance(v, _SCALARS)}
    return None


def minimize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Return only allow-listed, non-None alert and evidence fields."""
    out = {k: alert[k] for k in ALLOWED_ALERT_FIELDS if alert.get(k) is not None}
    ev = alert.get("evidence")
    if isinstance(ev, dict):
        kept = {k: _clean(ev[k]) for k in ALLOWED_EVIDENCE_FIELDS if ev.get(k) is not None}
        if kept:
            out["evidence"] = kept
    return out


def _extract_json(text: str) -> Any:
    text = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise AIInvalidJSONError(f"Provider returned invalid JSON ({exc.msg})") from None


def _load_config() -> Dict[str, Any]:
    key = os.environ.get("AI_API_KEY", "").strip()
    if not key:
        raise AIConfigError("AI_API_KEY is not set")
    try:
        timeout = float(os.environ.get("AI_TIMEOUT_SEC", DEFAULT_TIMEOUT))
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    return {
        "key": key,
        "url": os.environ.get("AI_API_URL", DEFAULT_URL),
        "model": os.environ.get("AI_MODEL", DEFAULT_MODEL),
        "timeout": timeout,
    }


# ----------------------------------------------------------------- core calls
def generate_report(alert: Dict[str, Any]) -> ThreatReport:
    """Call the provider and return a validated ThreatReport. Raises AIAgentError."""
    cfg = _load_config()
    payload = {
        "model": cfg["model"],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(minimize_alert(alert))},
        ],
    }
    headers = {"Authorization": f"Bearer {cfg['key']}", "Content-Type": "application/json"}
    try:
        resp = requests.post(cfg["url"], json=payload, headers=headers, timeout=cfg["timeout"])
    except requests.Timeout:
        raise AITimeoutError(f"Provider timed out after {cfg['timeout']}s") from None
    except requests.RequestException as exc:
        raise AIProviderError(f"Provider request failed: {type(exc).__name__}") from None

    if resp.status_code != 200:
        raise AIProviderError(f"Provider returned HTTP {resp.status_code}")

    try:
        content = resp.json()["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise AIProviderError("Provider response missing content") from None
    if not isinstance(content, str) or not content.strip():
        raise AIProviderError("Provider response missing content")

    data = _extract_json(content)
    try:
        return ThreatReport.model_validate(data)
    except ValidationError as exc:
        fields = ", ".join(sorted({".".join(map(str, e["loc"])) or "root" for e in exc.errors()}))
        raise AISchemaError(f"Report failed schema validation (fields: {fields})") from None


def investigate_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Fault-tolerant wrapper for the detection pipeline. Never raises.

    Returns {"alert": <original, unmodified>, "report": dict|None,
             "investigation_status": "ok"|"failed", "investigation_error": str|None}
    """
    result: Dict[str, Any] = {
        "alert": alert, "report": None,
        "investigation_status": "failed", "investigation_error": None,
    }
    try:
        report = generate_report(alert)
        result["report"] = report.model_dump()
        result["investigation_status"] = "ok"
    except AIAgentError as exc:
        result["investigation_error"] = f"{type(exc).__name__}: {exc}"
        logger.warning("AI investigation failed for %s: %s", alert.get("rule_id") if isinstance(alert, dict) else None, result["investigation_error"])
    except Exception as exc:  # last-resort containment; log type only
        result["investigation_error"] = f"UnexpectedError: {type(exc).__name__}"
        logger.error("Unexpected AI agent error: %s", type(exc).__name__)
    return result
