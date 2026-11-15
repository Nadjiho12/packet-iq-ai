"""Saved AI provider settings (API key, optional URL and model).

Where it lives: a JSON file (SETTINGS_PATH, default ./packetiq_settings.json), written with
owner-only permissions where the OS supports it. The file is git-ignored. The key is stored in
plain text, like a .env file, so protect the folder the same way. The API never returns the
full key, only a masked hint.

How it is used: ai_agent.py reads AI_API_KEY / AI_API_URL / AI_MODEL from the environment.
Saving here sets those variables for the running process, and they are re-applied at startup.
A saved value wins over an existing environment value; removing it restores the original.
"""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

ENV_KEYS = {"api_key": "AI_API_KEY", "api_url": "AI_API_URL", "model": "AI_MODEL"}
MAX_KEY_LEN = 512
MAX_FIELD_LEN = 300

_env_backup: Dict[str, Optional[str]] = {}


class SettingsError(ValueError):
    """Invalid user input (message is safe to show)."""


def _path() -> Path:
    return Path(os.environ.get("SETTINGS_PATH", "packetiq_settings.json"))


def _load() -> Dict[str, str]:
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if k in ENV_KEYS and isinstance(v, str) and v}


def _write(data: Dict[str, str]) -> None:
    path = _path()
    fd, tmp = tempfile.mkstemp(dir=path.parent if str(path.parent) else ".", prefix=".settings_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass  # not supported on every platform
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _set_env(field: str, value: Optional[str]) -> None:
    var = ENV_KEYS[field]
    if var not in _env_backup:
        _env_backup[var] = os.environ.get(var)
    if value:
        os.environ[var] = value
    elif _env_backup[var] is None:
        os.environ.pop(var, None)
    else:
        os.environ[var] = _env_backup[var]


def apply_to_env() -> None:
    """Load saved settings into the process environment (called at startup and after saving)."""
    saved = _load()
    for field in ENV_KEYS:
        if field in saved:
            _set_env(field, saved[field])


def _check_url(url: str) -> str:
    u = urlparse(url)
    host = (u.hostname or "").lower()
    loopback = host == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if u.scheme == "https" and host:
        return url
    if u.scheme == "http" and loopback:
        return url
    raise SettingsError("API URL must start with https:// (http:// is allowed only for localhost).")


def _clean(value: Optional[str], label: str, limit: int) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if len(value) > limit or any(c in value for c in "\r\n\x00") or " " in value:
        raise SettingsError(f"{label} is not valid.")
    return value


def save(api_key: Optional[str], api_url: Optional[str] = None, model: Optional[str] = None) -> None:
    """Save settings. A blank api_key keeps the current key, so URL/model can be edited alone."""
    data = _load()
    key = _clean(api_key, "API key", MAX_KEY_LEN)
    url = _clean(api_url, "API URL", MAX_FIELD_LEN)
    mdl = _clean(model, "Model", MAX_FIELD_LEN)
    if key is None and "api_key" not in data and not os.environ.get("AI_API_KEY"):
        raise SettingsError("Enter an API key.")
    if url:
        _check_url(url)
    if key:
        data["api_key"] = key
    for name, val in (("api_url", url), ("model", mdl)):
        if val:
            data[name] = val
        else:
            data.pop(name, None)
            _set_env(name, None)  # back to the original environment value
    _write(data)
    apply_to_env()


def clear() -> None:
    """Remove all saved settings and restore the original environment."""
    for field in ENV_KEYS:
        _set_env(field, None)
    _env_backup.clear()
    try:
        _path().unlink()
    except OSError:
        pass


def _mask(key: str) -> str:
    return "••••" + key[-4:] if len(key) > 8 else "••••"


def status() -> Dict[str, Any]:
    saved = _load()
    key = os.environ.get("AI_API_KEY", "")
    source = None if not key else ("saved" if saved.get("api_key") == key else "environment")
    return {
        "configured": bool(key),
        "source": source,
        "masked_key": _mask(key) if key else None,
        "api_url": os.environ.get("AI_API_URL") or None,
        "model": os.environ.get("AI_MODEL") or None,
    }
