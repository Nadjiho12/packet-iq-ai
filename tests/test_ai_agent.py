import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from backend.app import ai_agent
from backend.app.ai_agent import ThreatReport, investigate_alert, minimize_alert

ALERT = {
    "rule_id": "RULE-001", "rule_name": "Port Scan", "severity": "medium",
    "timestamp": 1790100012.0, "timestamp_iso": "2026-09-22T18:00:12+00:00",
    "src_ip": "198.51.100.77", "dst_ip": "192.0.2.10",
    "summary": "198.51.100.77 contacted 21 unique ports on 192.0.2.10 within 10s",
    "evidence": {"unique_dst_ports": 21, "threshold": 20, "window_seconds": 10.0,
                 "ports_sample": list(range(1000, 1021)), "payload": "SECRET-PAYLOAD"},
    "password": "hunter2",
}
DNS_ALERT = {
    "rule_id": "RULE-004", "rule_name": "Suspicious DNS", "severity": "medium",
    "timestamp_iso": "2026-09-22T18:01:51+00:00", "src_ip": "192.0.2.60", "dst_ip": "192.0.2.53",
    "summary": "suspicious DNS query (high_entropy_label): x7k2q9m4z8p1w5v3n6.exfil.example",
    "evidence": {"query": "x7k2q9m4z8p1w5v3n6.exfil.example", "reasons": ["high_entropy_label"],
                 "query_length": 32, "entropy_label": "x7k2q9m4z8p1w5v3n6", "entropy_bits": 4.17},
}
GOOD = {
    "summary": "Host scanned many ports on one target.",
    "observed_behavior": "35 unique destination ports in the window.",
    "severity_recommendation": "High",
    "confidence_score": 0.85,
    "benign_explanations": ["Authorized vulnerability scan"],
    "next_steps": ["Identify host owner", "Block source if unauthorized"],
}


def fake_resp(content, status=200):
    r = MagicMock(status_code=status)
    r.json.return_value = {"choices": [{"message": {"content": content}}]}
    return r


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "sk-test-DO-NOT-LEAK")


def test_valid_output():
    with patch("requests.post", return_value=fake_resp(json.dumps(GOOD))):
        res = investigate_alert(ALERT)
    assert res["investigation_status"] == "ok"
    assert res["report"]["severity_recommendation"] == "high"
    assert res["alert"] is ALERT


def test_fenced_json_accepted():
    with patch("requests.post", return_value=fake_resp("```json\n" + json.dumps(GOOD) + "\n```")):
        assert investigate_alert(ALERT)["investigation_status"] == "ok"


def test_malformed_json():
    with patch("requests.post", return_value=fake_resp("not json {")):
        res = investigate_alert(ALERT)
    assert res["investigation_status"] == "failed"
    assert "AIInvalidJSONError" in res["investigation_error"]
    assert res["alert"] == ALERT


@pytest.mark.parametrize("score", [-0.1, 1.01, 5])
def test_confidence_bounds_rejected(score):
    bad = {**GOOD, "confidence_score": score}
    with patch("requests.post", return_value=fake_resp(json.dumps(bad))):
        res = investigate_alert(ALERT)
    assert "AISchemaError" in res["investigation_error"]


@pytest.mark.parametrize("score", [0.0, 1.0])
def test_confidence_boundaries_accepted(score):
    ThreatReport.model_validate({**GOOD, "confidence_score": score})


def test_missing_field():
    bad = {k: v for k, v in GOOD.items() if k != "next_steps"}
    with patch("requests.post", return_value=fake_resp(json.dumps(bad))):
        assert "AISchemaError" in investigate_alert(ALERT)["investigation_error"]


def test_timeout_contained():
    with patch("requests.post", side_effect=requests.Timeout()):
        res = investigate_alert(ALERT)
    assert "AITimeoutError" in res["investigation_error"] and res["alert"] == ALERT


def test_http_error():
    with patch("requests.post", return_value=fake_resp("", status=500)):
        assert "HTTP 500" in investigate_alert(ALERT)["investigation_error"]


def test_empty_content():
    with patch("requests.post", return_value=fake_resp("")):
        assert "AIProviderError" in investigate_alert(ALERT)["investigation_error"]


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("AI_API_KEY")
    res = investigate_alert(ALERT)
    assert "AIConfigError" in res["investigation_error"] and res["alert"] == ALERT


def test_minimal_data_sent():
    with patch("requests.post", return_value=fake_resp(json.dumps(GOOD))) as p:
        investigate_alert(ALERT)
    sent = json.dumps(p.call_args.kwargs["json"])
    assert "SECRET-PAYLOAD" not in sent and "hunter2" not in sent
    m = minimize_alert(ALERT)
    assert "payload" not in m["evidence"] and "summary" not in m and "password" not in m
    assert m["evidence"]["unique_dst_ports"] == 21


def test_dns_query_name_not_sent():
    m = minimize_alert(DNS_ALERT)
    blob = json.dumps(m)
    assert "exfil.example" not in blob and "x7k2q9m4z8p1w5v3n6" not in blob
    assert m["evidence"]["query_length"] == 32 and m["evidence"]["reasons"] == ["high_entropy_label"]


def test_non_dict_alert_never_raises():
    res = investigate_alert(None)
    assert res["investigation_status"] == "failed"


def test_api_key_not_in_logs_or_errors(caplog):
    with patch("requests.post", side_effect=requests.ConnectionError("sk-test-DO-NOT-LEAK")):
        res = investigate_alert(ALERT)
    assert "sk-test-DO-NOT-LEAK" not in res["investigation_error"]
    assert "sk-test-DO-NOT-LEAK" not in caplog.text
