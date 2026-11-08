"""Week 1-3 integration: attack PCAP -> detection -> (mocked) AI -> (mocked) email."""
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from backend.app import pipeline
from backend.app.capture import read_pcap
from backend.app.detection import run_detection

GOOD = {"summary": "s", "observed_behavior": "o", "severity_recommendation": "medium",
        "confidence_score": 0.7, "benign_explanations": ["scan"], "next_steps": ["check"]}


def ok_resp():
    r = MagicMock(status_code=200)
    r.json.return_value = {"choices": [{"message": {"content": json.dumps(GOOD)}}]}
    return r


@pytest.fixture
def alerts():
    return [a.to_dict() for a in run_detection(read_pcap("sample_pcaps/attack_demo.pcap")).alerts]


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "sk-test")


def test_real_alerts_all_enriched(alerts):
    assert len(alerts) == 6
    with patch("requests.post", return_value=ok_resp()) as p:
        res = pipeline.enrich_alerts(alerts)
    assert [r["investigation_status"] for r in res] == ["ok"] * 6 and p.call_count == 6
    assert all(r["alert"] is a for r, a in zip(res, alerts))


def test_no_dns_query_names_sent_for_real_alerts(alerts):
    with patch("requests.post", return_value=ok_resp()) as p:
        pipeline.enrich_alerts(alerts)
    sent = " ".join(json.dumps(c.kwargs["json"]) for c in p.call_args_list)
    assert "exfil.example" not in sent and "bbbbbbbb" not in sent


def test_provider_down_keeps_every_alert(alerts):
    with patch("requests.post", side_effect=requests.Timeout()):
        res = pipeline.enrich_alerts(alerts)
    assert len(res) == 6 and all(r["investigation_status"] == "failed" for r in res)
    assert [r["alert"]["rule_id"] for r in res] == [a["rule_id"] for a in alerts]


def test_ai_disabled_makes_no_calls(alerts):
    with patch("requests.post") as p:
        res = pipeline.enrich_alerts(alerts, use_ai=False)
    p.assert_not_called()
    assert res[0]["investigation_status"] == "skipped"


def test_max_alerts_cap(alerts):
    with patch("requests.post", return_value=ok_resp()) as p:
        res = pipeline.enrich_alerts(alerts, max_alerts=2)
    assert p.call_count == 2 and res[2]["investigation_status"] == "skipped"


def test_email_failure_does_not_affect_result(alerts):
    with patch("requests.post", return_value=ok_resp()), \
         patch("backend.app.pipeline.send_alert_email", return_value=False):
        res = pipeline.enrich_alerts(alerts[:1], notify=True)
    assert res[0]["investigation_status"] == "ok" and res[0]["notified"] is False


def test_cli_no_ai_matches_detection(capsys):
    assert pipeline.main(["sample_pcaps/attack_demo.pcap"]) == 0
    out = capsys.readouterr().out
    assert out.count("RULE-") == 6


def test_cli_missing_file():
    assert pipeline.main(["nope.pcap"]) == 1
