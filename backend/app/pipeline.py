"""End-to-end pipeline (Week 1-3): PCAP -> flows -> alerts -> AI report -> email.

  python -m backend.app.pipeline <pcap> [--ai] [--email] [--max-alerts N] [--json]

AI and email are opt-in. Without --ai the output is identical to Week 2 detection.
Failures in the AI or email step never drop or alter a detection alert.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from backend.app.ai_agent import investigate_alert
from backend.app.notifier import send_alert_email


def enrich_alerts(alerts: List[Dict[str, Any]], use_ai: bool = True, notify: bool = False,
                  max_alerts: int = 20) -> List[Dict[str, Any]]:
    """Return one result per alert: {alert, report, investigation_status, investigation_error, notified}."""
    results: List[Dict[str, Any]] = []
    for i, alert in enumerate(alerts):
        if use_ai and i < max_alerts:
            res = investigate_alert(alert)
        else:
            reason = "AI disabled" if not use_ai else f"skipped (max_alerts={max_alerts})"
            res = {"alert": alert, "report": None, "investigation_status": "skipped",
                   "investigation_error": reason}
        res["notified"] = send_alert_email(res) if notify else False
        results.append(res)
    return results


def main(argv: Optional[List[str]] = None) -> int:
    from backend.app.capture import PcapReadError, read_pcap
    from backend.app.detection import run_detection

    try:  # optional: load .env if python-dotenv is installed
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    ap = argparse.ArgumentParser(prog="pipeline", description="PacketIQ AI pipeline")
    ap.add_argument("pcap")
    ap.add_argument("--ai", action="store_true", help="AI investigation report per alert")
    ap.add_argument("--email", action="store_true", help="send an SMTP notification per alert")
    ap.add_argument("--max-alerts", type=int, default=20, help="cap AI calls per run (cost control)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        records = read_pcap(args.pcap)
    except PcapReadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    alerts = [a.to_dict() for a in run_detection(records).alerts]
    results = enrich_alerts(alerts, use_ai=args.ai, notify=args.email, max_alerts=args.max_alerts)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            a = r["alert"]
            print(f"[{a['severity'].upper():<6}] {a['rule_id']} {a['summary']}")
            if r["report"]:
                print(f"    AI: {r['report']['severity_recommendation']} "
                      f"({r['report']['confidence_score']:.2f}) {r['report']['summary']}")
            elif args.ai:
                print(f"    AI: {r['investigation_status']} - {r['investigation_error']}")
            if args.email:
                print(f"    email: {'sent' if r['notified'] else 'not sent'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
