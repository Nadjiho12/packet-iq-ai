"""MOCK OpenAI-compatible provider for demos/tests. Returns a canned ThreatReport.

NOT a real AI: output is static and clearly labeled "[MOCK]". Use it to exercise the
AI path end to end without an API key:

  python scripts/mock_ai_server.py            # listens on 127.0.0.1:9000
  AI_API_URL=http://127.0.0.1:9000/v1/chat/completions AI_API_KEY=mock-key \
      uvicorn backend.app.main:app
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        meta = json.loads(self.rfile.read(length))["messages"][-1]["content"]
        rule = json.loads(meta).get("rule_id", "unknown")
        report = {
            "summary": f"[MOCK] Canned analysis of {rule}.",
            "observed_behavior": "[MOCK] Traffic pattern matches the detection rule threshold.",
            "severity_recommendation": "high",
            "confidence_score": 0.8,
            "benign_explanations": ["[MOCK] Authorized vulnerability scan", "[MOCK] Misconfigured client"],
            "next_steps": ["[MOCK] Review source host", "[MOCK] Check firewall logs"],
        }
        body = json.dumps({"choices": [{"message": {"content": json.dumps(report)}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
