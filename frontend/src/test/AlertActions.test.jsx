import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { exportAlert, investigateAlert } from "../api.js";
import AlertList from "../components/AlertList.jsx";

vi.mock("../api.js", () => ({
  investigateAlert: vi.fn(),
  exportAlert: vi.fn(),
}));

const NOT_RUN = {
  id: 7, upload_id: 1, rule_id: "RULE-004", rule_name: "Suspicious DNS", severity: "medium",
  timestamp_iso: "2026-09-22T18:01:51+00:00", src_ip: "192.0.2.60", dst_ip: "192.0.2.53",
  summary: "suspicious DNS query (high_entropy_label): x7k2.exfil.example", evidence: {},
  ai_status: "skipped", ai_error: "skipped (max_alerts=5)", ai_report: null, notified: false,
};

const DONE = {
  ...NOT_RUN, ai_status: "ok", ai_error: null,
  ai_report: {
    summary: "Looks like DNS tunnelling.", observed_behavior: "A random-looking label.",
    severity_recommendation: "high", confidence_score: 0.7,
    benign_explanations: ["Random-looking CDN name"], next_steps: ["Check the host"],
  },
};

// Keeps the list in state, the way the dashboard does.
function Harness({ start = NOT_RUN }) {
  const [alerts, setAlerts] = useState([start]);
  const update = (u) => setAlerts((list) => list.map((a) => (a.id === u.id ? u : a)));
  return <AlertList alerts={alerts} onUpdate={update} />;
}

beforeEach(() => vi.clearAllMocks());

describe("INVEST and SAVE on an alert", () => {
  it("shows INVEST and SAVE, and SAVE stays off until the alert is investigated", () => {
    render(<Harness />);
    expect(screen.getByRole("button", { name: "INVEST" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "SAVE" })).toBeDisabled();
  });

  it("INVEST investigates only this alert and then shows the report", async () => {
    investigateAlert.mockResolvedValue(DONE);
    render(<Harness />);
    await userEvent.click(screen.getByRole("button", { name: "INVEST" }));
    expect(investigateAlert).toHaveBeenCalledTimes(1);
    expect(investigateAlert).toHaveBeenCalledWith(7);
    expect(await screen.findByText("Looks like DNS tunnelling.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "SAVE" })).toBeEnabled();
  });

  it("shows why an investigation failed and keeps the alert", async () => {
    investigateAlert.mockResolvedValue({
      ...NOT_RUN, ai_status: "failed", ai_error: "AIProviderError: Provider returned HTTP 401",
    });
    render(<Harness />);
    await userEvent.click(screen.getByRole("button", { name: "INVEST" }));
    expect(await screen.findByText(/AI investigation unavailable/)).toHaveTextContent("HTTP 401");
    expect(screen.getByText(/Detection alert preserved/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "SAVE" })).toBeDisabled();
  });

  it("shows a network error from INVEST", async () => {
    investigateAlert.mockRejectedValue(new Error("Cannot reach the backend. Is it running on port 8000?"));
    render(<Harness />);
    await userEvent.click(screen.getByRole("button", { name: "INVEST" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the backend");
  });

  it("SAVE offers CSV and JSON and downloads the chosen format", async () => {
    exportAlert.mockResolvedValue(undefined);
    render(<Harness start={DONE} />);
    await userEvent.click(screen.getByRole("button", { name: "SAVE" }));
    expect(screen.getByRole("button", { name: "CSV" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "JSON" }));
    expect(exportAlert).toHaveBeenCalledWith(7, "json");
    expect(screen.queryByRole("button", { name: "JSON" })).not.toBeInTheDocument();
  });

  it("shows the server message when a save is refused", async () => {
    exportAlert.mockRejectedValue(new Error("Investigate this alert before saving it."));
    render(<Harness start={DONE} />);
    await userEvent.click(screen.getByRole("button", { name: "SAVE" }));
    await userEvent.click(screen.getByRole("button", { name: "CSV" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Investigate this alert before saving it.");
  });
});
