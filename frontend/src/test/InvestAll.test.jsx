import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "../api.js";
import Dashboard from "../pages/Dashboard.jsx";

vi.mock("../api.js", () => ({
  getMetrics: vi.fn(),
  getAlerts: vi.fn(),
  getAiSettings: vi.fn(),
  clearData: vi.fn(),
  uploadPcap: vi.fn(),
  investigateAlert: vi.fn(),
  exportAlert: vi.fn(),
  saveAiSettings: vi.fn(),
  removeAiSettings: vi.fn(),
}));

const METRICS = {
  total_packets: 10, active_flows: 2, total_alerts: 3, total_uploads: 1,
  alerts_by_severity: { medium: 3 }, last_upload_at: null,
};

function alert(id, status = "skipped") {
  return {
    id, upload_id: 1, rule_id: "RULE-001", rule_name: "Port Scan", severity: "medium",
    timestamp_iso: null, src_ip: "192.0.2.1", dst_ip: "192.0.2.2", summary: `alert ${id}`,
    evidence: {}, ai_status: status, ai_error: null, ai_report: null, notified: false,
  };
}

function investigated(a) {
  return {
    ...a, ai_status: "ok",
    ai_report: {
      summary: "done", observed_behavior: "seen", severity_recommendation: "low",
      confidence_score: 0.5, benign_explanations: ["benign"], next_steps: ["check"],
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getMetrics.mockResolvedValue(METRICS);
  api.getAiSettings.mockResolvedValue({
    configured: true, source: "saved", masked_key: "••••abcd", api_url: null, model: null,
  });
});

describe("INVEST ALL", () => {
  it("investigates every alert without a result yet, one after another", async () => {
    api.getAlerts.mockResolvedValue({ total: 3, items: [alert(3), investigated(alert(2)), alert(1)] });
    api.investigateAlert.mockImplementation(async (id) => investigated(alert(id)));
    render(<Dashboard />);
    await userEvent.click(await screen.findByRole("button", { name: "INVEST ALL" }));
    await waitFor(() => expect(api.investigateAlert).toHaveBeenCalledTimes(2));
    expect(api.investigateAlert.mock.calls.map((c) => c[0])).toEqual([3, 1]);
    await waitFor(() => expect(screen.getByRole("button", { name: "INVEST ALL" })).toBeDisabled());
  });

  it("stops at the first failed request and shows its message", async () => {
    api.getAlerts.mockResolvedValue({ total: 2, items: [alert(2), alert(1)] });
    api.investigateAlert.mockRejectedValueOnce(new Error("Cannot reach the backend. Is it running on port 8000?"));
    render(<Dashboard />);
    await userEvent.click(await screen.findByRole("button", { name: "INVEST ALL" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the backend");
    expect(api.investigateAlert).toHaveBeenCalledTimes(1);
  });
});
