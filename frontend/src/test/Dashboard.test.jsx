import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import Dashboard from "../pages/Dashboard.jsx";

const METRICS = {
  total_packets: 1234, active_flows: 56, total_alerts: 2, total_uploads: 1,
  alerts_by_severity: { low: 0, medium: 1, high: 1, critical: 0 }, last_upload_at: null,
};
const ALERT = {
  id: 1, upload_id: 1, rule_id: "RULE-001", rule_name: "Port Scan", severity: "medium",
  timestamp_iso: "2026-11-01T10:00:00Z", src_ip: "192.0.2.10", dst_ip: "198.51.100.20",
  summary: "21 unique ports", evidence: {}, ai_status: "failed",
  ai_error: "AIConfigError: AI_API_KEY is not set", ai_report: null, notified: false,
};

const NO_KEY = { configured: false, source: null, masked_key: null, api_url: null, model: null };

function mockFetch(routes) {
  routes = { "GET /api/v1/settings/ai": () => ({ body: NO_KEY }), ...routes };
  vi.stubGlobal("fetch", vi.fn(async (url, opts) => {
    const key = `${opts?.method ?? "GET"} ${String(url).split("?")[0]}`;
    const handler = routes[key];
    if (!handler) throw new Error(`unmocked ${key}`);
    const { status = 200, body } = handler(opts);
    return { ok: status < 400, status, json: async () => body };
  }));
}

afterEach(() => vi.unstubAllGlobals());

describe("Dashboard", () => {
  it("shows a loading state, then metrics and alerts", async () => {
    mockFetch({
      "GET /api/v1/metrics": () => ({ body: METRICS }),
      "GET /api/v1/alerts": () => ({ body: { total: 1, items: [ALERT] } }),
    });
    render(<Dashboard />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading");
    expect(await screen.findByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("56")).toBeInTheDocument();
    expect(screen.getByText("Port Scan")).toBeInTheDocument();
    expect(screen.getByText("medium")).toBeInTheDocument();
  });

  it("shows an empty state when there are no alerts", async () => {
    mockFetch({
      "GET /api/v1/metrics": () => ({ body: { ...METRICS, total_alerts: 0, alerts_by_severity: {} } }),
      "GET /api/v1/alerts": () => ({ body: { total: 0, items: [] } }),
    });
    render(<Dashboard />);
    expect(await screen.findByText(/No alerts yet/)).toBeInTheDocument();
  });

  it("shows an error banner when the backend is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network down"); }));
    render(<Dashboard />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot reach the backend");
  });

  it("expands an alert and shows the AI-unavailable fallback", async () => {
    mockFetch({
      "GET /api/v1/metrics": () => ({ body: METRICS }),
      "GET /api/v1/alerts": () => ({ body: { total: 1, items: [ALERT] } }),
    });
    render(<Dashboard />);
    await userEvent.click(await screen.findByRole("button", { name: /Port Scan/ }));
    expect(screen.getByText(/AI investigation unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/Detection alert preserved/)).toBeInTheDocument();
  });

  it("uploads a PCAP, then refreshes; surfaces server errors", async () => {
    let uploads = 0;
    mockFetch({
      "GET /api/v1/metrics": () => ({ body: METRICS }),
      "GET /api/v1/alerts": () => ({ body: { total: 0, items: [] } }),
      "POST /api/v1/upload": () => {
        uploads += 1;
        return uploads === 1
          ? { status: 201, body: { filename: "a.pcap", packet_count: 10, flow_count: 3, alert_count: 0 } }
          : { status: 415, body: { detail: "File content is not a PCAP/PCAPNG capture." } };
      },
    });
    render(<Dashboard />);
    const input = await screen.findByLabelText("PCAP file");
    await userEvent.upload(input, new File(["x"], "a.pcap"));
    expect(await screen.findByText(/a\.pcap: 10 packets, 3 flows, 0 alerts/)).toBeInTheDocument();
    await userEvent.upload(input, new File(["x"], "b.pcap"));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("not a PCAP"));
  });

  it("Refresh shows feedback and an updated time", async () => {
    let calls = 0;
    mockFetch({
      "GET /api/v1/metrics": () => { calls += 1; return { body: METRICS }; },
      "GET /api/v1/alerts": () => ({ body: { total: 0, items: [] } }),
    });
    render(<Dashboard />);
    await screen.findByText("1,234");
    const before = calls;
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(screen.getByRole("button", { name: "Refreshing…" })).toBeDisabled();
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled());
    expect(calls).toBeGreaterThan(before);
    expect(screen.getByText(/^Updated \d{2}:\d{2}:\d{2}$/)).toBeInTheDocument();
  });

  it("Clear data asks for confirmation, then deletes and reloads", async () => {
    let cleared = false;
    mockFetch({
      "GET /api/v1/metrics": () => ({ body: cleared ? { ...METRICS, total_packets: 0 } : METRICS }),
      "GET /api/v1/alerts": () => ({ body: { total: 0, items: [] } }),
      "DELETE /api/v1/data": () => { cleared = true; return { status: 204, body: null }; },
    });
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    render(<Dashboard />);
    await screen.findByText("1,234");
    await userEvent.click(screen.getByRole("button", { name: "Clear data" }));
    expect(cleared).toBe(false); // declined
    await userEvent.click(screen.getByRole("button", { name: "Clear data" }));
    await waitFor(() => expect(cleared).toBe(true));
    await waitFor(() => expect(screen.getByTestId("metric-Total packets")).toHaveTextContent("0"));
    confirm.mockRestore();
  });

  it("adds an API key: dialog sends it once, then only the masked hint is shown", async () => {
    let status = NO_KEY;
    let sent = null;
    mockFetch({
      "GET /api/v1/metrics": () => ({ body: METRICS }),
      "GET /api/v1/alerts": () => ({ body: { total: 0, items: [] } }),
      "GET /api/v1/settings/ai": () => ({ body: status }),
      "PUT /api/v1/settings/ai": (opts) => {
        sent = JSON.parse(opts.body);
        status = { configured: true, source: "saved", masked_key: "••••wxyz", api_url: null, model: null };
        return { body: status };
      },
    });
    render(<Dashboard />);
    await userEvent.click(await screen.findByRole("button", { name: /Add API key/ }));
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("Add API key");
    const field = screen.getByLabelText("API key");
    expect(field).toHaveAttribute("type", "password");
    await userEvent.type(field, "sk-secret-wxyz");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(sent.api_key).toBe("sk-secret-wxyz");
    expect(screen.queryByText(/sk-secret/)).not.toBeInTheDocument();
    // reopen to edit: shows the mask, empty key field, "Change" wording
    await userEvent.click(screen.getByRole("button", { name: "API key" }));
    expect(screen.getByTestId("current-key")).toHaveTextContent("••••wxyz");
    expect(screen.getByRole("dialog")).toHaveTextContent("Change API key");
    expect(screen.getByLabelText("New API key")).toHaveValue("");
  });

  it("disables Save until a key is typed, and shows server validation errors", async () => {
    mockFetch({
      "GET /api/v1/metrics": () => ({ body: METRICS }),
      "GET /api/v1/alerts": () => ({ body: { total: 0, items: [] } }),
      "PUT /api/v1/settings/ai": () => ({ status: 422, body: { detail: "API key is not valid." } }),
    });
    render(<Dashboard />);
    await userEvent.click(await screen.findByRole("button", { name: /Add API key/ }));
    const save = screen.getByRole("button", { name: "Save" });
    expect(save).toBeDisabled();
    await userEvent.type(screen.getByLabelText("API key"), "has space");
    expect(save).toBeEnabled();
    await userEvent.click(save);
    expect(await screen.findByRole("alert")).toHaveTextContent("API key is not valid.");
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("removes a saved key", async () => {
    let status = { configured: true, source: "saved", masked_key: "••••abcd", api_url: null, model: null };
    mockFetch({
      "GET /api/v1/metrics": () => ({ body: METRICS }),
      "GET /api/v1/alerts": () => ({ body: { total: 0, items: [] } }),
      "GET /api/v1/settings/ai": () => ({ body: status }),
      "DELETE /api/v1/settings/ai": () => { status = NO_KEY; return { body: NO_KEY }; },
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<Dashboard />);
    await userEvent.click(await screen.findByRole("button", { name: "API key" }));
    await userEvent.click(screen.getByRole("button", { name: "Remove key" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: /Add API key/ })).toBeInTheDocument();
  });
});
