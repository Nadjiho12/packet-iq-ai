import { useCallback, useEffect, useState } from "react";
import { clearData, getAiSettings, getAlerts, getMetrics, investigateAlert } from "../api.js";
import ApiKeyDialog from "../components/ApiKeyDialog.jsx";
import AlertList from "../components/AlertList.jsx";
import UploadPanel from "../components/UploadPanel.jsx";

const POLL_MS = 15000;
const fmt = (n) => (typeof n === "number" ? n.toLocaleString("en-US") : "–");
const clock = (d) => d.toLocaleTimeString("en-GB");

function Stat({ label, value, hint, accent }) {
  return (
    <div data-testid={`metric-${label}`}>
      <p className="text-sm text-slate-500">{label}</p>
      <p className={`mt-1 text-4xl font-semibold tabular-nums ${accent ?? ""}`}>{fmt(value)}</p>
      {hint && <p className="mt-1 text-xs text-slate-400">{hint}</p>}
    </div>
  );
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [error, setError] = useState(null);
  const [ai, setAi] = useState(null); // AI key status from the server
  const [keyOpen, setKeyOpen] = useState(false);
  const [batch, setBatch] = useState(null); // { done, total } while INVEST ALL runs

  const load = useCallback(async () => {
    try {
      const [m, a, k] = await Promise.all([getMetrics(), getAlerts(), getAiSettings()]);
      setMetrics(m);
      setAi(k);
      setAlerts(a.items);
      setError(null);
      setUpdatedAt(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Manual refresh: keep the "Refreshing…" state visible briefly so the click is noticeable.
  const refresh = useCallback(async () => {
    setRefreshing(true);
    await Promise.all([load(), new Promise((r) => setTimeout(r, 400))]);
    setRefreshing(false);
  }, [load]);

  const replaceAlert = useCallback((updated) => {
    setAlerts((list) => list.map((a) => (a.id === updated.id ? updated : a)));
  }, []);

  // Runs INVEST on every alert without a result, one request at a time. Stops at the first failed request.
  async function investAll() {
    const todo = alerts.filter((a) => !(a.ai_status === "ok" && a.ai_report));
    if (todo.length === 0) return;
    setBatch({ done: 0, total: todo.length });
    for (let i = 0; i < todo.length; i++) {
      try {
        replaceAlert(await investigateAlert(todo[i].id));
      } catch (err) {
        setError(err.message);
        break;
      }
      setBatch({ done: i + 1, total: todo.length });
    }
    setBatch(null);
  }

  async function handleClear() {
    if (!window.confirm("Delete all stored uploads and alerts?")) return;
    try {
      await clearData();
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  const pending = alerts.filter((a) => !(a.ai_status === "ok" && a.ai_report));
  const sev = metrics?.alerts_by_severity ?? {};

  return (
    <main className="mx-auto max-w-3xl space-y-10 px-6 py-10">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">PacketIQ AI</h1>
          <p className="text-sm text-slate-500">Network packet analysis and threat investigation</p>
        </div>
        <div className="flex items-center gap-3 text-sm">
          {updatedAt && <span className="text-slate-400">Updated {clock(updatedAt)}</span>}
          <button
            type="button"
            onClick={refresh}
            disabled={refreshing}
            className="rounded-lg bg-blue-600 px-3.5 py-1.5 font-medium text-white hover:bg-blue-700 disabled:opacity-60"
          >
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
          <button
            type="button"
            onClick={() => setKeyOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-300 px-3.5 py-1.5 text-slate-700 hover:bg-slate-50"
          >
            <span className={`h-2 w-2 rounded-full ${ai?.configured ? "bg-emerald-500" : "bg-slate-300"}`} aria-hidden="true" />
            {ai?.configured ? "API key" : "Add API key"}
          </button>
          <button
            type="button"
            onClick={handleClear}
            className="rounded-lg border border-slate-300 px-3.5 py-1.5 text-slate-700 hover:bg-slate-50"
          >
            Clear data
          </button>
        </div>
      </header>

      {error && (
        <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {loading ? (
        <p role="status" className="text-slate-500">Loading…</p>
      ) : (
        metrics && (
          <section aria-label="Metrics" className="grid grid-cols-1 gap-8 sm:grid-cols-3">
            <Stat label="Total packets" value={metrics.total_packets} />
            <Stat label="Active flows" value={metrics.active_flows} hint="from analyzed captures" />
            <Stat
              label="Threat alerts"
              value={metrics.total_alerts}
              accent={metrics.total_alerts > 0 ? "text-amber-600" : ""}
              hint={`${sev.critical ?? 0} critical · ${sev.high ?? 0} high · ${sev.medium ?? 0} medium · ${sev.low ?? 0} low`}
            />
          </section>
        )
      )}

      <UploadPanel onUploaded={load} aiConfigured={Boolean(ai?.configured)} onAddKey={() => setKeyOpen(true)} />

      <section>
        <div className="mb-2 flex items-center justify-between gap-4">
          <h2 className="text-lg font-medium">Alerts</h2>
          <button
            type="button"
            onClick={investAll}
            disabled={batch !== null || pending.length === 0}
            className="rounded-lg border border-slate-300 px-3 py-1 text-sm hover:bg-slate-50 disabled:opacity-50"
          >
            {batch ? `Investigating ${batch.done} of ${batch.total}…` : "INVEST ALL"}
          </button>
        </div>
        <p className="mb-3 text-sm text-slate-500">
          INVEST runs the AI investigation on one alert. SAVE downloads an investigated alert as CSV or JSON.
        </p>
        {!loading && <AlertList alerts={alerts} onUpdate={replaceAlert} />}
      </section>
      {keyOpen && <ApiKeyDialog settings={ai} onClose={() => setKeyOpen(false)} onChanged={setAi} />}
    </main>
  );
}
