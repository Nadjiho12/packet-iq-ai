import { useState } from "react";
import { exportAlert, investigateAlert } from "../api.js";
import SeverityBadge from "./SeverityBadge.jsx";

const BUTTON =
  "rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium tracking-wide text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50";

function Investigation({ alert }) {
  if (alert.ai_status === "ok" && alert.ai_report) {
    const r = alert.ai_report;
    return (
      <dl className="space-y-1.5 rounded-lg bg-slate-50 p-4 text-sm text-slate-700">
        <div><dt className="inline font-medium">Summary: </dt><dd className="inline">{r.summary}</dd></div>
        <div><dt className="inline font-medium">What happened: </dt><dd className="inline">{r.observed_behavior}</dd></div>
        <div>
          <dt className="inline font-medium">Severity: </dt>
          <dd className="inline">{r.severity_recommendation}, {Math.round(r.confidence_score * 100)}% confidence</dd>
        </div>
        <div><dt className="inline font-medium">Could be benign: </dt><dd className="inline">{r.benign_explanations.join("; ")}</dd></div>
        <div><dt className="inline font-medium">Next steps: </dt><dd className="inline">{r.next_steps.join("; ")}</dd></div>
      </dl>
    );
  }
  if (alert.ai_status === "failed") {
    return (
      <p className="rounded-lg bg-slate-50 p-4 text-sm text-slate-500">
        AI investigation unavailable ({alert.ai_error ?? "unknown error"}). Detection alert preserved.
      </p>
    );
  }
  return <p className="rounded-lg bg-slate-50 p-4 text-sm text-slate-500">Not investigated yet.</p>;
}

function AlertRow({ alert, onUpdate }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [menu, setMenu] = useState(false);
  const [error, setError] = useState(null);
  const investigated = alert.ai_status === "ok" && Boolean(alert.ai_report);

  async function invest() {
    setBusy(true);
    setError(null);
    try {
      onUpdate(await investigateAlert(alert.id));
      setOpen(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function save(format) {
    setMenu(false);
    setError(null);
    try {
      await exportAlert(alert.id, format);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <li className="py-4">
      <div className="flex items-start gap-4">
        <button
          type="button"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
          className="min-w-0 flex-1 text-left"
        >
          <span className="block font-medium">
            {alert.rule_name}
            <span className="ml-1 font-mono text-xs font-normal text-slate-400">{alert.rule_id}</span>
          </span>
          <span className="mt-0.5 block break-words text-sm text-slate-600">{alert.summary}</span>
          <span className="mt-1 block font-mono text-xs text-slate-400">
            {alert.src_ip ?? "n/a"} → {alert.dst_ip ?? "n/a"}
            {alert.timestamp_iso ? ` · ${alert.timestamp_iso}` : ""}
          </span>
        </button>

        <div className="flex shrink-0 flex-col items-end gap-2">
          <SeverityBadge severity={alert.severity} />
          <div className="flex items-center gap-1.5">
            <button type="button" className={BUTTON} onClick={invest} disabled={busy}>
              {busy ? "Running…" : "INVEST"}
            </button>
            {menu && investigated && (
              <>
                <button type="button" className={BUTTON} onClick={() => save("csv")}>CSV</button>
                <button type="button" className={BUTTON} onClick={() => save("json")}>JSON</button>
              </>
            )}
            <button
              type="button"
              className={BUTTON}
              onClick={() => setMenu(!menu)}
              disabled={!investigated}
              title={investigated ? "Save this investigation" : "Investigate this alert first"}
            >
              SAVE
            </button>
          </div>
        </div>
      </div>
      {error && <p role="alert" className="mt-2 text-sm text-red-600">{error}</p>}
      {open && (
        <div className="mt-3">
          <Investigation alert={alert} />
        </div>
      )}
    </li>
  );
}

export default function AlertList({ alerts, onUpdate = () => {} }) {
  if (alerts.length === 0) {
    return <p className="py-12 text-center text-slate-500">No alerts yet. Upload a PCAP to analyze it.</p>;
  }
  return (
    <ul className="divide-y divide-slate-200 border-y border-slate-200" aria-label="Alerts">
      {alerts.map((a) => (
        <AlertRow key={a.id} alert={a} onUpdate={onUpdate} />
      ))}
    </ul>
  );
}
