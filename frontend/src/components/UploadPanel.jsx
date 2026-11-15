import { useRef, useState } from "react";
import { uploadPcap } from "../api.js";

export default function UploadPanel({ onUploaded, aiConfigured = true, onAddKey }) {
  const inputRef = useRef(null);
  const [busy, setBusy] = useState(false);
  const [ai, setAi] = useState(false);
  const [drag, setDrag] = useState(false);
  const [status, setStatus] = useState(null); // {kind: "ok" | "error", text}

  async function send(file) {
    if (!file) return;
    setBusy(true);
    setStatus(null);
    try {
      const r = await uploadPcap(file, { ai });
      setStatus({
        kind: "ok",
        text: `${r.filename}: ${r.packet_count} packets, ${r.flow_count} flows, ${r.alert_count} alerts.`,
      });
      await onUploaded?.();
    } catch (err) {
      setStatus({ kind: "error", text: err.message });
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = "";
    }
  }

  return (
    <section aria-label="Upload">
      <label
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); if (!busy) send(e.dataTransfer.files?.[0]); }}
        className={`flex cursor-pointer flex-col items-center rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors ${
          drag ? "border-blue-500 bg-blue-50" : "border-slate-300 hover:border-blue-400 hover:bg-slate-50"
        } ${busy ? "pointer-events-none opacity-60" : ""}`}
      >
        <span className="font-medium">{busy ? "Analyzing…" : "Drop a PCAP here or click to choose"}</span>
        <span className="mt-1 text-sm text-slate-500">
          .pcap or .pcapng you are authorized to analyze. The file is deleted after processing.
        </span>
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="sr-only"
          aria-label="PCAP file"
          disabled={busy}
          onChange={(e) => send(e.target.files?.[0])}
        />
      </label>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <label className="flex items-center gap-2 text-sm text-slate-600">
          <input type="checkbox" checked={ai} disabled={busy} onChange={(e) => setAi(e.target.checked)} />
          Run AI investigation
          {!aiConfigured && (
            <span className="text-slate-400">
              {" "}(no API key yet{onAddKey && <>, <button type="button" onClick={onAddKey} className="text-blue-600 hover:underline">add one</button></>})
            </span>
          )}
        </label>
        {status && (
          <p
            role={status.kind === "error" ? "alert" : "status"}
            className={`text-sm ${status.kind === "error" ? "text-red-600" : "text-emerald-600"}`}
          >
            {status.text}
          </p>
        )}
      </div>
    </section>
  );
}
