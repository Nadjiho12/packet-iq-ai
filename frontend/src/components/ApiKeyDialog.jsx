import { useEffect, useRef, useState } from "react";
import { removeAiSettings, saveAiSettings } from "../api.js";

/**
 * Add, change or remove the AI provider key. The full key is only ever sent to the server;
 * the server answers with a masked hint, so the key is never shown again (even when editing).
 */
export default function ApiKeyDialog({ settings, onClose, onChanged }) {
  const configured = settings?.configured;
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(settings?.api_url ?? "");
  const [model, setModel] = useState(settings?.model ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const keyRef = useRef(null);

  useEffect(() => {
    keyRef.current?.focus();
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function run(action) {
    setBusy(true);
    setError(null);
    try {
      const next = await action();
      await onChanged(next);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const save = (e) => {
    e.preventDefault();
    run(() => saveAiSettings({ api_key: key, api_url: url, model }));
  };
  const remove = () => {
    if (window.confirm("Remove the saved API key?")) run(removeAiSettings);
  };

  const input = "mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none";

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-slate-900/40 p-4" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="apikey-title"
        className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="apikey-title" className="text-lg font-semibold">{configured ? "Change API key" : "Add API key"}</h2>
        <p className="mt-1 text-sm text-slate-500">
          Used for AI investigation. It is saved on this computer by the backend and never shown again.
        </p>
        {configured && (
          <p className="mt-3 text-sm text-slate-700" data-testid="current-key">
            Current key: <span className="font-mono">{settings.masked_key}</span>{" "}
            <span className="text-slate-400">({settings.source === "saved" ? "saved here" : "from environment"})</span>
          </p>
        )}
        <form onSubmit={save} className="mt-4 space-y-3">
          <label className="block text-sm font-medium">
            {configured ? "New API key" : "API key"}
            <input
              ref={keyRef}
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder={configured ? "Leave blank to keep the current key" : "Paste your key"}
              className={input}
            />
          </label>
          <details className="text-sm" open={Boolean(url || model)}>
            <summary className="cursor-pointer text-slate-600">Provider settings (optional)</summary>
            <label className="mt-2 block font-medium">
              API URL
              <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://api.openai.com/v1/chat/completions" className={input} />
            </label>
            <label className="mt-2 block font-medium">
              Model
              <input value={model} onChange={(e) => setModel(e.target.value)} placeholder="gpt-4o-mini" className={input} />
            </label>
          </details>
          {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
          <div className="flex items-center justify-between pt-2">
            {configured && settings.source === "saved" ? (
              <button type="button" onClick={remove} disabled={busy} className="text-sm text-red-600 hover:underline">
                Remove key
              </button>
            ) : <span />}
            <div className="flex gap-2">
              <button type="button" onClick={onClose} className="rounded-lg border border-slate-300 px-3.5 py-1.5 text-sm hover:bg-slate-50">
                Cancel
              </button>
              <button type="submit" disabled={busy || (!configured && !key.trim())} className="rounded-lg bg-blue-600 px-3.5 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-60">
                {busy ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
