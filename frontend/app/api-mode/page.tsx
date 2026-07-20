"use client";

import { useState } from "react";
import { api, ApiResponseOut, ParsedCurl } from "@/lib/api";

export default function ApiModePage() {
  const [curl, setCurl] = useState(
    `curl -X GET 'https://httpbin.org/get' -H 'Accept: application/json'`
  );
  const [parsed, setParsed] = useState<ParsedCurl | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [result, setResult] = useState<ApiResponseOut | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function doParse() {
    setError(null);
    try {
      const p = await api.parseCurl(curl);
      setParsed(p);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function doSend() {
    setError(null);
    setBusy(true);
    setResult(null);
    try {
      const res = await api.apiFromCurl(curl, authorized);
      setResult(res);
      const p = await api.parseCurl(curl);
      setParsed(p);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6 animate-fadeUp">
      <div>
        <h1 className="font-display text-4xl text-ink-900">API Mode</h1>
        <p className="mt-2 max-w-2xl text-ink-600">
          Paste a curl command from your terminal. The backend parses it and
          executes the HTTP request — useful for replaying API probes without
          leaving the browser.
        </p>
      </div>

      <div className="border border-amber-800/20 bg-amber-50/80 px-4 py-3 text-sm text-amber-950">
        Only send requests against systems you are authorized to test. Non-GET
        methods require the authorization checkbox.
      </div>

      <label className="block space-y-2">
        <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
          Curl command
        </span>
        <textarea
          className="min-h-[140px] w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-xs outline-none focus:border-signal"
          value={curl}
          onChange={(e) => setCurl(e.target.value)}
          spellCheck={false}
        />
      </label>

      <label className="flex items-start gap-2 text-sm text-ink-700">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
          className="mt-1"
        />
        <span>
          I am authorized to send this request (required for POST/PUT/PATCH/DELETE).
        </span>
      </label>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={doParse}
          className="border border-ink-800/20 px-4 py-2 font-mono text-xs uppercase tracking-wider text-ink-800 hover:border-signal"
        >
          Parse only
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={doSend}
          className="bg-ink-900 px-5 py-2 font-mono text-xs uppercase tracking-wider text-fog-50 hover:bg-signal disabled:opacity-50"
        >
          {busy ? "Sending…" : "Execute"}
        </button>
      </div>

      {error && (
        <p className="font-mono text-xs text-red-700">{error}</p>
      )}

      {parsed && (
        <div className="border border-ink-800/10 bg-fog-50/70 p-4">
          <h2 className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
            Parsed
          </h2>
          <pre className="mt-2 overflow-x-auto font-mono text-xs text-ink-800">
            {JSON.stringify(parsed, null, 2)}
          </pre>
        </div>
      )}

      {result && (
        <div className="space-y-3 border border-ink-800/10 bg-fog-50/70 p-4">
          <div className="flex flex-wrap items-baseline gap-3">
            <span className="font-mono text-sm text-ink-900">
              {result.status_code}
            </span>
            <span className="font-mono text-xs text-ink-600">
              {result.elapsed_ms}ms · {result.method} {result.url}
            </span>
          </div>
          <div>
            <h3 className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              PoC curl
            </h3>
            <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px]">
              {result.poc_curl}
            </pre>
          </div>
          <div>
            <h3 className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              Body{result.body_truncated ? " (truncated)" : ""}
            </h3>
            <pre className="mt-1 max-h-96 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px]">
              {result.body}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
