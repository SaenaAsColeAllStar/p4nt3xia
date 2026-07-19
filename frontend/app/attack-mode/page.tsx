"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  api,
  AttackModeOptions,
  Finding,
  ProgressEvent,
  ScanWithDetails,
  WS_URL,
} from "@/lib/api";
import { FindingsTable } from "@/components/FindingsTable";
import { ProgressPanel } from "@/components/ProgressPanel";

const DEFAULT_OPTIONS: AttackModeOptions = {
  sql_injection: true,
  xss: true,
  nuclei_exploit: true,
  threads: 3,
  timeout: 60,
  delay_ms: 0,
  sqlmap_level: 2,
  sqlmap_risk: 2,
  authorized: false,
};

const VECTORS: { key: keyof AttackModeOptions; label: string }[] = [
  { key: "sql_injection", label: "SQL Injection (sqlmap)" },
  { key: "xss", label: "XSS (Dalfox)" },
  { key: "nuclei_exploit", label: "Nuclei Exploit Templates" },
];

type LogEntry = { id: string; message: string; tool?: string | null };

export default function AttackModePage() {
  const [target, setTarget] = useState("");
  const [authHeader, setAuthHeader] = useState("");
  const [options, setOptions] = useState<AttackModeOptions>(DEFAULT_OPTIONS);
  const [scanId, setScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState("idle");
  const [currentTool, setCurrentTool] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const logCounter = useRef(0);
  const wsRef = useRef<WebSocket | null>(null);

  const pushLog = useCallback((message: string, tool?: string | null) => {
    logCounter.current += 1;
    setLogs((prev) =>
      [...prev, { id: String(logCounter.current), message, tool }].slice(-200)
    );
  }, []);

  const connectWs = useCallback(
    (id: string) => {
      wsRef.current?.close();
      const ws = new WebSocket(`${WS_URL}/ws/scans/${id}`);
      wsRef.current = ws;

      ws.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data) as ProgressEvent;
          setProgress(data.progress);
          setStatus(data.status);
          setCurrentTool(data.current_tool);
          if (data.message) pushLog(data.message, data.current_tool);
          if (data.finding?.title) {
            const finding = data.finding;
            setFindings((prev) => {
              const fid = finding.id || `tmp-${prev.length}`;
              if (prev.some((f) => f.id === fid)) return prev;
              return [
                ...prev,
                {
                  id: fid,
                  scan_id: data.scan_id,
                  title: finding.title || "Finding",
                  severity: finding.severity || "info",
                  finding_type: finding.finding_type || "attack",
                  cvss_score: finding.cvss_score ?? null,
                  cve_id: null,
                  description: finding.description || null,
                  poc_request: null,
                  poc_response: null,
                  poc_curl: finding.poc_curl || null,
                  remediation: null,
                  references: [],
                  raw_data: {},
                  created_at: new Date().toISOString(),
                },
              ];
            });
          }
          if (data.status === "completed" || data.status === "failed") {
            api.getScan(id).then((detail: ScanWithDetails) => {
              setFindings(detail.findings);
              setProgress(detail.progress);
              setStatus(detail.status);
            });
          }
        } catch {
          /* ignore malformed */
        }
      };

      ws.onerror = () => pushLog("WebSocket error — refresh or open History");
    },
    [pushLog]
  );

  useEffect(() => {
    return () => wsRef.current?.close();
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!target.trim()) {
      setError("Target is required");
      return;
    }
    if (!options.authorized) {
      setError("You must confirm authorization before launching Attack Mode");
      return;
    }
    setSubmitting(true);
    setFindings([]);
    setLogs([]);
    setProgress(0);
    setStatus("pending");
    try {
      const scan = await api.startAttackScan({
        target: target.trim(),
        auth_header: authHeader.trim() || null,
        options,
      });
      setScanId(scan.id);
      connectWs(scan.id);
      pushLog(`Attack started — scan ${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start attack");
      setStatus("idle");
    } finally {
      setSubmitting(false);
    }
  }

  async function onCancel() {
    if (!scanId) return;
    try {
      await api.cancelScan(scanId);
      pushLog("Cancel requested");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cancel failed");
    }
  }

  function toggleVector(key: keyof AttackModeOptions) {
    setOptions((prev) => {
      if (typeof prev[key] !== "boolean") return prev;
      return { ...prev, [key]: !prev[key] };
    });
  }

  const running = status === "running" || status === "pending";

  return (
    <div className="mx-auto max-w-3xl space-y-8 animate-fadeUp">
      <header>
        <p className="font-mono text-[11px] uppercase tracking-[0.25em] text-warn-high">
          Attack Mode · Phase 2
        </p>
        <h1 className="mt-1 font-display text-4xl text-ink-900">Launch Attack</h1>
        <p className="mt-3 max-w-xl text-ink-600">
          Aggressive exploitation vectors for systems you are explicitly
          authorized to test. Findings include PoC curl commands and CVSS scores.
        </p>
      </header>

      <div className="border border-warn-high/40 bg-warn-high/5 p-5">
        <p className="font-mono text-xs uppercase tracking-wider text-warn-high">
          Authorization reminder
        </p>
        <p className="mt-2 text-sm text-ink-700">
          Only attack targets you own or have written permission to assess.
          sqlmap, Dalfox, and Nuclei exploit templates can disrupt services and
          trigger security alerts.
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-6">
        <label className="block space-y-2">
          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
            Target URL / Domain / IP
          </span>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://api.target.example"
            className="w-full border border-ink-800/15 bg-fog-50 px-3 py-2.5 font-mono text-sm outline-none focus:border-signal"
            disabled={running}
          />
        </label>

        <label className="block space-y-2">
          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
            Auth header (optional)
          </span>
          <input
            value={authHeader}
            onChange={(e) => setAuthHeader(e.target.value)}
            placeholder="Bearer eyJ… or Authorization: Bearer …"
            className="w-full border border-ink-800/15 bg-fog-50 px-3 py-2.5 font-mono text-sm outline-none focus:border-signal"
            disabled={running}
            autoComplete="off"
          />
        </label>

        <fieldset className="space-y-3">
          <legend className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
            Attack vectors
          </legend>
          <div className="grid gap-2 sm:grid-cols-1">
            {VECTORS.map((v) => (
              <label
                key={v.key}
                className="flex cursor-pointer items-center gap-3 border border-ink-800/10 bg-fog-50/80 px-3 py-2.5"
              >
                <input
                  type="checkbox"
                  checked={Boolean(options[v.key])}
                  onChange={() => toggleVector(v.key)}
                  disabled={running}
                  className="accent-signal"
                />
                <span className="text-sm text-ink-800">{v.label}</span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="grid gap-4 sm:grid-cols-3">
          <label className="block space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              Delay (ms)
            </span>
            <input
              type="number"
              min={0}
              max={10000}
              value={options.delay_ms}
              onChange={(e) =>
                setOptions((o) => ({ ...o, delay_ms: Number(e.target.value) }))
              }
              disabled={running}
              className="w-full border border-ink-800/15 bg-fog-50 px-3 py-2 font-mono text-sm"
            />
          </label>
          <label className="block space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              Timeout (s)
            </span>
            <input
              type="number"
              min={10}
              max={900}
              value={options.timeout}
              onChange={(e) =>
                setOptions((o) => ({ ...o, timeout: Number(e.target.value) }))
              }
              disabled={running}
              className="w-full border border-ink-800/15 bg-fog-50 px-3 py-2 font-mono text-sm"
            />
          </label>
          <label className="block space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              sqlmap level / risk
            </span>
            <div className="flex gap-2">
              <input
                type="number"
                min={1}
                max={5}
                value={options.sqlmap_level}
                onChange={(e) =>
                  setOptions((o) => ({
                    ...o,
                    sqlmap_level: Number(e.target.value),
                  }))
                }
                disabled={running}
                className="w-full border border-ink-800/15 bg-fog-50 px-3 py-2 font-mono text-sm"
                title="level"
              />
              <input
                type="number"
                min={1}
                max={3}
                value={options.sqlmap_risk}
                onChange={(e) =>
                  setOptions((o) => ({
                    ...o,
                    sqlmap_risk: Number(e.target.value),
                  }))
                }
                disabled={running}
                className="w-full border border-ink-800/15 bg-fog-50 px-3 py-2 font-mono text-sm"
                title="risk"
              />
            </div>
          </label>
        </div>

        <label className="flex items-start gap-3 border border-warn-high/30 bg-warn-high/5 px-3 py-3">
          <input
            type="checkbox"
            checked={options.authorized}
            onChange={(e) =>
              setOptions((o) => ({ ...o, authorized: e.target.checked }))
            }
            disabled={running}
            className="mt-1 accent-warn-high"
          />
          <span className="text-sm text-ink-800">
            I confirm I am authorized to run aggressive tests against this
            target.
          </span>
        </label>

        {error && (
          <p className="font-mono text-sm text-warn-high">{error}</p>
        )}

        <div className="flex flex-wrap gap-3">
          <button
            type="submit"
            disabled={submitting || running}
            className="bg-ink-900 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-fog-50 transition hover:bg-warn-high disabled:opacity-50"
          >
            {submitting || running ? "Attack running…" : "Launch Attack"}
          </button>
          {running && scanId && (
            <button
              type="button"
              onClick={onCancel}
              className="border border-ink-800/20 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-ink-700"
            >
              Cancel
            </button>
          )}
          {scanId && (
            <Link
              href={`/history/${scanId}`}
              className="border border-ink-800/20 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-ink-700"
            >
              Open scan detail
            </Link>
          )}
        </div>
      </form>

      {(status !== "idle" || logs.length > 0) && (
        <ProgressPanel
          progress={progress}
          status={status}
          currentTool={currentTool}
          logs={logs}
        />
      )}

      <section className="space-y-3">
        <h2 className="font-display text-2xl text-ink-900">Findings</h2>
        <FindingsTable findings={findings} scanId={scanId || undefined} />
      </section>
    </div>
  );
}
