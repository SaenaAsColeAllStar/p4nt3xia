"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  DeepScanOptions,
  Finding,
  ProgressEvent,
  ScanWithDetails,
  WS_URL,
} from "@/lib/api";
import { FindingsTable } from "@/components/FindingsTable";
import { ProgressPanel } from "@/components/ProgressPanel";

const DEFAULT_OPTIONS: DeepScanOptions = {
  subdomain_enum: true,
  port_scan: true,
  directory_fuzz: true,
  tech_detect: true,
  safe_vuln_scan: true,
  crawl: true,
  threads: 3,
  timeout: 30,
};

const TOOL_TOGGLES: { key: keyof DeepScanOptions; label: string }[] = [
  { key: "subdomain_enum", label: "Subdomain Enum" },
  { key: "port_scan", label: "Port Scan" },
  { key: "directory_fuzz", label: "Directory Fuzz" },
  { key: "tech_detect", label: "Tech Detect" },
  { key: "safe_vuln_scan", label: "Safe Vuln Scan" },
  { key: "crawl", label: "Crawl (Katana)" },
];

type LogEntry = { id: string; message: string; tool?: string | null };

export default function DeepScanPage() {
  const [target, setTarget] = useState("");
  const [options, setOptions] = useState<DeepScanOptions>(DEFAULT_OPTIONS);
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
                  finding_type: finding.finding_type || "info",
                  cvss_score: null,
                  cve_id: null,
                  description: finding.description || null,
                  poc_request: null,
                  poc_response: null,
                  poc_curl: null,
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

      ws.onerror = () => pushLog("WebSocket error — retry by refreshing results");
      ws.onclose = () => {
        /* quiet */
      };
    },
    [pushLog]
  );

  useEffect(() => {
    return () => wsRef.current?.close();
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    setFindings([]);
    setLogs([]);
    setProgress(0);
    setStatus("pending");
    setCurrentTool(null);

    try {
      const scan = await api.startDeepScan({
        target: target.trim(),
        options,
      });
      setScanId(scan.id);
      setStatus(scan.status);
      pushLog(`Scan started: ${scan.id}`);
      connectWs(scan.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
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

  function toggleOption(key: keyof DeepScanOptions) {
    setOptions((prev) => {
      const val = prev[key];
      if (typeof val === "boolean") {
        return { ...prev, [key]: !val };
      }
      return prev;
    });
  }

  return (
    <div className="space-y-8">
      <header className="animate-fadeUp">
        <p className="font-mono text-[11px] uppercase tracking-[0.25em] text-signal">
          Non-destructive recon
        </p>
        <h1 className="mt-1 font-display text-4xl text-ink-900">Deep Scan</h1>
        <p className="mt-2 max-w-xl text-ink-600">
          Pipeline: Subfinder → Nmap → ffuf → WhatWeb → Nuclei (safe) → Katana.
          Results stream over WebSocket.
        </p>
      </header>

      <form
        onSubmit={onSubmit}
        className="animate-fadeUp space-y-6 border border-ink-800/10 bg-fog-50/70 p-6"
        style={{ animationDelay: "60ms" }}
      >
        <div>
          <label
            htmlFor="target"
            className="mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-ink-600"
          >
            Target Input
          </label>
          <input
            id="target"
            type="text"
            required
            placeholder="https://example.com  or  example.com  or  203.0.113.10"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="w-full border border-ink-800/15 bg-white px-3 py-2.5 font-mono text-sm text-ink-900 outline-none ring-signal/40 placeholder:text-ink-600/40 focus:ring-2"
          />
        </div>

        <fieldset>
          <legend className="mb-2 font-mono text-[10px] uppercase tracking-wider text-ink-600">
            Modules
          </legend>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {TOOL_TOGGLES.map((t) => (
              <label
                key={t.key}
                className="flex cursor-pointer items-center gap-2 font-mono text-sm text-ink-800"
              >
                <input
                  type="checkbox"
                  checked={Boolean(options[t.key])}
                  onChange={() => toggleOption(t.key)}
                  className="accent-signal"
                />
                {t.label}
              </label>
            ))}
          </div>
        </fieldset>

        <div className="flex flex-wrap gap-6">
          <label className="flex items-center gap-2 font-mono text-sm">
            <span className="text-ink-600">Threads</span>
            <input
              type="number"
              min={1}
              max={50}
              value={options.threads}
              onChange={(e) =>
                setOptions((o) => ({ ...o, threads: Number(e.target.value) || 3 }))
              }
              className="w-16 border border-ink-800/15 bg-white px-2 py-1 text-ink-900 outline-none focus:ring-2 focus:ring-signal/40"
            />
          </label>
          <label className="flex items-center gap-2 font-mono text-sm">
            <span className="text-ink-600">Timeout (s)</span>
            <input
              type="number"
              min={5}
              max={600}
              value={options.timeout}
              onChange={(e) =>
                setOptions((o) => ({
                  ...o,
                  timeout: Number(e.target.value) || 30,
                }))
              }
              className="w-16 border border-ink-800/15 bg-white px-2 py-1 text-ink-900 outline-none focus:ring-2 focus:ring-signal/40"
            />
          </label>
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            type="submit"
            disabled={submitting || status === "running"}
            className="bg-ink-900 px-6 py-3 font-mono text-xs uppercase tracking-wider text-fog-50 transition hover:bg-signal disabled:opacity-50"
          >
            Start Deep Scan
          </button>
          {status === "running" && (
            <button
              type="button"
              onClick={onCancel}
              className="border border-warn-high/40 px-6 py-3 font-mono text-xs uppercase tracking-wider text-warn-high transition hover:bg-warn-high/5"
            >
              Cancel
            </button>
          )}
        </div>

        {error && (
          <p className="font-mono text-sm text-warn-high">{error}</p>
        )}
        {scanId && (
          <p className="font-mono text-[11px] text-ink-600">
            Scan ID: {scanId}
          </p>
        )}
      </form>

      {status !== "idle" && (
        <section className="animate-fadeUp space-y-3">
          <h2 className="font-display text-2xl text-ink-900">Live progress</h2>
          <ProgressPanel
            progress={progress}
            status={status}
            currentTool={currentTool}
            logs={logs}
          />
        </section>
      )}

      <section className="animate-fadeUp space-y-3" style={{ animationDelay: "100ms" }}>
        <h2 className="font-display text-2xl text-ink-900">Results</h2>
        <FindingsTable findings={findings} />
      </section>
    </div>
  );
}
