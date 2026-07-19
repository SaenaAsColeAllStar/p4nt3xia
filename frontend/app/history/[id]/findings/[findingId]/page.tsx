"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { api, Finding, reportUrl } from "@/lib/api";
import { SeverityBadge } from "@/components/Badges";

export default function FindingDetailPage() {
  const params = useParams();
  const scanId = String(params.id);
  const findingId = String(params.findingId);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api
      .getFinding(scanId, findingId)
      .then(setFinding)
      .catch((e) => setError(e.message));
  }, [scanId, findingId]);

  if (error) {
    return <p className="font-mono text-sm text-warn-high">{error}</p>;
  }
  if (!finding) {
    return <p className="font-mono text-sm text-ink-600">Loading…</p>;
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6 animate-fadeUp">
      <div>
        <Link
          href={`/history/${scanId}`}
          className="font-mono text-xs uppercase tracking-wider text-signal hover:underline"
        >
          ← Scan
        </Link>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <SeverityBadge severity={finding.severity} />
          {finding.cvss_score != null && (
            <span className="font-mono text-xs text-ink-600">
              CVSS {finding.cvss_score}
            </span>
          )}
          {finding.cve_id && (
            <span className="font-mono text-xs text-ink-600">
              {finding.cve_id}
            </span>
          )}
        </div>
        <h1 className="mt-2 font-display text-3xl text-ink-900">
          {finding.title}
        </h1>
        <p className="mt-1 font-mono text-xs uppercase tracking-wider text-ink-600">
          {finding.finding_type}
        </p>
      </div>

      {finding.description && (
        <p className="text-ink-700">{finding.description}</p>
      )}

      {finding.poc_curl && (
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-xl text-ink-900">PoC curl</h2>
            <button
              type="button"
              className="font-mono text-[10px] uppercase tracking-wider text-signal hover:underline"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(finding.poc_curl || "");
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                } catch {
                  /* ignore */
                }
              }}
            >
              {copied ? "Copied" : "Copy PoC"}
            </button>
          </div>
          <pre className="overflow-x-auto border border-ink-800/10 bg-fog-50 p-3 font-mono text-xs">
            {finding.poc_curl}
          </pre>
        </section>
      )}

      {finding.poc_request && (
        <section className="space-y-2">
          <h2 className="font-display text-xl text-ink-900">Request</h2>
          <pre className="overflow-x-auto whitespace-pre-wrap border border-ink-800/10 bg-fog-50 p-3 font-mono text-xs">
            {finding.poc_request}
          </pre>
        </section>
      )}

      {finding.poc_response && (
        <section className="space-y-2">
          <h2 className="font-display text-xl text-ink-900">Response</h2>
          <pre className="overflow-x-auto whitespace-pre-wrap border border-ink-800/10 bg-fog-50 p-3 font-mono text-xs">
            {finding.poc_response}
          </pre>
        </section>
      )}

      {finding.remediation && (
        <section className="space-y-2">
          <h2 className="font-display text-xl text-ink-900">Remediation</h2>
          <p className="text-ink-700">{finding.remediation}</p>
        </section>
      )}

      {finding.references?.length > 0 && (
        <section className="space-y-2">
          <h2 className="font-display text-xl text-ink-900">References</h2>
          <ul className="list-inside list-disc space-y-1 text-sm text-signal">
            {finding.references.map((r) => (
              <li key={r}>
                <a href={r} target="_blank" rel="noopener noreferrer">
                  {r}
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      <p className="font-mono text-[10px] text-ink-600">
        Report:{" "}
        <a
          className="text-signal hover:underline"
          href={reportUrl(scanId, "html")}
          target="_blank"
          rel="noopener noreferrer"
        >
          HTML
        </a>{" "}
        ·{" "}
        <a
          className="text-signal hover:underline"
          href={reportUrl(scanId, "json")}
          target="_blank"
          rel="noopener noreferrer"
        >
          JSON
        </a>
      </p>
    </div>
  );
}
