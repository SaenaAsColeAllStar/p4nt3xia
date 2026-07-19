"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { api, ScanWithDetails } from "@/lib/api";
import { FindingsTable } from "@/components/FindingsTable";
import { StatusBadge } from "@/components/Badges";

export default function ScanDetailPage() {
  const params = useParams();
  const id = String(params.id);
  const [scan, setScan] = useState<ScanWithDetails | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getScan(id)
      .then(setScan)
      .catch((e) => setError(e.message));
  }, [id]);

  if (error) {
    return <p className="font-mono text-sm text-warn-high">{error}</p>;
  }

  if (!scan) {
    return <p className="font-mono text-sm text-ink-600">Loading…</p>;
  }

  const target =
    scan.target?.value || String(scan.configuration?.target || "—");

  return (
    <div className="space-y-8 animate-fadeUp">
      <div>
        <Link
          href="/history"
          className="font-mono text-xs uppercase tracking-wider text-signal hover:underline"
        >
          ← History
        </Link>
        <h1 className="mt-2 font-display text-3xl text-ink-900 sm:text-4xl">
          {target}
        </h1>
        <div className="mt-2 flex flex-wrap items-center gap-4 font-mono text-xs text-ink-600">
          <StatusBadge status={scan.status} />
          <span>{scan.mode}</span>
          <span>{Math.round(scan.progress)}%</span>
          {scan.started_at && (
            <span>{new Date(scan.started_at).toLocaleString()}</span>
          )}
        </div>
        {scan.error_message && (
          <p className="mt-3 font-mono text-sm text-warn-high">
            {scan.error_message}
          </p>
        )}
      </div>

      <section className="space-y-3">
        <h2 className="font-display text-2xl text-ink-900">Tool runs</h2>
        <div className="overflow-x-auto border border-ink-800/10">
          <table className="w-full min-w-[520px] text-left text-sm">
            <thead className="bg-ink-900 text-fog-100">
              <tr className="font-mono text-[10px] uppercase tracking-wider">
                <th className="px-3 py-2.5">Tool</th>
                <th className="px-3 py-2.5">Status</th>
                <th className="px-3 py-2.5">Duration</th>
                <th className="px-3 py-2.5">Exit</th>
              </tr>
            </thead>
            <tbody>
              {scan.tool_results.map((tr, i) => (
                <tr
                  key={tr.id}
                  className={i % 2 === 0 ? "bg-fog-50/80" : "bg-fog-100/50"}
                >
                  <td className="px-3 py-2.5 font-medium">{tr.tool_name}</td>
                  <td className="px-3 py-2.5 font-mono text-xs">{tr.status}</td>
                  <td className="px-3 py-2.5 font-mono text-xs">
                    {tr.duration_ms != null ? `${tr.duration_ms} ms` : "—"}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs">
                    {tr.exit_code ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="font-display text-2xl text-ink-900">Findings</h2>
        <FindingsTable findings={scan.findings} />
      </section>
    </div>
  );
}
