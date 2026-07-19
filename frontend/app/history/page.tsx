"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, Scan } from "@/lib/api";
import { StatusBadge } from "@/components/Badges";

export default function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listScans()
      .then(setScans)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <div className="space-y-6">
      <header className="animate-fadeUp">
        <h1 className="font-display text-4xl text-ink-900">History</h1>
        <p className="mt-2 text-ink-600">Past scans and stored findings.</p>
      </header>

      {error && (
        <p className="font-mono text-sm text-warn-high">{error}</p>
      )}

      {!scans.length && !error ? (
        <p className="font-mono text-sm text-ink-600">No scan history yet.</p>
      ) : (
        <div className="overflow-x-auto border border-ink-800/10 animate-fadeUp">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="bg-ink-900 text-fog-100">
              <tr className="font-mono text-[10px] uppercase tracking-wider">
                <th className="px-3 py-2.5 font-medium">Target</th>
                <th className="px-3 py-2.5 font-medium">Mode</th>
                <th className="px-3 py-2.5 font-medium">Status</th>
                <th className="px-3 py-2.5 font-medium">Progress</th>
                <th className="px-3 py-2.5 font-medium">Started</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan, i) => (
                <tr
                  key={scan.id}
                  className={i % 2 === 0 ? "bg-fog-50/80" : "bg-fog-100/50"}
                >
                  <td className="px-3 py-2.5">
                    <Link
                      href={`/history/${scan.id}`}
                      className="font-medium text-ink-900 hover:text-signal"
                    >
                      {scan.target?.value ||
                        String(scan.configuration?.target || "—")}
                    </Link>
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs text-ink-600">
                    {scan.mode}
                  </td>
                  <td className="px-3 py-2.5">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs">
                    {Math.round(scan.progress)}%
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs text-ink-600">
                    {scan.started_at
                      ? new Date(scan.started_at).toLocaleString()
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
