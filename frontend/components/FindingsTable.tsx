"use client";

import { Finding } from "@/lib/api";
import { SeverityBadge } from "./Badges";

export function FindingsTable({ findings }: { findings: Finding[] }) {
  if (!findings.length) {
    return (
      <p className="font-mono text-sm text-ink-600">No findings yet.</p>
    );
  }

  return (
    <div className="overflow-x-auto border border-ink-800/10">
      <table className="w-full min-w-[640px] text-left text-sm">
        <thead className="bg-ink-900 text-fog-100">
          <tr className="font-mono text-[10px] uppercase tracking-wider">
            <th className="px-3 py-2.5 font-medium">Severity</th>
            <th className="px-3 py-2.5 font-medium">Type</th>
            <th className="px-3 py-2.5 font-medium">Description</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr
              key={f.id}
              className={
                i % 2 === 0 ? "bg-fog-50/80" : "bg-fog-100/50"
              }
            >
              <td className="px-3 py-2.5 align-top">
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="px-3 py-2.5 align-top font-mono text-xs text-ink-600">
                {f.finding_type}
              </td>
              <td className="px-3 py-2.5 align-top">
                <div className="font-medium text-ink-900">{f.title}</div>
                {f.description && (
                  <div className="mt-0.5 text-xs text-ink-600 line-clamp-2">
                    {f.description}
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
