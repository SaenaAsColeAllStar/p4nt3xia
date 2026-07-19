"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, DashboardStats } from "@/lib/api";
import { StatusBadge } from "@/components/Badges";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .dashboard()
      .then(setStats)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <div className="space-y-10">
      <section className="relative overflow-hidden grid-fade animate-fadeUp border border-ink-800/10 bg-fog-50/60 px-6 py-12 sm:px-10">
        <div className="relative z-10 max-w-2xl">
          <p className="mb-3 font-mono text-[11px] uppercase tracking-[0.25em] text-signal">
            Authorized testing only
          </p>
          <h1 className="font-display text-5xl leading-none tracking-tight text-ink-900 sm:text-6xl">
            P4NT3XIA
          </h1>
          <p className="mt-4 max-w-md text-base text-ink-600 sm:text-lg">
            Personal deep-scan and attack workbench. Recon streams live; Attack
            Mode runs sqlmap, Dalfox, and Nuclei exploit templates with PoC
            exports.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              href="/deep-scan"
              className="bg-ink-900 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-fog-50 transition hover:bg-signal"
            >
              New Deep Scan
            </Link>
            <Link
              href="/attack-mode"
              className="border border-ink-800/20 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-ink-700 transition hover:border-ink-800/40"
            >
              Attack Mode
            </Link>
          </div>
        </div>
      </section>

      {error && (
        <p className="border border-warn-high/30 bg-warn-high/5 px-4 py-3 font-mono text-sm text-warn-high">
          Backend unreachable: {error}. Is `docker compose up` running?
        </p>
      )}

      <section className="animate-fadeUp space-y-4" style={{ animationDelay: "80ms" }}>
        <h2 className="font-display text-2xl text-ink-900">Overview</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { label: "Total scans", value: stats?.total_scans ?? "—" },
            { label: "Active targets", value: stats?.active_targets ?? "—" },
            {
              label: "Vulnerabilities",
              value: stats?.vulnerabilities_found ?? "—",
            },
            { label: "Running now", value: stats?.running_scans ?? "—" },
          ].map((card) => (
            <div
              key={card.label}
              className="border-l-2 border-signal/60 bg-fog-50/80 px-4 py-4"
            >
              <p className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
                {card.label}
              </p>
              <p className="mt-1 font-mono text-3xl text-ink-900">{card.value}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="animate-fadeUp space-y-4" style={{ animationDelay: "140ms" }}>
        <div className="flex items-baseline justify-between">
          <h2 className="font-display text-2xl text-ink-900">Recent activity</h2>
          <Link
            href="/history"
            className="font-mono text-xs uppercase tracking-wider text-signal hover:underline"
          >
            View all
          </Link>
        </div>
        {!stats?.recent_scans?.length ? (
          <p className="font-mono text-sm text-ink-600">
            No scans yet. Start a Deep Scan to begin.
          </p>
        ) : (
          <ul className="divide-y divide-ink-800/10 border border-ink-800/10 bg-fog-50/50">
            {stats.recent_scans.map((scan) => (
              <li key={scan.id}>
                <Link
                  href={`/history/${scan.id}`}
                  className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 transition hover:bg-fog-100/80"
                >
                  <div>
                    <p className="font-medium text-ink-900">
                      {scan.target?.value ||
                        (typeof scan.configuration?.target === "string"
                          ? scan.configuration.target
                          : "—")}
                    </p>
                    <p className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
                      {scan.mode.replace("_", " ")} ·{" "}
                      {scan.started_at
                        ? new Date(scan.started_at).toLocaleString()
                        : "queued"}
                    </p>
                  </div>
                  <StatusBadge status={scan.status} />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
