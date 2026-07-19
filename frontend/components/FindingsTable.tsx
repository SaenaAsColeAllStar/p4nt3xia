"use client";

import Link from "next/link";
import { Fragment, useState } from "react";
import { Finding } from "@/lib/api";
import { SeverityBadge } from "./Badges";

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function FindingsTable({
  findings,
  scanId,
}: {
  findings: Finding[];
  scanId?: string;
}) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!findings.length) {
    return (
      <p className="font-mono text-sm text-ink-600">No findings yet.</p>
    );
  }

  return (
    <div className="overflow-x-auto border border-ink-800/10">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead className="bg-ink-900 text-fog-100">
          <tr className="font-mono text-[10px] uppercase tracking-wider">
            <th className="px-3 py-2.5 font-medium">Severity</th>
            <th className="px-3 py-2.5 font-medium">Type</th>
            <th className="px-3 py-2.5 font-medium">Description</th>
            <th className="px-3 py-2.5 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const detailHref =
              scanId || f.scan_id
                ? `/history/${scanId || f.scan_id}/findings/${f.id}`
                : null;
            const open = expanded === f.id;
            return (
              <Fragment key={f.id}>
                <tr
                  className={
                    i % 2 === 0 ? "bg-fog-50/80" : "bg-fog-100/50"
                  }
                >
                  <td className="px-3 py-2.5 align-top">
                    <SeverityBadge severity={f.severity} />
                    {f.cvss_score != null && (
                      <div className="mt-1 font-mono text-[10px] text-ink-600">
                        CVSS {f.cvss_score}
                      </div>
                    )}
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
                  <td className="px-3 py-2.5 align-top">
                    <div className="flex flex-col gap-1.5 font-mono text-[10px] uppercase tracking-wider">
                      {f.poc_curl && (
                        <button
                          type="button"
                          className="text-left text-signal hover:underline"
                          onClick={async () => {
                            const ok = await copyText(f.poc_curl || "");
                            if (ok) {
                              setCopiedId(f.id);
                              setTimeout(() => setCopiedId(null), 1500);
                            }
                          }}
                        >
                          {copiedId === f.id ? "Copied" : "Copy PoC"}
                        </button>
                      )}
                      {(f.poc_request || f.poc_response || f.poc_curl) && (
                        <button
                          type="button"
                          className="text-left text-ink-600 hover:text-ink-900"
                          onClick={() => setExpanded(open ? null : f.id)}
                        >
                          {open ? "Hide" : "Detail"}
                        </button>
                      )}
                      {detailHref && !f.id.startsWith("tmp-") && (
                        <Link
                          href={detailHref}
                          className="text-ink-600 hover:text-ink-900"
                        >
                          Full page
                        </Link>
                      )}
                    </div>
                  </td>
                </tr>
                {open && (
                  <tr className="bg-ink-900/[0.03]">
                    <td colSpan={4} className="px-3 py-3">
                      <div className="space-y-2 font-mono text-xs text-ink-700">
                        {f.poc_request && (
                          <div>
                            <p className="mb-1 text-[10px] uppercase tracking-wider text-ink-600">
                              Request
                            </p>
                            <pre className="overflow-x-auto whitespace-pre-wrap border border-ink-800/10 bg-fog-50 p-2">
                              {f.poc_request}
                            </pre>
                          </div>
                        )}
                        {f.poc_response && (
                          <div>
                            <p className="mb-1 text-[10px] uppercase tracking-wider text-ink-600">
                              Response
                            </p>
                            <pre className="overflow-x-auto whitespace-pre-wrap border border-ink-800/10 bg-fog-50 p-2">
                              {f.poc_response}
                            </pre>
                          </div>
                        )}
                        {f.poc_curl && (
                          <div>
                            <p className="mb-1 text-[10px] uppercase tracking-wider text-ink-600">
                              Curl
                            </p>
                            <pre className="overflow-x-auto whitespace-pre-wrap border border-ink-800/10 bg-fog-50 p-2">
                              {f.poc_curl}
                            </pre>
                          </div>
                        )}
                        {f.remediation && (
                          <p>
                            <span className="text-ink-600">Remediation: </span>
                            {f.remediation}
                          </p>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
