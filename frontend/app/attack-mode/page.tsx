import Link from "next/link";

export default function AttackModePage() {
  return (
    <div className="mx-auto max-w-2xl space-y-6 animate-fadeUp">
      <header>
        <p className="font-mono text-[11px] uppercase tracking-[0.25em] text-warn-medium">
          Phase 2 — not yet available
        </p>
        <h1 className="mt-1 font-display text-4xl text-ink-900">Attack Mode</h1>
        <p className="mt-3 text-ink-600">
          Full exploitation vectors (sqlmap, Dalfox, Nuclei exploit templates,
          hydra, JWT attacks, and more) ship in Phase 2. Deep Scan is ready now.
        </p>
      </header>

      <div className="border border-warn-medium/30 bg-warn-medium/5 p-5">
        <p className="font-mono text-xs uppercase tracking-wider text-warn-medium">
          Authorization reminder
        </p>
        <p className="mt-2 text-sm text-ink-700">
          Attack Mode will only be used against systems you are explicitly
          authorized to test. Aggressive payloads and exploit templates are
          intentionally deferred until that surface is built.
        </p>
      </div>

      <Link
        href="/deep-scan"
        className="inline-block bg-ink-900 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-fog-50 transition hover:bg-signal"
      >
        Go to Deep Scan
      </Link>
    </div>
  );
}
