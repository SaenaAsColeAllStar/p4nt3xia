"use client";

type LogEntry = {
  id: string;
  message: string;
  tool?: string | null;
};

export function ProgressPanel({
  progress,
  status,
  currentTool,
  logs,
}: {
  progress: number;
  status: string;
  currentTool: string | null;
  logs: LogEntry[];
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between gap-4">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
            Progress
          </p>
          <p className="font-mono text-2xl text-ink-900">
            {Math.round(progress)}%
          </p>
        </div>
        <div className="text-right font-mono text-xs text-ink-600">
          <div className="uppercase tracking-wider">{status}</div>
          {currentTool && <div className="text-signal">→ {currentTool}</div>}
        </div>
      </div>
      <div className="relative h-2 overflow-hidden bg-ink-800/10">
        <div
          className="absolute inset-y-0 left-0 bg-signal transition-all duration-500 ease-out"
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        />
        {status === "running" && (
          <div className="pointer-events-none absolute inset-0 overflow-hidden">
            <div className="h-full w-1/3 animate-scanline bg-gradient-to-b from-transparent via-white/40 to-transparent opacity-40" />
          </div>
        )}
      </div>
      <div className="max-h-48 overflow-y-auto border border-ink-800/10 bg-ink-950 p-3 font-mono text-xs text-fog-200">
        {logs.length === 0 ? (
          <p className="text-fog-300/60">Waiting for events…</p>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="border-b border-white/5 py-1 last:border-0">
              {log.tool && (
                <span className="mr-2 text-signal-bright">[{log.tool}]</span>
              )}
              <span>{log.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
