import clsx from "clsx";

const severityStyles: Record<string, string> = {
  info: "text-ink-600 bg-fog-200/60",
  low: "text-warn-low bg-warn-low/10",
  medium: "text-warn-medium bg-warn-medium/10",
  high: "text-warn-high bg-warn-high/10",
  critical: "text-warn-critical bg-warn-critical/10",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toLowerCase();
  return (
    <span
      className={clsx(
        "inline-block px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
        severityStyles[key] || severityStyles.info
      )}
    >
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    pending: "text-ink-600",
    running: "text-signal animate-pulseBar",
    completed: "text-signal-dim",
    failed: "text-warn-high",
    cancelled: "text-ink-600",
  };
  return (
    <span
      className={clsx(
        "font-mono text-xs uppercase tracking-wider",
        colors[status] || "text-ink-600"
      )}
    >
      {status}
    </span>
  );
}
