export default function SettingsPage() {
  return (
    <div className="space-y-4 animate-fadeUp">
      <h1 className="font-display text-4xl text-ink-900">Settings</h1>
      <p className="text-ink-600">
        Phase 1 uses sensible defaults from the PRD. Tool paths and timeouts can
        be overridden with <code className="font-mono text-sm">P4NT3XIA_*</code>{" "}
        environment variables on the backend.
      </p>
    </div>
  );
}
