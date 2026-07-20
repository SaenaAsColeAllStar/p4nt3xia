"use client";

import { useEffect, useState } from "react";
import { api, FridaDevice, FridaRunResult } from "@/lib/api";

export default function FridaPage() {
  const [available, setAvailable] = useState(false);
  const [devices, setDevices] = useState<FridaDevice[]>([]);
  const [samples, setSamples] = useState<Record<string, string>>({});
  const [sampleKey, setSampleKey] = useState("");
  const [deviceId, setDeviceId] = useState("usb");
  const [target, setTarget] = useState("com.example.app");
  const [spawn, setSpawn] = useState(true);
  const [script, setScript] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [timeoutSec, setTimeoutSec] = useState(20);
  const [result, setResult] = useState<FridaRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const st = await api.fridaStatus();
        setAvailable(st.available);
        const [devs, smp] = await Promise.all([
          api.fridaDevices(),
          api.fridaSamples(),
        ]);
        setDevices(devs);
        setSamples(smp);
        const first = Object.keys(smp)[0];
        if (first) {
          setSampleKey(first);
          setScript(smp[first]);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    })();
  }, []);

  useEffect(() => {
    if (sampleKey && samples[sampleKey]) {
      setScript(samples[sampleKey]);
    }
  }, [sampleKey, samples]);

  async function run() {
    setError(null);
    setBusy(true);
    setResult(null);
    try {
      const res = await api.fridaRun({
        device_id: deviceId,
        target,
        spawn,
        script,
        timeout: timeoutSec,
        authorized,
      });
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6 animate-fadeUp">
      <div>
        <h1 className="font-display text-4xl text-ink-900">Frida</h1>
        <p className="mt-2 max-w-2xl text-ink-600">
          Android dynamic analysis via Frida. Attach or spawn a package, load a
          JS script, and collect <code className="font-mono text-xs">send()</code>{" "}
          messages. Missing binaries or devices skip gracefully.
        </p>
      </div>

      <div
        className={`border px-4 py-3 text-sm ${
          available
            ? "border-ink-800/10 bg-fog-50 text-ink-700"
            : "border-amber-800/20 bg-amber-50 text-amber-950"
        }`}
      >
        Frida runtime:{" "}
        <strong>{available ? "available" : "not installed / unavailable"}</strong>
        {available
          ? ` · ${devices.length} device(s) enumerated`
          : " — install frida-tools in the backend image and connect a USB device or emulator."}
      </div>

      {devices.length > 0 && (
        <ul className="font-mono text-xs text-ink-700">
          {devices.map((d) => (
            <li key={d.id}>
              {d.id} — {d.name} ({d.type})
            </li>
          ))}
        </ul>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        <label className="block space-y-1">
          <span className="font-mono text-[10px] uppercase text-ink-600">
            Device
          </span>
          <input
            className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            placeholder="usb"
          />
        </label>
        <label className="block space-y-1">
          <span className="font-mono text-[10px] uppercase text-ink-600">
            Package or PID
          </span>
          <input
            className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </label>
      </div>

      <div className="flex flex-wrap gap-4 text-sm">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={spawn}
            onChange={(e) => setSpawn(e.target.checked)}
          />
          Spawn (vs attach)
        </label>
        <label className="flex items-center gap-2">
          Timeout
          <input
            type="number"
            min={5}
            max={300}
            className="w-20 border border-ink-800/15 px-2 py-1 font-mono text-sm"
            value={timeoutSec}
            onChange={(e) => setTimeoutSec(Number(e.target.value))}
          />
          s
        </label>
      </div>

      <label className="block space-y-1">
        <span className="font-mono text-[10px] uppercase text-ink-600">
          Sample script
        </span>
        <select
          className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
          value={sampleKey}
          onChange={(e) => setSampleKey(e.target.value)}
        >
          {Object.keys(samples).map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
      </label>

      <label className="block space-y-1">
        <span className="font-mono text-[10px] uppercase text-ink-600">
          Script
        </span>
        <textarea
          className="min-h-[200px] w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-xs"
          value={script}
          onChange={(e) => setScript(e.target.value)}
          spellCheck={false}
        />
      </label>

      <label className="flex items-start gap-2 text-sm text-ink-700">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
          className="mt-1"
        />
        I own / am authorized to instrument this application
      </label>

      <button
        type="button"
        disabled={busy}
        onClick={run}
        className="bg-ink-900 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-fog-50 hover:bg-signal disabled:opacity-50"
      >
        {busy ? "Running…" : "Run Frida script"}
      </button>

      {error && <p className="font-mono text-xs text-red-700">{error}</p>}

      {result && (
        <div className="border border-ink-800/10 bg-fog-50/70 p-4">
          <p className="font-mono text-xs">
            Status: <strong>{result.status}</strong>
            {result.skip_reason ? ` — ${result.skip_reason}` : ""}
          </p>
          {result.stderr && (
            <pre className="mt-2 overflow-x-auto font-mono text-[11px] text-red-800">
              {result.stderr}
            </pre>
          )}
          <pre className="mt-2 max-h-96 overflow-auto font-mono text-[11px]">
            {(result.messages || []).join("\n") || result.stdout || "(no messages)"}
          </pre>
        </div>
      )}
    </div>
  );
}
