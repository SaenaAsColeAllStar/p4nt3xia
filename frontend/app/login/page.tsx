"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, setToken } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [authEnabled, setAuthEnabled] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.authStatus().then((s) => setAuthEnabled(s.auth_enabled)).catch(() => setAuthEnabled(false));
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === "register") {
        await api.register({ username, password });
        const tok = await api.login(username, password);
        setToken(tok.access_token);
      } else {
        const tok = await api.login(username, password);
        setToken(tok.access_token);
      }
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md space-y-6 animate-fadeUp">
      <h1 className="font-display text-4xl text-ink-900">Sign in</h1>
      {authEnabled === false && (
        <p className="border border-ink-800/10 bg-fog-50 px-4 py-3 text-sm text-ink-600">
          Auth is currently <strong>disabled</strong> on the backend
          (<code className="font-mono text-xs">P4NT3XIA_AUTH_ENABLED=false</code>).
          You can still create a local account for later, or enable auth in Settings / Docker env.
        </p>
      )}
      <form onSubmit={onSubmit} className="space-y-4 border border-ink-800/10 bg-fog-50/60 p-6">
        <label className="block space-y-1">
          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
            Username
          </span>
          <input
            className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm outline-none focus:border-signal"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            minLength={3}
          />
        </label>
        <label className="block space-y-1">
          <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
            Password
          </span>
          <input
            type="password"
            className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm outline-none focus:border-signal"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            required
            minLength={8}
          />
        </label>
        {error && (
          <p className="font-mono text-xs text-red-700">{error}</p>
        )}
        <div className="flex flex-wrap gap-2">
          <button
            type="submit"
            disabled={busy}
            className="bg-ink-900 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-fog-50 transition hover:bg-signal disabled:opacity-50"
          >
            {busy ? "…" : mode === "login" ? "Login" : "Register"}
          </button>
          <button
            type="button"
            className="px-4 py-2.5 font-mono text-xs uppercase tracking-wider text-ink-600 hover:text-ink-900"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
          >
            {mode === "login" ? "Need an account?" : "Have an account?"}
          </button>
        </div>
      </form>
      <p className="text-sm text-ink-600">
        Roles: <span className="font-mono text-xs">admin</span> (manage users),{" "}
        <span className="font-mono text-xs">operator</span> (run scans),{" "}
        <span className="font-mono text-xs">viewer</span> (read-only).
      </p>
    </div>
  );
}
