"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, User } from "@/lib/api";

export default function SettingsPage() {
  const [authEnabled, setAuthEnabled] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [newUser, setNewUser] = useState({
    username: "",
    password: "",
    role: "operator",
  });
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    api.authStatus().then((s) => {
      setAuthEnabled(s.auth_enabled);
      setUser(s.user);
      if (s.user?.role === "admin" || !s.auth_enabled) {
        api.listUsers().then(setUsers).catch(() => {});
      }
    });
  }, []);

  async function createUser() {
    setMsg(null);
    try {
      await api.createUser(newUser);
      setMsg(`Created ${newUser.username}`);
      setNewUser({ username: "", password: "", role: "operator" });
      const list = await api.listUsers();
      setUsers(list);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="space-y-6 animate-fadeUp">
      <h1 className="font-display text-4xl text-ink-900">Settings</h1>
      <p className="max-w-2xl text-ink-600">
        Phase 4 adds optional multi-user JWT auth, Frida, API Mode, and payload
        templates. Override backends with{" "}
        <code className="font-mono text-sm">P4NT3XIA_*</code> environment
        variables.
      </p>

      <section className="border border-ink-800/10 bg-fog-50/60 p-4">
        <h2 className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
          Auth
        </h2>
        <p className="mt-2 text-sm text-ink-700">
          Enabled: <strong>{authEnabled ? "yes" : "no"}</strong>
          {user ? ` · signed in as ${user.username} (${user.role})` : ""}
        </p>
        <p className="mt-1 text-sm text-ink-600">
          Set <code className="font-mono text-xs">P4NT3XIA_AUTH_ENABLED=true</code>{" "}
          and <code className="font-mono text-xs">P4NT3XIA_JWT_SECRET</code> to
          require login. Optional bootstrap:{" "}
          <code className="font-mono text-xs">P4NT3XIA_BOOTSTRAP_ADMIN_USER</code>{" "}
          / <code className="font-mono text-xs">_PASSWORD</code>.
        </p>
        <Link
          href="/login"
          className="mt-3 inline-block font-mono text-xs uppercase tracking-wider text-signal"
        >
          Login / register →
        </Link>

        {(user?.role === "admin" || (!authEnabled && users.length >= 0)) && (
          <div className="mt-4 space-y-3 border-t border-ink-800/10 pt-4">
            <h3 className="font-mono text-[10px] uppercase text-ink-600">
              Users
            </h3>
            {users.length > 0 && (
              <ul className="font-mono text-xs">
                {users.map((u) => (
                  <li key={u.id}>
                    {u.username} · {u.role}
                    {!u.is_active ? " (disabled)" : ""}
                  </li>
                ))}
              </ul>
            )}
            <div className="grid gap-2 sm:grid-cols-4">
              <input
                placeholder="username"
                className="border border-ink-800/15 px-2 py-1.5 font-mono text-xs"
                value={newUser.username}
                onChange={(e) =>
                  setNewUser({ ...newUser, username: e.target.value })
                }
              />
              <input
                type="password"
                placeholder="password"
                className="border border-ink-800/15 px-2 py-1.5 font-mono text-xs"
                value={newUser.password}
                onChange={(e) =>
                  setNewUser({ ...newUser, password: e.target.value })
                }
              />
              <select
                className="border border-ink-800/15 px-2 py-1.5 font-mono text-xs"
                value={newUser.role}
                onChange={(e) =>
                  setNewUser({ ...newUser, role: e.target.value })
                }
              >
                <option value="viewer">viewer</option>
                <option value="operator">operator</option>
                <option value="admin">admin</option>
              </select>
              <button
                type="button"
                onClick={createUser}
                className="bg-ink-900 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-fog-50"
              >
                Add user
              </button>
            </div>
            {msg && <p className="font-mono text-xs text-ink-700">{msg}</p>}
          </div>
        )}
      </section>

      <div className="overflow-x-auto border border-ink-800/10">
        <table className="w-full min-w-[520px] text-left text-sm">
          <thead className="bg-ink-900 text-fog-100">
            <tr className="font-mono text-[10px] uppercase tracking-wider">
              <th className="px-3 py-2.5">Variable</th>
              <th className="px-3 py-2.5">Purpose</th>
            </tr>
          </thead>
          <tbody className="font-mono text-xs">
            {[
              ["P4NT3XIA_AUTH_ENABLED", "Require JWT (true/false)"],
              ["P4NT3XIA_JWT_SECRET", "Signing secret for tokens"],
              ["P4NT3XIA_BOOTSTRAP_ADMIN_USER", "First admin username"],
              ["P4NT3XIA_BOOTSTRAP_ADMIN_PASSWORD", "First admin password"],
              ["P4NT3XIA_DATABASE_URL", "Postgres URL (else SQLite)"],
              ["P4NT3XIA_HYDRA_PATH", "hydra binary"],
              ["P4NT3XIA_SSRFMAP_PATH", "SSRFmap wrapper / script"],
              ["P4NT3XIA_JWT_TOOL_PATH", "JWT_Tool wrapper / script"],
              ["P4NT3XIA_FRIDA_PATH", "frida CLI (optional)"],
              ["P4NT3XIA_HYDRA_WORDLIST", "Password list for hydra"],
              ["P4NT3XIA_FFUF_WORDLIST", "Directory wordlist"],
              ["P4NT3XIA_CORS_ORIGINS", "Allowed frontend origins (JSON)"],
            ].map(([k, v], i) => (
              <tr
                key={k}
                className={i % 2 === 0 ? "bg-fog-50/80" : "bg-fog-100/50"}
              >
                <td className="px-3 py-2.5 text-ink-900">{k}</td>
                <td className="px-3 py-2.5 text-ink-600">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-sm text-ink-600">
        Production:{" "}
        <code className="font-mono text-xs">
          docker compose -f docker-compose.prod.yml up --build -d
        </code>
      </p>
    </div>
  );
}
