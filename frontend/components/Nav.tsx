"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import clsx from "clsx";
import { api, getToken, setToken, User } from "@/lib/api";

const links = [
  { href: "/", label: "Dashboard" },
  { href: "/deep-scan", label: "Deep Scan" },
  { href: "/attack-mode", label: "Attack Mode" },
  { href: "/api-mode", label: "API Mode" },
  { href: "/templates", label: "Templates" },
  { href: "/frida", label: "Frida" },
  { href: "/targets", label: "Targets" },
  { href: "/history", label: "History" },
  { href: "/settings", label: "Settings" },
];

export function Nav() {
  const pathname = usePathname();
  const [user, setUser] = useState<User | null>(null);
  const [authEnabled, setAuthEnabled] = useState(false);

  useEffect(() => {
    api
      .authStatus()
      .then((s) => {
        setAuthEnabled(s.auth_enabled);
        setUser(s.user);
        if (!s.user && getToken()) {
          api.me().then(setUser).catch(() => setToken(null));
        }
      })
      .catch(() => {});
  }, [pathname]);

  function logout() {
    setToken(null);
    setUser(null);
    window.location.href = "/login";
  }

  return (
    <header className="border-b border-ink-800/10 bg-fog-50/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-4 sm:px-6">
        <Link href="/" className="group flex items-baseline gap-2">
          <span className="font-display text-2xl tracking-tight text-ink-900 transition-colors group-hover:text-signal">
            P4NT3XIA
          </span>
          <span className="hidden font-mono text-[10px] uppercase tracking-[0.2em] text-ink-600 sm:inline">
            Phase 4
          </span>
        </Link>
        <nav className="flex flex-wrap items-center gap-1 sm:gap-2">
          {links.map((link) => {
            const active =
              link.href === "/"
                ? pathname === "/"
                : pathname.startsWith(link.href);
            return (
              <Link
                key={link.href}
                href={link.href}
                className={clsx(
                  "px-3 py-1.5 font-mono text-xs uppercase tracking-wider transition-colors",
                  active
                    ? "text-signal"
                    : "text-ink-600 hover:text-ink-900"
                )}
              >
                {link.label}
              </Link>
            );
          })}
          {authEnabled && (
            user ? (
              <button
                type="button"
                onClick={logout}
                className="ml-1 px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-ink-600 hover:text-ink-900"
                title={user.username}
              >
                {user.username} · out
              </button>
            ) : (
              <Link
                href="/login"
                className="ml-1 px-3 py-1.5 font-mono text-xs uppercase tracking-wider text-signal"
              >
                Login
              </Link>
            )
          )}
        </nav>
      </div>
    </header>
  );
}
