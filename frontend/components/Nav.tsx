"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import clsx from "clsx";

const links = [
  { href: "/", label: "Dashboard" },
  { href: "/deep-scan", label: "Deep Scan" },
  { href: "/attack-mode", label: "Attack Mode" },
  { href: "/history", label: "History" },
  { href: "/settings", label: "Settings" },
];

export function Nav() {
  const pathname = usePathname();

  return (
    <header className="border-b border-ink-800/10 bg-fog-50/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-4 sm:px-6">
        <Link href="/" className="group flex items-baseline gap-2">
          <span className="font-display text-2xl tracking-tight text-ink-900 transition-colors group-hover:text-signal">
            P4NT3XIA
          </span>
          <span className="hidden font-mono text-[10px] uppercase tracking-[0.2em] text-ink-600 sm:inline">
            Phase 1
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
        </nav>
      </div>
    </header>
  );
}
