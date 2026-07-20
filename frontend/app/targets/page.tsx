"use client";

import { FormEvent, useEffect, useState } from "react";
import Link from "next/link";
import { api, Target } from "@/lib/api";
import { StatusBadge } from "@/components/Badges";

export default function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [value, setValue] = useState("");
  const [type, setType] = useState("web");
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  async function refresh() {
    try {
      setTargets(await api.listTargets());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load targets");
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!value.trim()) return;
    setSaving(true);
    setError(null);
    try {
      const tagList = tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      if (editingId) {
        await api.updateTarget(editingId, {
          value: value.trim(),
          type,
          tags: tagList,
          notes: notes.trim() || null,
        });
      } else {
        await api.createTarget({
          value: value.trim(),
          type,
          tags: tagList,
          notes: notes.trim() || null,
        });
      }
      setValue("");
      setTags("");
      setNotes("");
      setEditingId(null);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  function startEdit(t: Target) {
    setEditingId(t.id);
    setValue(t.value);
    setType(t.type);
    setTags((t.tags || []).join(", "));
    setNotes(t.notes || "");
  }

  async function onDelete(id: string) {
    if (!confirm("Delete this target and its scan history?")) return;
    try {
      await api.deleteTarget(id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  }

  return (
    <div className="space-y-8 animate-fadeUp">
      <header>
        <p className="font-mono text-[11px] uppercase tracking-[0.25em] text-signal">
          Target library
        </p>
        <h1 className="mt-1 font-display text-4xl text-ink-900">Targets</h1>
        <p className="mt-2 max-w-xl text-ink-600">
          Save hosts for re-scan. Tags and notes help organize engagements;
          history links show prior Deep Scan and Attack runs.
        </p>
      </header>

      <form
        onSubmit={onSubmit}
        className="space-y-4 border border-ink-800/10 bg-fog-50/70 p-5"
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="block space-y-1 sm:col-span-2">
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              URL / Domain / IP
            </span>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              required
              placeholder="https://app.example.com"
              className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-signal/40"
            />
          </label>
          <label className="block space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              Type
            </span>
            <select
              value={type}
              onChange={(e) => setType(e.target.value)}
              className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
            >
              <option value="web">web</option>
              <option value="api">api</option>
              <option value="android_backend">android_backend</option>
            </select>
          </label>
          <label className="block space-y-1">
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              Tags (comma-separated)
            </span>
            <input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="prod, scope-a"
              className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
            />
          </label>
          <label className="block space-y-1 sm:col-span-2">
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              Notes
            </span>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
              className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
            />
          </label>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            type="submit"
            disabled={saving}
            className="bg-ink-900 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-fog-50 hover:bg-signal disabled:opacity-50"
          >
            {editingId ? "Update target" : "Save target"}
          </button>
          {editingId && (
            <button
              type="button"
              onClick={() => {
                setEditingId(null);
                setValue("");
                setTags("");
                setNotes("");
              }}
              className="border border-ink-800/20 px-5 py-2.5 font-mono text-xs uppercase tracking-wider text-ink-700"
            >
              Cancel edit
            </button>
          )}
        </div>
      </form>

      {error && <p className="font-mono text-sm text-warn-high">{error}</p>}

      {!targets.length ? (
        <p className="font-mono text-sm text-ink-600">No saved targets yet.</p>
      ) : (
        <div className="overflow-x-auto border border-ink-800/10">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="bg-ink-900 text-fog-100">
              <tr className="font-mono text-[10px] uppercase tracking-wider">
                <th className="px-3 py-2.5">Target</th>
                <th className="px-3 py-2.5">Type</th>
                <th className="px-3 py-2.5">Tags</th>
                <th className="px-3 py-2.5">Scans</th>
                <th className="px-3 py-2.5">Last scan</th>
                <th className="px-3 py-2.5">Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t, i) => (
                <tr
                  key={t.id}
                  className={i % 2 === 0 ? "bg-fog-50/80" : "bg-fog-100/50"}
                >
                  <td className="px-3 py-2.5">
                    <p className="font-medium text-ink-900">{t.value}</p>
                    {t.notes && (
                      <p className="mt-0.5 text-xs text-ink-600">{t.notes}</p>
                    )}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs">{t.type}</td>
                  <td className="px-3 py-2.5 font-mono text-xs text-ink-600">
                    {(t.tags || []).join(", ") || "—"}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs">
                    {t.scan_count ?? 0}
                  </td>
                  <td className="px-3 py-2.5">
                    {t.last_scan_status ? (
                      <div className="space-y-1">
                        <StatusBadge status={t.last_scan_status} />
                        <p className="font-mono text-[10px] text-ink-600">
                          {t.last_scan_mode} ·{" "}
                          {t.last_scan_at
                            ? new Date(t.last_scan_at).toLocaleString()
                            : "—"}
                        </p>
                      </div>
                    ) : (
                      <span className="font-mono text-xs text-ink-600">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex flex-wrap gap-2">
                      <Link
                        href={`/deep-scan?target=${encodeURIComponent(t.value)}`}
                        className="font-mono text-[10px] uppercase tracking-wider text-signal hover:underline"
                      >
                        Deep Scan
                      </Link>
                      <Link
                        href={`/attack-mode?target=${encodeURIComponent(t.value)}`}
                        className="font-mono text-[10px] uppercase tracking-wider text-warn-high hover:underline"
                      >
                        Attack
                      </Link>
                      <button
                        type="button"
                        onClick={() => startEdit(t)}
                        className="font-mono text-[10px] uppercase tracking-wider text-ink-600 hover:underline"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => onDelete(t.id)}
                        className="font-mono text-[10px] uppercase tracking-wider text-warn-high hover:underline"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
