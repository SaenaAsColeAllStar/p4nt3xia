"use client";

import { FormEvent, useEffect, useState } from "react";
import {
  api,
  PayloadTemplate,
  TemplateRunResult,
} from "@/lib/api";

const emptyForm = {
  name: "",
  category: "custom",
  description: "",
  method: "GET",
  path_template: "/?q={{payload}}",
  body_template: "",
  payloads_text: "<script>alert(1)</script>",
  match_body_text: "",
  tags_text: "",
};

export default function TemplatesPage() {
  const [templates, setTemplates] = useState<PayloadTemplate[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [target, setTarget] = useState("https://httpbin.org/get");
  const [authorized, setAuthorized] = useState(false);
  const [runResult, setRunResult] = useState<TemplateRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const list = await api.listTemplates();
      setTemplates(list);
      if (!selected && list[0]) setSelected(list[0].id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const t = templates.find((x) => x.id === selected);
    if (!t) return;
    setForm({
      name: t.name,
      category: t.category,
      description: t.description || "",
      method: t.method,
      path_template: t.path_template,
      body_template: t.body_template || "",
      payloads_text: (t.payloads || []).join("\n"),
      match_body_text: (t.match_body_contains || []).join("\n"),
      tags_text: (t.tags || []).join(", "),
    });
  }, [selected, templates]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const body = {
      name: form.name,
      category: form.category,
      description: form.description || null,
      method: form.method,
      path_template: form.path_template,
      body_template: form.body_template || null,
      payloads: form.payloads_text
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      match_body_contains: form.match_body_text
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      match_status: [] as number[],
      headers: {} as Record<string, string>,
      tags: form.tags_text
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    };
    try {
      if (selected) {
        await api.updateTemplate(selected, body);
      } else {
        const created = await api.createTemplate(body);
        setSelected(created.id);
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function createNew() {
    setSelected(null);
    setForm(emptyForm);
    setRunResult(null);
  }

  async function remove() {
    if (!selected) return;
    if (!confirm("Delete this template?")) return;
    await api.deleteTemplate(selected);
    setSelected(null);
    await load();
  }

  async function run() {
    if (!selected) {
      setError("Save or select a template first");
      return;
    }
    setError(null);
    setBusy(true);
    setRunResult(null);
    try {
      const res = await api.runTemplate(selected, {
        target,
        authorized,
      });
      setRunResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6 animate-fadeUp">
      <div>
        <h1 className="font-display text-4xl text-ink-900">
          Payload templates
        </h1>
        <p className="mt-2 max-w-2xl text-ink-600">
          Build reusable payload sets with{" "}
          <code className="font-mono text-xs">{"{{payload}}"}</code> in path or
          body. Match on response body substrings when probing authorized
          targets.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-[240px_1fr]">
        <aside className="space-y-2 border border-ink-800/10 bg-fog-50/60 p-3">
          <button
            type="button"
            onClick={createNew}
            className="w-full border border-ink-800/15 px-3 py-2 font-mono text-[10px] uppercase tracking-wider hover:border-signal"
          >
            + New template
          </button>
          <ul className="max-h-[480px] space-y-1 overflow-y-auto">
            {templates.map((t) => (
              <li key={t.id}>
                <button
                  type="button"
                  onClick={() => setSelected(t.id)}
                  className={`w-full px-2 py-1.5 text-left font-mono text-xs ${
                    selected === t.id
                      ? "bg-ink-900 text-fog-50"
                      : "text-ink-700 hover:bg-fog-100"
                  }`}
                >
                  <span className="block truncate">{t.name}</span>
                  <span className="text-[10px] uppercase opacity-70">
                    {t.category}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <div className="space-y-4">
          <form onSubmit={save} className="space-y-3 border border-ink-800/10 bg-fog-50/50 p-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block space-y-1">
                <span className="font-mono text-[10px] uppercase text-ink-600">Name</span>
                <input
                  className="w-full border border-ink-800/15 bg-white px-3 py-2 text-sm"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  required
                />
              </label>
              <label className="block space-y-1">
                <span className="font-mono text-[10px] uppercase text-ink-600">Category</span>
                <input
                  className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
                  value={form.category}
                  onChange={(e) => setForm({ ...form, category: e.target.value })}
                />
              </label>
            </div>
            <label className="block space-y-1">
              <span className="font-mono text-[10px] uppercase text-ink-600">Description</span>
              <input
                className="w-full border border-ink-800/15 bg-white px-3 py-2 text-sm"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </label>
            <div className="grid gap-3 sm:grid-cols-[100px_1fr]">
              <label className="block space-y-1">
                <span className="font-mono text-[10px] uppercase text-ink-600">Method</span>
                <select
                  className="w-full border border-ink-800/15 bg-white px-2 py-2 font-mono text-sm"
                  value={form.method}
                  onChange={(e) => setForm({ ...form, method: e.target.value })}
                >
                  {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
                    <option key={m}>{m}</option>
                  ))}
                </select>
              </label>
              <label className="block space-y-1">
                <span className="font-mono text-[10px] uppercase text-ink-600">
                  Path template
                </span>
                <input
                  className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
                  value={form.path_template}
                  onChange={(e) =>
                    setForm({ ...form, path_template: e.target.value })
                  }
                />
              </label>
            </div>
            <label className="block space-y-1">
              <span className="font-mono text-[10px] uppercase text-ink-600">
                Body template (optional)
              </span>
              <textarea
                className="min-h-[60px] w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-xs"
                value={form.body_template}
                onChange={(e) =>
                  setForm({ ...form, body_template: e.target.value })
                }
              />
            </label>
            <label className="block space-y-1">
              <span className="font-mono text-[10px] uppercase text-ink-600">
                Payloads (one per line)
              </span>
              <textarea
                className="min-h-[100px] w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-xs"
                value={form.payloads_text}
                onChange={(e) =>
                  setForm({ ...form, payloads_text: e.target.value })
                }
              />
            </label>
            <label className="block space-y-1">
              <span className="font-mono text-[10px] uppercase text-ink-600">
                Match body contains (one per line)
              </span>
              <textarea
                className="min-h-[60px] w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-xs"
                value={form.match_body_text}
                onChange={(e) =>
                  setForm({ ...form, match_body_text: e.target.value })
                }
              />
            </label>
            <div className="flex flex-wrap gap-2">
              <button
                type="submit"
                disabled={busy}
                className="bg-ink-900 px-4 py-2 font-mono text-xs uppercase tracking-wider text-fog-50 hover:bg-signal disabled:opacity-50"
              >
                {selected ? "Save" : "Create"}
              </button>
              {selected && (
                <button
                  type="button"
                  onClick={remove}
                  className="px-4 py-2 font-mono text-xs uppercase tracking-wider text-red-700"
                >
                  Delete
                </button>
              )}
            </div>
          </form>

          <div className="space-y-3 border border-ink-800/10 p-4">
            <h2 className="font-mono text-[10px] uppercase tracking-wider text-ink-600">
              Run against target
            </h2>
            <input
              className="w-full border border-ink-800/15 bg-white px-3 py-2 font-mono text-sm"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://authorized-target.example"
            />
            <label className="flex items-start gap-2 text-sm text-ink-700">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-1"
              />
              Authorized to probe this target
            </label>
            <button
              type="button"
              disabled={busy || !selected}
              onClick={run}
              className="bg-signal px-4 py-2 font-mono text-xs uppercase tracking-wider text-white disabled:opacity-50"
            >
              {busy ? "Running…" : "Run template"}
            </button>
          </div>

          {error && (
            <p className="font-mono text-xs text-red-700">{error}</p>
          )}

          {runResult && (
            <div className="border border-ink-800/10 bg-fog-50/70 p-4">
              <p className="font-mono text-xs text-ink-700">
                {runResult.matched_count}/{runResult.total_tested} matched ·{" "}
                {runResult.template_name}
              </p>
              <ul className="mt-3 max-h-80 space-y-2 overflow-y-auto">
                {runResult.hits.map((h, i) => (
                  <li
                    key={i}
                    className={`border px-3 py-2 font-mono text-[11px] ${
                      h.matched
                        ? "border-signal/40 bg-signal/5"
                        : "border-ink-800/10"
                    }`}
                  >
                    <div className="flex justify-between gap-2">
                      <span className="truncate">{h.payload || "(empty)"}</span>
                      <span>{h.status_code}</span>
                    </div>
                    <div className="mt-1 truncate text-ink-600">{h.url}</div>
                    {h.matched && h.poc_curl && (
                      <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all text-[10px]">
                        {h.poc_curl}
                      </pre>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
