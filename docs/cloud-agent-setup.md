# Cursor Cloud Agent / Automations setup

Repo-side agent guidance is already in:

- `AGENTS.md` — project briefing for Cloud Agents
- `.cursor/rules/*.mdc` — always-on and path-scoped rules

## Automations editor (manual)

Interactive Automations creation needs the **Agents Window** finish path (`open_automation`), which is not available in every chat session.

To finish creating a useful automation for this repo:

1. Open Cursor **Agents Window** (not a plain chat-only session).
2. Ask: create an automation that runs on **pull request opened** for `SaenaAsColeAllStar/p4nt3xia`, with instructions to review changes against `docs/prd/mvp-1.md` and `AGENTS.md` (tool wrappers, auth banner, no secrets).
3. Enable tools: **Comment on PRs** (and optionally **Manage check runs**).
4. Confirm repo `SaenaAsColeAllStar/p4nt3xia`, default branch `main`.
5. Cloud compute: [Cloud Agents dashboard](https://cursor.com/dashboard?tab=cloud-agents).

Suggested automation intent:

| Field | Value |
|-------|--------|
| Name | P4NT3XIA PR review |
| Trigger | Pull request opened on this repo |
| Tools | Comment on PRs |
| Outcome | PR comment covering Phase scope, tool-runner skips, auth UI, and secrets |

## Cloud Agents dashboard

Connect the GitHub repo `SaenaAsColeAllStar/p4nt3xia` under Cloud Agents so background agents can check out `main` with these rules present.
