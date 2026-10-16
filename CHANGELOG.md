# Changelog

## 0.3.0 (unreleased)

### What changed
- Hash-chained, append-only audit trail (`events.jsonl`) with `verify-log`; protected mode fails closed (exit 3) on a broken chain. Daily snapshots, weekly dashboard copies, `retention_days` (default 365) with a `prune` event that keeps the chain valid. The AI summary is a separate `explained` event written by the user job, never by root.
- `history KEY`, `diff --since 30d|90d|180d|365d|signed`, `report --as-of YYYY-MM-DD`. Dashboard gains "Since you last signed", "Slow-drift warnings" and a "Then vs now" panel (no JavaScript).
- Slow-drift rules: cumulative raising, creep (`creep_threshold`, default 5 in 90 days), low-and-slow, dormant reappearance. Alerts fire once per finding.
- Explainer prompt rewritten for plain English (what changed, what an agent can do now, what to do); it also sees the last 3 trail events for the file. `bench/` scores it on 15 scenarios; see `bench/HISTORY.md`.
- `promote` writes a `sign` event and keeps `signed/<seq>.json.gz` so a past dashboard shows the right baseline.

### Prior behavior
0.2.x kept only the current overlay and a short history strip. A settled change left no durable record,
and a series of small accepted changes was never compared against the signed baseline as a whole.

### Why
Settling is what keeps the daily load small, but it also let several harmless steps add up unseen. The
trail and the cumulative rules make that visible without asking for more reviews.

## 0.2.1 (unreleased)
- Explainer: no per-run count cap by default (`--explain-max 0`). Prior: 10 fresh calls per run. Why: the model is local and free; a 20-minute time budget (was 3) still keeps hourly runs from overlapping, and leftovers are explained next run from the cache.
- Explanations now carry `why`, `detail` (exact names, commands, paths) and `action` besides the plain summary. Terminal shows summary + action; the dashboard shows Why, What to do, and a collapsible Technical detail. Prior: summary + one-sentence why.
- `quarantine` refuses entries inside shared files (`~/.claude.json#mcpServers`); the dashboard suggests removing the entry by hand instead.

## 0.2.0 (2026-10-16)

### What changed
- `watch`, `report --html` and `quarantine KEY` commands; `install-user.sh`.
- Semantic config diff with a per-change plain-English line and risk class.
- Rolling trust overlay (`accepted.json`) with rule R-settle: neutral, clean changes auto-accept after
  `trust_after` (24h). Raising changes still need `sign`.
- Optional local-LLM explainer (`--explain`), escalate-only, loopback only unless `explain_allow_remote`.
- Alerts on new raising items only, and a self-contained HTML dashboard.
- Manifests now carry normalized config fingerprints (secrets and long strings hashed).
- Every output states `mode: protected` or `mode: unprotected (detection only)`.

### Prior behavior
0.1.0 reported every byte-level change and a human reviewed and re-signed all of them, which does not
scale and hid the one dangerous change among harmless ones.

### Why
The reviewer's attention should go only where a change can raise what an agent is allowed to do.
The model is advisory and can only raise a risk, because attacker-written file text must never be able
to talk the tool into accepting it.

## 0.1.0 (unreleased, 2026-10-16)

First standalone release, extracted from a single-user script and hardened.

### What the original did
A single 541-line script kept inside the author's own repository. It hashed agent files into a
manifest stored beside the files it watched, compared them on a schedule, scanned changed files for
risky patterns, and auto-accepted plugin updates from known marketplaces. It covered Claude Code
only, printed unbounded text, and a companion PreToolUse hook refused fetch-and-run shell commands.

### Why it changed
The manifest, the verifier and the schedule were all writable by the account being watched, so an
attacker running as that account (exactly what a poisoned agent is) could rewrite the evidence. It
also drowned a reviewer: thousands of plugin-cache files per update hid the one changed settings
file that mattered.

### Changed
1. Manifest moved out of the user tree into a configurable store (`--store`; root-owned after
   `install-root.sh`). It is signed with `ssh-keygen -Y sign` (namespace `agent-integrity`); `check`
   verifies against an `allowed_signers` file in the store and fails closed. `baseline` writes a pending
   manifest to the user directory; `sign` and `promote` install it. A signed sequence number and
   timestamp, plus a last-seen sequence in the store, defeat rollback. A root heartbeat makes a stopped
   checker read as STALE.
2. Added `install-root.sh` (root launchd daemon or systemd timer) and a read-only SessionStart hook.
3. Added Codex and Cursor coverage; all surfaces are one data table.
4. Added `--format text|json|sarif` to `check` and `scan` (SARIF 2.1.0).
5. Added the scan-before-baseline guard with per-file `--i-reviewed <sha>`.
6. Reviewable drift: output grouped by source and capped at 20 lines; `.trash/` and `worktrees/`
   excluded; official-marketplace plugin updates auto-accepted only on signed-manifest provenance plus
   a clean signature scan, reported as one line with a count. Provenance is stricter than the original:
   the marketplace must be recorded in the signed manifest, unchanged, and match an official prefix.
7. Genericised the remote-exec gate (no internal names, configurable log directory).

### Not carried over
- `remediate` (quarantine of flagged files) and `allow-audit`: out of scope for this release.
- The estate-specific allowlist and manifest. The allowlist now lives in the store as `allow.json`.

### Known limits
See the threat model in `README.md`. In short: regex signatures, trust on first use, and
detection-only until the root install is done.
