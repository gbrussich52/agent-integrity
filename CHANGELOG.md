# Changelog

## 0.4.0 (unreleased)

### What changed
- **Approved scheduled jobs ("loops").** A second signed manifest, `loops.json` (+ `.sig`, own rollback
  mark `loops_last_seen.json`), signed with the same key and `allowed_signers`. It carries `"kind": "loops"`;
  `check`, `promote` and the gate refuse a manifest whose kind is not the one they expect, so the main
  manifest's signature cannot stand in for it (and the other way round). Per job it records the exact
  argv, working directory, environment, schedule keys, the sha256 of the gated plist, and the sha256 of
  every file the job can run: argv files, `PROMPT.md`/`prompt.md` beside the program, sourced shell
  helpers and imported python modules (depth 5), caller-supplied extra files, plus one opaque extra
  blob stored as a sha256 only.
- **`run-loop LABEL` (the gate).** A job's plist is rewritten to start the root-owned copy of this tool
  with `run-loop LABEL`. The gate verifies the signature and sequence, re-hashes the plist and the file
  set, and either `execve`s the approved argv with the approved cwd and env (inherited environment
  dropped, `PATH` reset) or exits 3, appends a line to `loops-refused.jsonl`, runs the optional
  `loops_notify_cmd` (argv list, message as last argument, 10 s timeout, failure ignored) and runs nothing.
  New store config keys: `loops_notify_cmd`, `loops_forbid_dirs` (a file set touching one is refused),
  `loops_enforce`.
- **`loops propose | sign | apply | unadopt | status`.** `propose` (no sudo) builds a pending manifest
  and staged gated plists and prints a review with signature-scan hits; it understands plists that are
  already gated by reading the originals from the signed manifest. `apply` backs up each replaced plist
  and reloads it. `unadopt LABEL` restores the backup. `status [--json]` reports approved, changed,
  unapproved, not-gated or missing per label.
- **Root watcher.** `check` reports plists that are not in the loops manifest or differ from it. With
  `loops_enforce: true` the root daemon runs `launchctl bootout gui/<uid>/<label>` for them and records
  `loops-drift` and `loops-bootout` events in the trail. Plists you do not gate are adopted as
  *pinned* entries (hash only). The path of `launchctl` can be overridden with
  `AGENT_INTEGRITY_LAUNCHCTL` (tests). The root daemon plist gains `WatchPaths` on the user's
  LaunchAgents directory, so a new or edited plist is checked at once instead of within the hour.
- `ssh-keygen` is now called by absolute path when one exists in a system location, instead of through `PATH`.

### Prior behavior
Nothing watched scheduled jobs. A job's plist, script, prompt file and helpers were ordinary files, so
anything running as the user could edit them and the next unattended run would do what the edit said.
`check` only compared the files listed in `manifest.json`.

### Fixed
- `install-root.sh` built the daemon's arguments as one string and word-split it, so a store path
  containing a space (`/Library/Application Support/...`) became two arguments and the daemon failed
  with "unrecognized arguments" on every run. Each argument is now written as its own element (and
  XML-escaped; quoted for systemd). A test installs into a path with spaces and parses the plist back.

### Why
Approving a job once should be enough for it to keep running on its schedule, and any change to what it
runs should need your signature, not an agent's. The gate puts that decision at run time, where the
risk is, rather than only at the next scan.

## 0.3.1 (unreleased)
- Explanations end in a concrete fix chosen by the kind of change: added → "Remove X unless you added it"; removed → "Put it back"; turned off → "Turn it back on"; changed → "Change it back"; possible key leak → also rotate it. Sentence 2 says the real-world result ("it downloads and runs code from the internet"). Prior: actions were mostly "Review X". Why: a Claude reader scored the old text about 3.3 of 5 for clarity, mainly because "Review X" does not tell a non-expert what to do.
- gpt-oss runs with `think: "low"`, `num_ctx` 8192, and a 60 s default `explain_timeout` (was 30 s). Prior: gpt-oss answers took 25–37 s, so many calls timed out, and two timeouts end the explainer run. Answers now take about 5 s.
- Default explainer model order: gpt-oss, then gemma3, then llama3 (was gemma3 first). Why: bench average gpt-oss 96% over 3 runs vs gemma3 73%.
- Bench: `action_concrete` check; results are now read as three-run averages.
- Text output no longer drops a file's 4th+ change silently; it prints `...+N more change(s)` (previously cut at 3 with no notice).

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
