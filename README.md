# agent-integrity

Tamper-evident monitoring for the files that steer your AI coding agents: skills, agents, hooks,
settings, MCP servers, plugins, and rules files for Claude Code, Codex and Cursor. Python 3
standard library only. macOS first, Linux paths where they come free.

## Why this exists

In August 2026 a developer asked an AI assistant for a transcription app. The assistant gave an
unverified link to a copycat site. The developer pasted that site's one-line terminal command, and it
ran instantly. The malware then wrote a poisoned `SKILL.md` into the developer's agent
configuration, so every later session loaded attacker instructions as if the user had written them.

Two weak points made that work. The install was a fetch piped straight into a shell, and nothing
noticed that an agent file changed. This project addresses both: a gate that refuses
fetch-and-run commands (`hooks/block-remote-exec.py`), and a signed baseline of agent files that
reports any change (`agent_integrity.py`).

## What it does

- Takes a baseline (SHA-256 per file, plus the `mcpServers` section of `~/.claude.json`) of every
  watched surface. The surfaces are one data table (`SURFACES` in `agent_integrity.py`), so adding an
  agent is one entry.
- `check` compares today's files with the signed baseline and groups drift by source (agent,
  plugin, marketplace) so a human can review it. The human report is capped at 20 lines.
- Scans changed and new files for behaviours a poisoned agent file needs: fetch-and-execute,
  decode-and-execute, credential reads, exfiltration hosts, instructions to hide actions from the
  user, persistence, and invisible unicode.
- `baseline` refuses to bless a new or changed file that has an unreviewed high-severity hit.
- Exports `--format text|json|sarif` (SARIF 2.1.0, one rule per signature).

## Autopilot (0.2.0): the tool reviews drift; you sign only risk-raising changes

Reviewing every change by hand does not scale, so `watch` does the first pass.

- **Semantic diff.** Config files (Claude `settings*.json`, `~/.claude.json` `mcpServers`, `.mcp.json`,
  Codex `config.toml`, Cursor `mcp.json`) are compared as parsed structure, not bytes. Each change
  gets a plain-English line and a risk: `neutral` (model, theme, a permission `allow` removed, a
  `deny` added), `review-soon` (a clean user-authored skill or rule), or `raising` (a hook or MCP
  server added or changed, an `allow` added, a `deny` removed, the sandbox loosened, a
  dangerous/bypass flag, a proxy or `*_BASE_URL` override). Anything the diff does not understand is
  treated as raising. Secrets are hashed before they reach the manifest.
- **Settling.** A neutral change with a clean scan is accepted on its own after `trust_after`
  (default 24h) if it has not changed again and nothing escalated it. Raising changes never settle;
  they need `sign` after you look at them.
- **Local explainer (optional, `watch --explain`).** A small local model (Ollama, or any
  OpenAI-compatible server on loopback) writes a one-line summary of each change. Escalate-only:
  the final risk is the higher of the deterministic risk and the model's. The model can never lower
  a risk, accept a change, or edit a baseline, because its input is attacker-controlled file text and
  a poisoned file would simply tell it to say "safe". Any model failure falls back to the
  deterministic text. File excerpts (at most 8 KB) are fenced with a random nonce and labelled
  untrusted in the prompt.
- **Alerts and dashboard.** Desktop notification (and an optional webhook) only for a new raising
  item, a threat, STALE, untrusted or rollback; review-soon items batch into one alert a day.
  `watch --html PATH` or `report --html PATH` writes one self-contained page (no scripts, no external
  assets, light and dark) with the exact command for each red item.
- **`quarantine KEY`** moves a flagged file into `<user dir>/quarantine/<time>/` and prints the
  restore command. It refuses any path that is not one of the watched surfaces.
- `install-user.sh` (no sudo) schedules `watch --explain` hourly via a LaunchAgent or systemd user
  timer; `--uninstall` removes it.

`explain_allow_remote` (config, default `false`). The explainer refuses any non-loopback backend.
Setting it to `true` sends the content of changed agent files, which can include secrets you
pasted into them, to that remote host. Leave it off unless you accept that.

| | Protected (root install) | Unprotected (user mode) |
|---|---|---|
| Baseline and settle overlay | root-owned store; an agent running as you cannot edit them | in your user directory; an agent running as you could rewrite them |
| Output label | `mode: protected` | `mode: unprotected (detection only)` on every output |
| Auto-accept (settle) | written by the root daemon | written by `watch`, so only as trustworthy as your account |
| `escalations.json` (user side) | read as hold-only input: forging it can delay a settle, never cause one | same |

## Audit trail and look-back (0.3.0)

Settling and autopilot keep the daily noise down; the trail makes sure nothing they accept is ever
forgotten.

- **`events.jsonl`** sits next to the overlay. One line for every change the tool observed (once per
  new contents), plus one for each `sign` and each auto-accept. Each line carries the plain-English
  change, its risk, who accepted it (`E8` official-marketplace update, `R-settle`, `sign`, or nobody
  yet), and `prev_hash` / `hash`, so the file is an append-only chain: `hash = sha256(prev_hash +
  canonical JSON of the line)`. Writer: the root job in protected mode; the user folder in
  unprotected mode, and every output says which.
- **The AI never writes the chain in protected mode.** Root does not call a model. The user job adds
  its summary as a separate `explained` line in `explained.jsonl`, pointing at the change's hash.
- **`verify-log`** walks the chain and names the first broken line. In protected mode `check` and
  `watch` fail closed (exit 3) when the chain is broken. The root heartbeat records the chain head, so
  deleting lines from the end is caught too.
- **Daily snapshot** (`snapshots/YYYY-MM-DD.json.gz`: digests, plus normalized fingerprints for config
  files) and a **weekly dashboard copy** (`reports/YYYY-Www.html`).
- **Retention.** `retention_days` (config, default 365). Only whole days older than that are pruned,
  with their snapshots and old reports. Pruning appends a `prune` event holding the hash of the last
  removed line, so the chain still verifies. The newest signed baseline copy is always kept.

Look back:

```sh
python3 agent_integrity.py history ~/.claude/settings.json --since 180d   # one file, newest first
python3 agent_integrity.py diff --since signed                            # now vs your last signature
python3 agent_integrity.py diff --since 90d                               # now vs the snapshot 90 days ago
python3 agent_integrity.py report --html out.html --as-of 2026-08-01      # the dashboard as it was that day
python3 agent_integrity.py verify-log
```

The dashboard has a "Since you last signed" section (everything accepted along the way is listed, never
hidden) and a "Then vs now" panel with 30, 90, 180 and 365-day tabs. Pure HTML and CSS, no scripts.
`diff` exits 1 when something differs. Cumulative diffs compare saved fingerprints, so they do not
rerun the signature scan.

What the trail is not: the chain is hashed, not signed. In protected mode it is only as safe as root
ownership of the store; in unprotected mode a process running as you can rewrite the whole file and
recompute every hash. It is a record that makes a quiet edit show up, not proof against that process.

## Slow-drift detection (0.3.0)

A change that would be refused as one step can arrive as five small ones. Every run checks the
cumulative picture, deterministically, with the same classifier:

1. **Cumulative raising.** Now versus the last signed baseline and versus each window snapshot taken
   since. If the total change is risk-raising, you get an alert even though each step was neutral or
   settled. (Items already pending as raising are not reported twice.)
2. **Creep.** At least `creep_threshold` (default 5) settled changes to one security-relevant file
   (settings, MCP config, hooks, rules) within 90 days since your last signature: review-soon, with the
   list.
3. **Low and slow.** A neutral change followed within 60 days by a risk-raising one in the same file,
   or by a change that points at something the earlier change introduced (a new script settles, a
   hook later calls it): raising. The alert links both events.
4. **Dormant reappearance.** Something removed comes back after 30 or more days with different
   contents: raising.

Settling never hides any of this: settled changes stay in the trail and in "Since you last signed". A
later `sign` that covers the exact contents closes a finding. Each rule is tested with a fake clock
over several months (`tests/test_slowdrift.py`). Rule 1 mostly catches a forged or buggy overlay or a
classifier miss, since a correct classifier already flags a raising step the moment it happens.

## Explanation clarity benchmark (`bench/`)

`bench/run.py --model gpt-oss:20b` runs the real explainer prompt on 15 realistic changes against a
local Ollama model and scores each answer without another model: valid JSON, a summary of at most 2
sentences and 40 words, Flesch reading ease of at least 55 (file names and commands excluded),
no jargon, every named fact present, an imperative action, and a risk at or above the floor. It is
not in the CLI path or CI; it needs a local model. `bench/HISTORY.md` records each prompt version.

## Threat model, honestly

Read this before you rely on it.

- **Tamper-evident, not tamper-proof.** Without the root install below, everything runs as you. An
  attacker who runs as you can edit the baseline, the verifier, and the schedule. In that mode this
  tool is detection-only: it catches accidents and unsophisticated attacks, and it does not stop a
  careful one.
- **With the root install, the trust anchor moves out of your reach.** The verifier, the public
  key, the signed manifest, the last-seen sequence number and the heartbeat live in a root-owned
  directory. A same-user attacker cannot rewrite them. The manifest is signed with your SSH key
  (`ssh-keygen -Y sign`, namespace `agent-integrity`); the private key stays with you, protected by a
  passphrase, and the agent must never be able to read it.
- **Rollback is detected.** The signed payload carries a monotonic sequence number and timestamp,
  and the store remembers the highest sequence it has seen. Replaying an older, validly signed
  manifest fails.
- **A stopped checker is not "clean".** The root job writes a heartbeat. If it stops, or someone
  deletes the user-side hook, `status` and `check` report STALE and exit non-zero.
- **Trust on first use.** The first baseline blesses whatever is on disk at that moment. If the
  machine is already poisoned, the baseline is poisoned. The scan-before-baseline guard helps only
  for the patterns it knows. Review the files, then sign.
- **Signatures are regular expressions.** They catch the common shapes and are trivially evaded by an
  attacker who knows them (split strings, indirection, a different language). They are a tripwire for
  new behaviour, not a malware scanner.
- **Provenance is narrow.** Plugin updates are auto-accepted only when the signed manifest
  recorded the marketplace, its source is unchanged and matches an official prefix
  (default `anthropics/`), and the changed files have no high-severity hit. Anything else is shown.

### What it does not cover

- Anything outside the watched surfaces (your shell rc files, other apps, browser extensions,
  environment variables, files an agent writes at run time).
- Content an agent fetches during a session, and prompt injection in web pages, issues or
  documents. Those never touch a watched file.
- A compromised root account, a compromised signing key, or an attacker who gets you to sign.
- Windows. Linux works in principle (systemd timer, `/var/lib` store) and is tested less.
- Tools the surface table does not list. Unknown agents are unwatched.

## Install

Fetch, read, then run. There is deliberately no pipe-to-shell install.

```sh
git clone <this repository's URL> agent-integrity   # the green Code button on GitHub
less agent-integrity/install-root.sh          # read it: it is short
```

1. Make a dedicated signing key with a passphrase (do this yourself; never let an agent do it):
   `ssh-keygen -t ed25519 -f ~/.ssh/agent_integrity_signing`
2. Install the root-owned store and daemon (one time, you run it):
   `sudo ./install-root.sh --pubkey ~/.ssh/agent_integrity_signing.pub --user-home "$HOME"`
3. Baseline, review, sign:
   ```sh
   python3 agent_integrity.py baseline          # writes a PENDING manifest to ~/.agent-integrity
   python3 agent_integrity.py check             # review anything flagged
   python3 agent_integrity.py sign --key ~/.ssh/agent_integrity_signing
   ```
   `sign` asks for your passphrase, then prints the single `sudo ... promote` command that places
   the signed manifest in the store. Promote re-verifies the signature before installing it.
4. Optional: add `hooks/session-status.sh` as a SessionStart hook (it only reads the last root result)
   and `hooks/block-remote-exec.py` as a PreToolUse hook on Bash.

The installer takes `--store`, `--interval`, `--project`, `--no-service` and `--uninstall`.

## Everyday use

```sh
python3 agent_integrity.py check                  # exit 0 clean, 1 drift, 2 no manifest,
                                                  # 3 untrusted (bad signature / rollback), 4 STALE
python3 agent_integrity.py check --format sarif   # for code scanning dashboards
python3 agent_integrity.py scan                   # signatures only, no baseline needed
python3 agent_integrity.py baseline --i-reviewed <sha256-prefix>   # per-file override of the guard
python3 agent_integrity.py status                 # what the root job last recorded
python3 agent_integrity.py history KEY            # see the audit trail section
```

After you legitimately change a watched file: `baseline`, review, `sign`. With autopilot you only do
this for risk-raising changes; `watch` handles the rest.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The suite includes the four tamper tests that gate a release (`tests/test_tamper.py`; see
`RELEASE-GATE.md`) and a test that fails if internal names or secrets leak into this tree.

## License

MIT. See `LICENSE`.
