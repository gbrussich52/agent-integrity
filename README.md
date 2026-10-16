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
git clone <repository-url> agent-integrity    # URL is published with the first release
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
```

After you legitimately change a watched file: `baseline`, review, `sign`.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The suite includes the four tamper tests that gate a release (`tests/test_tamper.py`; see
`RELEASE-GATE.md`) and a test that fails if internal names or secrets leak into this tree.

## License

MIT. See `LICENSE`.
