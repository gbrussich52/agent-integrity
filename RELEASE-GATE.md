# Release gate: four tamper tests

Attacker model: code running as the same user as the agent. In the tests the store is a temp
directory made read-only to stand in for a root-owned directory. All four pass in the automated
suite. Two of them only mean something on a real machine after the human completes the one-time root
install and signs with their passphrase-protected key; the table says which.

Run everything (from the repository root):
`python3 -m unittest discover -s tests -v`

| # | Test | Automated result | Exact command | Needs the human's root install + passphrase for real? |
|---|------|------------------|---------------|-----------------------------------|
| 1 | Baseline replacement: attacker writes a new manifest or overwrites the store copy; `check` must fail | PASS | `cd tests && python3 -m unittest test_tamper.TamperTests.test_1_baseline_replacement` | Yes. Without root ownership of the store, a same-user attacker can also overwrite `allowed_signers` with their own key. |
| 2 | Verifier replacement: attacker swaps the user-side script for an always-clean one; the store's copy still reports drift | PASS | `cd tests && python3 -m unittest test_tamper.TamperTests.test_2_verifier_replacement` | Yes. Passes for real only when the daemon runs the root-owned copy. Without the root install the tool is detection-only. |
| 3 | Rollback: attacker restores an older, validly signed manifest; `check` and `promote` must refuse | PASS | `cd tests && python3 -m unittest test_tamper.TamperTests.test_3_rollback` | Yes for the same reason (the last-seen sequence must be in a store the attacker cannot write). |
| 4 | Disabled collection: user hook deleted and runs stopped; heartbeat goes stale; result is STALE, not clean | PASS | `cd tests && python3 -m unittest test_tamper.TamperTests.test_4_disabled_collection` | Yes. The heartbeat is trustworthy only if root writes it. |

Extra cases: `test_1b_missing_signature_fails_closed`, `test_3b_same_seq_replacement`.

## Autopilot tests (0.2.0)
All run in `python3 -m unittest discover -s tests -v`: `tests/test_semantic.py` (diff classes, secrets
never stored), `tests/test_autopilot.py` (settle timing and reset, escalate-only LLM against a fake
loopback backend including prompt injection and backend down, remote refusal, alert dedup, dashboard
escaping and no external assets, quarantine refusal, install-user, the 5,000-file break test).

## Audit trail and slow-drift tests (0.3.0)
`tests/test_trail.py` (chain verify, tamper on a middle line, removed and reordered lines, tail
truncation via the heartbeat head, prune and retention keep the chain valid, protected-mode fail-closed
for `check`, `verify-log`, `history`, `--as-of`, `diff --since`, the sign event) and
`tests/test_slowdrift.py` (all four rules over multi-month fake clocks, alert dedupe, a `watch`
end-to-end). The 5,000-file break test stays at 20 lines or fewer.

Not a CI gate: `bench/run.py --model gpt-oss:20b` needs a local model. Before a release, run it and
record the pass rate in `bench/HISTORY.md`; it must be at least 90%.

## Loop approval gate tests (0.4.0)
`tests/test_loops.py`, run against a temp home, a temp job directory, a stand-in store and a mock
`launchctl` (`AGENT_INTEGRITY_LAUNCHCTL`) that only logs its arguments. The nine release tests:
1. a tampered script is refused (exit 3, nothing runs, refusal logged);
2. a tampered `PROMPT.md` is refused (and a `prompt.md` that appears later);
3. a tampered sourced helper is refused (and a changed imported python module);
4. a plist pointed away from the gate is reported by `check` and, with `loops_enforce`, booted out (mock
   `launchctl`), with `loops-bootout` in the trail; without it, only reported;
5. a rolled-back `loops.json` is refused by the gate and by `promote --loops`;
6. the main manifest and its valid signature cannot be installed or read as a loops manifest (and the
   reverse);
7. a failing, missing or hanging notify command still refuses, and repeated refusals are logged and
   notified once per hour;
8. the gate never runs argv taken from an edited plist or the caller's environment; the approved argv,
   cwd and env run;
9. an extra-blob mismatch (a registry entry edited) is refused, while an edit to another entry is not.
`tests/test_hook_and_install.py` also installs into a store path containing a space, parses the daemon
plist with `plistlib` and asserts `--store` is one element.

## What the human must do once (the agent never does these)
With autopilot the human steps shrink to the one-time key, `install-root.sh` and `install-user.sh`;
after that only risk-raising changes ask for a signature.
1. Generate a passphrase-protected signing key: `ssh-keygen -t ed25519 -f ~/.ssh/agent_integrity_signing`
2. `sudo ./install-root.sh --pubkey ~/.ssh/agent_integrity_signing.pub --user-home "$HOME"`
3. `python3 agent_integrity.py baseline`, review, then `python3 agent_integrity.py sign --key ~/.ssh/agent_integrity_signing`
   and run the one `sudo ... promote` command it prints.
4. Confirm on the real machine: `sudo launchctl print system/dev.agent-integrity.check` (macOS) shows
   the job, and `python3 agent_integrity.py status` prints a clean result with a fresh timestamp.

## What the automated pass does not prove
- It simulates root ownership with `chmod`; a same-user process could chmod it back. Real ownership is
  the control, so a pass here is evidence the logic is right, not that a given machine is protected.
- The audit trail is unsigned: with real root ownership it resists an agent running as the user, but a
  root-level attacker can rewrite it. The tests only simulate protected mode.
- It does not run launchd or systemd, and `install-root.sh` is tested in a non-root test mode against
  temp directories.
- Nothing here is a claim the tool detects every poisoned file (see the README).
- The loop tests use a mock `launchctl`; they show the right commands are issued, not that launchd
  honours them. Static discovery of sourced and imported files is a best effort (see the README).
