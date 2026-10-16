"""Audit trail: hash chain, tamper detection, pruning/retention, daemon + watch integration, look-back."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from autopilot_helpers import HOUR, T0, AutoEnv, ai  # noqa: E402

DAY = 86400.0
NEUTRAL = {"hooks": {}, "model": "opus"}


class ChainTests(AutoEnv):
    def trail(self) -> "ai.Trail":
        return ai.Trail(self.tmp / "t" / "events.jsonl")

    def fill(self, n=6, start=T0):
        tr = self.trail()
        for i in range(n):
            tr.append("changed", f"~/k{i}", start + i * DAY, new_digest=f"sha256:{i}", semantic_lines=[f"line {i}"])
        return tr

    def test_chain_verifies_and_links(self):
        tr = self.fill()
        ok, n, why = tr.verify()
        self.assertTrue(ok, why)
        self.assertEqual(n, 6)
        evs = tr.events()
        self.assertEqual(evs[0]["prev_hash"], ai.GENESIS)
        self.assertEqual(evs[1]["prev_hash"], evs[0]["hash"])

    def test_edit_of_middle_line_is_caught(self):
        tr = self.fill()
        lines = tr.path.read_text().splitlines()
        lines[2] = lines[2].replace("line 2", "line X")
        tr.path.write_text("\n".join(lines) + "\n")
        ok, n, why = tr.verify()
        self.assertFalse(ok)
        self.assertEqual(n, 3)
        self.assertIn("edited", why)

    def test_removed_and_reordered_lines_are_caught(self):
        tr = self.fill()
        lines = tr.path.read_text().splitlines()
        tr.path.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
        ok, n, why = tr.verify()
        self.assertFalse(ok)
        self.assertEqual(n, 3)

    def test_missing_start_and_missing_tail(self):
        tr = self.fill()
        head = tr.head()
        lines = tr.path.read_text().splitlines()
        tr.path.write_text("\n".join(lines[1:]) + "\n")
        self.assertIn("start", tr.verify()[2])
        tr.path.write_text("\n".join(lines[:-1]) + "\n")
        self.assertTrue(tr.verify()[0])                       # a shortened chain is internally valid ...
        ok, _n, why = tr.verify(anchor=head)                  # ... only the daemon's recorded head exposes it
        self.assertFalse(ok)
        self.assertIn("end of the log", why)

    def test_prune_keeps_chain_valid_and_records_itself(self):
        tr = self.fill(n=6, start=T0)                         # one event per day for 6 days
        now = T0 + 5 * DAY
        dropped = ai.prune_trail(tr.path, now, retention_days=2)
        self.assertGreater(dropped, 0)
        ok, n, why = tr.verify()
        self.assertTrue(ok, why)
        evs = tr.events()
        self.assertEqual(evs[-1]["kind"], "prune")
        self.assertEqual(evs[-1]["extra"]["pruned_count"], dropped)
        self.assertEqual(evs[0]["prev_hash"], evs[-1]["extra"]["pruned_hash"])
        tr.append("changed", "~/after", now + 1, new_digest="sha256:z")
        self.assertTrue(tr.verify()[0])

    def test_prune_removes_only_whole_old_days(self):
        tr = self.fill(n=4, start=T0)
        now = T0 + 3 * DAY
        ai.prune_trail(tr.path, now, retention_days=365)
        self.assertEqual(len(tr.events()), 4)                 # nothing is old enough

    def test_prune_refuses_broken_chain(self):
        tr = self.fill()
        lines = tr.path.read_text().splitlines()
        lines[1] = lines[1].replace("line 1", "line Y")
        tr.path.write_text("\n".join(lines) + "\n")
        self.assertEqual(ai.prune_trail(tr.path, T0 + 400 * DAY, 30), 0)

    def test_retention_prunes_snapshots_and_old_reports(self):
        tdir = self.tmp / "t"
        for off in (0, 10, 300, 399):
            ai.write_gz_json(tdir / "snapshots" / f"{ai.local_day(T0 + off * DAY)}.json.gz", {"files": {}})
        now = T0 + 400 * DAY
        ai.prune_files(tdir, now, 365)
        left = sorted(p.name[:10] for p in (tdir / "snapshots").glob("*.json.gz"))
        self.assertEqual(left, sorted(ai.local_day(T0 + o * DAY) for o in (300, 399)))
        self.assertEqual(ai.retention_of({"retention_days": "7"}), 7)
        self.assertEqual(ai.retention_of({}), 365)


class DaemonTrailTests(AutoEnv):
    def daemon(self, now):
        r = self.run_tool("check", "--write-heartbeat", "--quiet", "--user-dir", str(self.user), "--now", str(now))
        self.assertIn(r.returncode, (0, 1), r.stdout + r.stderr)
        return r

    def events(self):
        return ai.Trail(self.store / "events.jsonl").events()

    def test_change_is_recorded_once_with_plain_lines(self):
        self.trusted_baseline()
        self.set_settings({"hooks": {}, "model": "opus", "permissions": {"allow": ["Bash(*)"]}})
        self.daemon(T0)
        self.daemon(T0 + HOUR)                                # same digest: no second event
        evs = [e for e in self.events() if e["kind"] in ai.CHANGE_KINDS and "settings.json" in e["key"]]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["kind"], "changed")
        self.assertIn(evs[0]["risk"], ("raising", "review-soon"))
        self.assertTrue(any("Bash(*)" in ln for ln in evs[0]["semantic_lines"]))
        self.assertNotEqual(evs[0]["old_digest"], evs[0]["new_digest"])
        hb = json.loads((self.store / "heartbeat.json").read_text())
        self.assertEqual(hb["events_head"], ai.Trail(self.store / "events.jsonl").head())
        self.assertTrue(ai.Trail(self.store / "events.jsonl").verify(hb["events_head"])[0])

    def test_sign_event_and_snapshot_are_written(self):
        self.trusted_baseline()
        self.write(".claude/skills/demo/SKILL.md", "# demo skill\nSummarise more files.\n")
        self.daemon(T0)
        snaps = list((self.store / "snapshots").glob("*.json.gz"))
        self.assertEqual(len(snaps), 1)
        self.assertTrue(ai.load_gz_json(snaps[0])["files"])
        self.assertTrue((self.store / "state-now.json.gz").exists())

    def test_settle_is_recorded_and_accepted_by_is_derived(self):
        self.trusted_baseline()
        self.set_settings(NEUTRAL)
        self.daemon(T0)
        self.daemon(T0 + 25 * HOUR)                           # past the 24h cool-off
        evs = self.events()
        self.assertEqual([e["kind"] for e in evs if e["kind"] == "settled"], ["settled"])
        change = next(e for e in evs if e["kind"] == "changed")
        idx = ai.trail_index(evs)
        self.assertEqual(ai.accepted_by_of(change, idx), "R-settle")
        settled = next(e for e in evs if e["kind"] == "settled")
        self.assertEqual(settled["ref"], change["hash"])

    def test_verify_log_cli_reports_ok_and_tamper(self):
        self.trusted_baseline()
        self.set_settings(NEUTRAL)
        self.daemon(T0)
        r = self.run_tool("verify-log", "--user-dir", str(self.user))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ok:", r.stdout)
        p = self.store / "events.jsonl"
        p.write_text(p.read_text().replace('"neutral"', '"raising"', 1))
        r = self.run_tool("verify-log", "--user-dir", str(self.user))
        self.assertEqual(r.returncode, 3)
        self.assertIn("BROKEN at line", r.stdout)

    def test_protected_check_fails_closed_on_broken_chain(self):
        self.trusted_baseline()
        self.set_settings(NEUTRAL)
        self.daemon(T0)
        p = self.store / "events.jsonl"
        p.write_text(p.read_text().replace('"neutral"', '"raising"', 1))
        real = ai.is_protected
        ai.is_protected = lambda store: True
        try:
            args = self.parse("check", "--now", str(T0 + HOUR))
            with contextlib.redirect_stdout(io.StringIO()):
                res = ai.run_check(args, ai.Store(self.store))
        finally:
            ai.is_protected = real
        self.assertEqual(res.exit, 3)
        self.assertIn("audit trail broken", res.reason)

    def test_unprotected_check_only_notes_a_broken_chain(self):
        self.trusted_baseline()
        self.set_settings(NEUTRAL)
        self.daemon(T0)
        p = self.store / "events.jsonl"
        p.write_text(p.read_text().replace('"neutral"', '"raising"', 1))
        args = self.parse("check", "--now", str(T0 + HOUR))
        res = ai.run_check(args, ai.Store(self.store))
        self.assertNotEqual(res.exit, 3)
        self.assertTrue(any("audit trail broken" in n for n in res.notes))

    def test_deleted_log_is_caught_by_the_heartbeat_anchor(self):
        self.trusted_baseline()
        self.set_settings(NEUTRAL)
        self.daemon(T0)
        (self.store / "events.jsonl").unlink()
        self.assertIn("log is missing", ai.chain_problem(ai.Store(self.store)))

    def test_watch_in_unprotected_mode_writes_trail_in_user_dir(self):
        self.trusted_baseline()
        self.set_settings(NEUTRAL)
        rc, out, _ = self.watch()
        self.assertEqual(rc, 1)
        evs = ai.Trail(self.user / "events.jsonl").events()
        self.assertTrue(any(e["kind"] == "changed" for e in evs))
        r = self.run_tool("history", "settings.json", "--user-dir", str(self.user), "--now", str(T0 + HOUR))
        self.assertIn("unprotected", r.stdout)

    def test_explained_event_references_the_change_hash(self):
        self.trusted_baseline()
        self.set_settings(NEUTRAL)
        self.fake(lambda body: json.dumps({"summary": "Your default model changed.", "risk": "low",
                                           "why": "Only the model name differs.", "detail": "model: opus",
                                           "action": "Nothing to do."}))
        self.watch("--explain")
        evs = ai.Trail(self.user / "events.jsonl").events()
        change = next(e for e in evs if e["kind"] == "changed")
        ex = next(e for e in evs if e["kind"] == "explained")
        self.assertEqual(ex["ref"], change["hash"])
        self.assertEqual(ex["llm"]["summary"], "Your default model changed.")
        self.assertTrue(ai.Trail(self.user / "events.jsonl").verify()[0])

    def test_history_shows_plain_lines_acceptance_and_ai_summary(self):
        self.trusted_baseline()
        self.set_settings(NEUTRAL)
        self.fake()
        self.watch("--explain", now=T0)
        self.watch(now=T0 + 25 * HOUR)
        r = self.run_tool("history", "settings.json", "--user-dir", str(self.user), "--since", "30d",
                          "--now", str(T0 + 26 * HOUR))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("accepted automatically after the quiet cool-off", r.stdout)
        self.assertIn("AI summary (advisory): ok", r.stdout)
        none = self.run_tool("history", "no-such-file", "--user-dir", str(self.user), "--now", str(T0 + HOUR))
        self.assertIn("no recorded changes", none.stdout)


class SignEventTests(AutoEnv):
    def test_promote_records_a_sign_event_and_a_signed_copy(self):
        self.trusted_baseline()
        tr = ai.Trail(self.pending / "events.jsonl")      # store is not root-owned here, so the pending dir holds it
        evs = tr.events()
        self.assertEqual([e["kind"] for e in evs], ["sign"])
        self.assertTrue(tr.verify()[0])
        seq = evs[0]["extra"]["manifest_seq"]
        self.assertTrue(evs[0]["extra"]["initial"])
        self.assertTrue(ai.load_gz_json(self.pending / "signed" / f"{seq}.json.gz")["files"])


class LookBackTests(AutoEnv):
    def daemon(self, now):
        self.run_tool("check", "--write-heartbeat", "--quiet", "--user-dir", str(self.user), "--now", str(now))

    def test_diff_since_signed_and_window(self):
        self.trusted_baseline()
        self.daemon(T0)                                       # snapshot of an untouched machine
        self.set_settings({"hooks": {}, "permissions": {"allow": ["Bash(*)"]}})
        r = self.run_tool("diff", "--since", "signed", "--user-dir", str(self.user), "--now", str(T0 + 40 * DAY))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Bash(*)", r.stdout)
        self.assertIn("last signed baseline", r.stdout)
        w = self.run_tool("diff", "--since", "30d", "--user-dir", str(self.user), "--now", str(T0 + 40 * DAY))
        self.assertIn("Bash(*)", w.stdout)
        self.assertIn("snapshot of", w.stdout)
        bad = self.run_tool("diff", "--since", "soon", "--user-dir", str(self.user))
        self.assertEqual(bad.returncode, 2)

    def test_diff_window_without_snapshot_says_so(self):
        self.trusted_baseline()
        r = self.run_tool("diff", "--since", "90d", "--user-dir", str(self.user), "--now", str(T0))
        self.assertEqual(r.returncode, 2)
        self.assertIn("no snapshot that old yet", r.stdout)

    def test_as_of_dashboard_matches_that_day_not_today(self):
        self.trusted_baseline()
        self.daemon(T0)
        self.set_settings({"hooks": {}, "model": "opus"})
        self.daemon(T0 + 10 * DAY)
        self.set_settings({"hooks": {}, "permissions": {"allow": ["Bash(*)"]}})
        self.daemon(T0 + 20 * DAY)
        out = self.tmp / "asof.html"
        day = ai.local_day(T0 + 12 * DAY)
        r = self.run_tool("report", "--html", str(out), "--as-of", day, "--user-dir", str(self.user),
                          "--now", str(T0 + 60 * DAY))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        page = out.read_text()
        self.assertIn(f"Historical view as of {day}", page)
        self.assertIn("model", page)                          # the change that was pending on that day
        self.assertNotIn("Bash(*)", page)                     # the later change does not leak back
        self.assertNotIn("<script", page)
        today = self.tmp / "today.html"
        self.run_tool("report", "--html", str(today), "--user-dir", str(self.user), "--now", str(T0 + 60 * DAY))
        self.assertIn("Since you last signed", today.read_text())
        self.assertIn("Then vs now", today.read_text())
        self.assertEqual(today.read_text().count("<details><summary><b>"), 4)

    def test_as_of_before_any_snapshot_is_an_error(self):
        self.trusted_baseline()
        self.daemon(T0)
        r = self.run_tool("report", "--html", str(self.tmp / "x.html"), "--as-of", "1999-01-01",
                          "--user-dir", str(self.user))
        self.assertEqual(r.returncode, 2)
        self.assertIn("no saved snapshot", r.stderr)
        bad = self.run_tool("report", "--html", str(self.tmp / "x.html"), "--as-of", "yesterday",
                            "--user-dir", str(self.user))
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
