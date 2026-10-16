"""Slow drift: four deterministic rules over a fake multi-month timeline (every test sets its own clock)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from autopilot_helpers import T0, AutoEnv, ai  # noqa: E402

D = 86400.0
SET = "~/.claude/settings.json"


class SlowDriftTests(AutoEnv):
    def trail(self):
        return ai.Trail(self.tmp / "tr" / "events.jsonl")

    def state(self):
        ctx = ai.make_ctx(self.parse("check"))
        files = ai.snapshot(ctx, "all")
        return files, ai.config_fingerprints(ctx, [k for k in files if ai.config_type(k)])

    def anchor(self, label="the last signed baseline"):
        files, fps = self.state()
        return {"label": label, "files": dict(files), "fps": dict(fps)}

    def evs(self, tr):
        return tr.events()

    def test_cumulative_raising_over_five_months_of_settled_steps(self):
        self.seed_files()
        self.write(".claude/settings.json", json.dumps({"hooks": {}, "permissions": {"deny": ["Bash(rm *)"]}}))
        base = self.anchor()
        tr = self.trail()
        steps = [
            {"hooks": {}, "permissions": {"deny": ["Bash(rm *)"]}, "model": "opus"},
            {"hooks": {}, "permissions": {"deny": ["Bash(rm *)"], "allow": ["Read(*)"]}, "model": "opus"},
            {"hooks": {}, "permissions": {"deny": [], "allow": ["Read(*)"]}, "model": "opus"},
            {"hooks": {}, "permissions": {"deny": [], "allow": ["Read(*)", "Bash(*)"]}, "model": "opus"},
            {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "echo hi"}]}]},
             "permissions": {"deny": [], "allow": ["Read(*)", "Bash(*)"]}, "model": "opus"},
        ]
        for i, s in enumerate(steps):
            self.write(".claude/settings.json", json.dumps(s))
            files, _ = self.state()
            tr.append("settled", SET, T0 + (i + 1) * 30 * D, new_digest=files[SET], risk="neutral",
                      semantic_lines=["settings.json: small step"])
        files, fps = self.state()
        now = T0 + 160 * D
        found = ai.slow_drift(tr.events(), now, (files, fps), [base])
        cum = [f for f in found if f["rule"] == "cumulative"]
        self.assertEqual(len(cum), 1)
        self.assertEqual(cum[0]["level"], "raising")
        text = " ".join(cum[0]["lines"])
        self.assertIn("Bash(*)", text)
        # An unchanged machine produces nothing.
        self.assertEqual(ai.slow_drift(tr.events(), now, (files, fps), [self.anchor()]), [])
        # A pending raising item is reported by the normal alert instead, never twice.
        self.assertEqual([f for f in ai.slow_drift(tr.events(), now, (files, fps), [base], skip_keys={SET})
                          if f["rule"] == "cumulative"], [])

    def test_creep_needs_n_settled_changes_in_90_days(self):
        tr = self.trail()
        for i in range(4):
            tr.append("settled", SET, T0 + i * 10 * D, new_digest=f"sha256:{i}", semantic_lines=[f"model change {i}"])
        now = T0 + 40 * D
        self.assertEqual([f for f in ai.slow_drift(tr.events(), now, None, []) if f["rule"] == "creep"], [])
        tr.append("settled", SET, T0 + 40 * D, new_digest="sha256:4", semantic_lines=["model change 4"])
        got = [f for f in ai.slow_drift(tr.events(), now, None, []) if f["rule"] == "creep"]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["level"], "review-soon")
        self.assertEqual(len(got[0]["lines"]), 5)
        # Threshold is configurable, and old steps age out of the 90-day window.
        self.assertEqual(len([f for f in ai.slow_drift(tr.events(), now, None, [], creep_n=6) if f["rule"] == "creep"]), 0)
        later = T0 + 200 * D
        self.assertEqual([f for f in ai.slow_drift(tr.events(), later, None, []) if f["rule"] == "creep"], [])

    def test_creep_ignores_non_security_files_and_resets_at_sign(self):
        tr = self.trail()
        for i in range(5):
            tr.append("settled", "~/notes/readme.txt", T0 + i * D, new_digest=f"sha256:{i}")
        self.assertEqual(ai.slow_drift(tr.events(), T0 + 6 * D, None, []), [])
        for i in range(5):
            tr.append("settled", SET, T0 + (10 + i) * D, new_digest=f"sha256:s{i}")
        tr.append("sign", "", T0 + 20 * D, extra={"manifest_seq": 2, "signed": {}, "removed": {}})
        self.assertEqual([f for f in ai.slow_drift(tr.events(), T0 + 21 * D, None, []) if f["rule"] == "creep"], [])

    def test_low_and_slow_same_file(self):
        tr = self.trail()
        tr.append("changed", SET, T0, new_digest="sha256:a", risk="neutral", semantic_lines=["settings.json: model changed - neutral"])
        tr.append("changed", SET, T0 + 40 * D, old_digest="sha256:a", new_digest="sha256:b", risk="raising",
                  semantic_lines=["settings.json: allow Bash(*) added - raising"])
        got = [f for f in ai.slow_drift(tr.events(), T0 + 41 * D, None, []) if f["rule"] == "low-and-slow"]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["level"], "raising")
        self.assertEqual(len(got[0]["events"]), 2)        # the alert links both events
        self.assertEqual(got[0]["events"], [e["hash"] for e in tr.events()])

    def test_low_and_slow_too_far_apart_is_not_flagged(self):
        tr = self.trail()
        tr.append("changed", SET, T0, new_digest="sha256:a", risk="neutral")
        tr.append("changed", SET, T0 + 90 * D, new_digest="sha256:b", risk="raising", semantic_lines=["allow added - raising"])
        self.assertEqual([f for f in ai.slow_drift(tr.events(), T0 + 91 * D, None, []) if f["rule"] == "low-and-slow"], [])

    def test_low_and_slow_new_script_then_hook_pointing_at_it(self):
        tr = self.trail()
        tr.append("added", "~/.claude/hooks/sync_notes.sh", T0, new_digest="sha256:script", risk="neutral",
                  semantic_lines=["new file"])
        tr.append("changed", SET, T0 + 20 * D, old_digest="sha256:x", new_digest="sha256:y", risk="raising",
                  semantic_lines=["settings.json: hook added: runs ~/.claude/hooks/sync_notes.sh before every tool - raising"])
        got = [f for f in ai.slow_drift(tr.events(), T0 + 21 * D, None, []) if f["rule"] == "low-and-slow"]
        self.assertEqual(len(got), 1)
        self.assertIn("sync_notes.sh", got[0]["title"])

    def test_low_and_slow_closed_by_a_later_sign(self):
        tr = self.trail()
        tr.append("changed", SET, T0, new_digest="sha256:a", risk="neutral")
        tr.append("changed", SET, T0 + 5 * D, new_digest="sha256:b", risk="raising", semantic_lines=["x - raising"])
        tr.append("sign", "", T0 + 6 * D, extra={"manifest_seq": 3, "signed": {SET: "sha256:b"}, "removed": {}})
        self.assertEqual([f for f in ai.slow_drift(tr.events(), T0 + 7 * D, None, []) if f["rule"] == "low-and-slow"], [])

    def test_dormant_reappearance(self):
        key = "~/.claude/hooks/guard.sh"
        tr = self.trail()
        tr.append("removed", key, T0, old_digest="sha256:old", new_digest="-", risk="review-soon")
        tr.append("added", key, T0 + 45 * D, old_digest="-", new_digest="sha256:new", risk="neutral", semantic_lines=["new file"])
        got = [f for f in ai.slow_drift(tr.events(), T0 + 46 * D, None, []) if f["rule"] == "dormant"]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["level"], "raising")
        self.assertIn("45 days", got[0]["title"])

    def test_dormant_needs_30_days_and_different_contents(self):
        key = "~/.claude/hooks/guard.sh"
        tr = self.trail()
        tr.append("removed", key, T0, old_digest="sha256:old", new_digest="-")
        tr.append("added", key, T0 + 10 * D, new_digest="sha256:new")        # too soon
        tr.append("removed", key, T0 + 20 * D, old_digest="sha256:new", new_digest="-")
        tr.append("added", key, T0 + 80 * D, new_digest="sha256:new")        # same contents as removed
        self.assertEqual([f for f in ai.slow_drift(tr.events(), T0 + 81 * D, None, []) if f["rule"] == "dormant"], [])

    def test_dormant_after_a_sign_that_dropped_the_key(self):
        key = "~/.claude/hooks/guard.sh"
        tr = self.trail()
        tr.append("sign", "", T0, extra={"manifest_seq": 2, "signed": {}, "removed": {key: "sha256:old"}})
        tr.append("added", key, T0 + 50 * D, new_digest="sha256:new")
        self.assertEqual(len([f for f in ai.slow_drift(tr.events(), T0 + 51 * D, None, []) if f["rule"] == "dormant"]), 1)

    def test_alerts_fire_once_and_clear(self):
        f = [{"id": "x", "level": "raising", "title": "A small thing grew"}, {"id": "y", "level": "review-soon", "title": "B"}]
        alerts, active = ai.plan_slow_alerts(f, [])
        self.assertEqual({a["level"] for a in alerts}, {"red", "amber"})
        self.assertEqual(active, ["x", "y"])
        again, active2 = ai.plan_slow_alerts(f, active)
        self.assertEqual(again, [])
        self.assertEqual(ai.plan_slow_alerts([], active2)[1], [])

    def test_watch_end_to_end_alerts_on_low_and_slow(self):
        self.trusted_baseline()
        ai.Trail(self.user / "events.jsonl").append("changed", SET, T0 - 30 * D, new_digest="sha256:a", risk="neutral",
                                                    semantic_lines=["settings.json: model changed - neutral"])
        self.set_settings({"hooks": {}, "permissions": {"allow": ["Bash(*)"]}})
        rc, out, alerts = self.watch()
        self.assertIn("SLOW DRIFT", out)
        self.assertTrue(any("slow-drift" in a["title"] for a in alerts), alerts)
        rc2, out2, alerts2 = self.watch(now=T0 + 3600)
        self.assertFalse(any("slow-drift" in a["title"] for a in alerts2))


if __name__ == "__main__":
    unittest.main()
