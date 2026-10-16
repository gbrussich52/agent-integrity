"""Fails if anything private to the original author's setup leaks into this tree."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Built by concatenation so this file does not match its own patterns.
FORBIDDEN = {
    "username/path": re.compile("gian" + "ibrussich", re.I),
    "estate repo name": re.compile("project" + "-claude", re.I),
    "employer tag": re.compile(r"\b" + "N" + "DR" + r"\b"),
    "first name": re.compile(r"\b" + "Gia" + "ni" + r"\b"),
    "launchd prefix": re.compile("com" + r"\.gi" + "ani", re.I),
    "email fragment": re.compile("gbrus" + "sich", re.I),
    "incident victim handle": re.compile("numa" + "lunah", re.I),
    "estate memory": re.compile("MEM" + r"ORY\.md|feed" + r"back_[a-z]|\.claude/" + "mem" + "ory", re.I),
    "estate helper": re.compile("verify" + "-source", re.I),
    "api key (sk-)": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    "aws key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    "private key block": re.compile("-----BEGIN [A-Z ]*PRIV" + "ATE KEY"),
    "slack/stripe token": re.compile(r"\b(?:xox[abp]-|sk_live_|rk_live_)[A-Za-z0-9-]{8,}"),
}
SKIP_DIRS = {".git", "__pycache__"}


def tree_files():
    for p in ROOT.rglob("*"):
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_DIRS):
            yield p


class NoEstateStrings(unittest.TestCase):
    def test_tree_is_clean(self):
        hits = []
        for p in tree_files():
            try:
                text = p.read_text(errors="ignore")
            except OSError:
                continue
            for label, rx in FORBIDDEN.items():
                for m in rx.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    hits.append(f"{p.relative_to(ROOT)}:{line} [{label}]")
        self.assertEqual(hits, [], "private strings found:\n" + "\n".join(hits))

    def test_scanner_would_catch_a_leak(self):
        sample = "see /Users/" + "gian" + "ibrussich" + "/x"
        self.assertTrue(FORBIDDEN["username/path"].search(sample))

    def test_no_stray_artifacts(self):
        bad = [str(p.relative_to(ROOT)) for p in tree_files()
               if p.suffix in {".pyc", ".log", ".sig"} or p.name in {"manifest.json", "heartbeat.json"}]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
