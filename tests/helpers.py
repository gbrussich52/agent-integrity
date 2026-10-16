"""Shared fixture: a fake home, a fake project, a stand-in 'root' store, and a real ssh key."""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "agent_integrity.py"


def running_as_root() -> bool:
    return os.geteuid() == 0


class Env(unittest.TestCase):
    """setUp builds an isolated world; nothing here touches the real home or any real store."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ai-test-"))
        self.addCleanup(self._cleanup)
        self.home = self.tmp / "home"
        self.project = self.tmp / "proj"
        self.store = self.tmp / "root-store"      # stands in for the root-owned dir
        self.pending = self.tmp / "pending"
        self.keydir = self.tmp / "keys"
        for d in (self.home, self.project, self.store, self.keydir):
            d.mkdir()
        self.key = self.keydir / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)
        self.write_allowed(self.key)
        self.seed_files()

    def _cleanup(self):
        for dirpath, dirnames, filenames in os.walk(self.tmp):
            for n in dirnames + filenames:
                try:
                    os.chmod(Path(dirpath) / n, 0o755 if n in dirnames else 0o644)
                except OSError:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- fixture content ---------------------------------------------------------------
    def write(self, rel: str, text: str = "x\n", base: Path | None = None) -> Path:
        p = (base or self.home) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def seed_files(self):
        self.write(".claude/settings.json", '{"hooks": {}}\n')
        self.write(".claude/skills/demo/SKILL.md", "# demo skill\nSummarise files.\n")
        self.write(".claude.json", json.dumps({"mcpServers": {"a": {"command": "echo"}}, "other": 1}))
        self.write(".codex/config.toml", 'model = "x"\n')
        self.write(".cursor/mcp.json", '{"mcpServers": {}}\n')
        self.write("CLAUDE.md", "# rules\n", self.project)
        self.write("AGENTS.md", "# agents\n", self.project)
        self.write(".cursor/rules/style.mdc", "use tabs\n", self.project)
        self.write(".mcp.json", '{"mcpServers": {}}\n', self.project)

    def write_allowed(self, key: Path, store: Path | None = None):
        pub = Path(str(key) + ".pub").read_text().split()
        line = f'{"agent-integrity"} namespaces="agent-integrity" {pub[0]} {pub[1]}\n'
        (store or self.store).joinpath("allowed_signers").write_text(line)

    # -- running the tool ----------------------------------------------------------------
    def run_tool(self, *args, script: Path | None = None, store: Path | None = None, tier="all",
                 common=True, input_text=None):
        cmd = [sys.executable, str(script or SCRIPT), *args]
        if common:
            cmd += ["--store", str(store or self.store), "--home", str(self.home),
                    "--project", str(self.project), "--tier", tier]
        return subprocess.run(cmd, capture_output=True, text=True, input=input_text, timeout=300)

    def baseline(self, *extra, tier="all"):
        return self.run_tool("baseline", "--pending-dir", str(self.pending), *extra, tier=tier)

    def sign_and_promote(self, key: Path | None = None, store: Path | None = None):
        mf = self.pending / "manifest.json"
        sig = self.pending / "manifest.json.sig"
        if sig.exists():
            sig.unlink()
        subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key or self.key), "-n", "agent-integrity",
                        str(mf)], check=True, capture_output=True)
        return subprocess.run(
            [sys.executable, str(SCRIPT), "promote", "--store", str(store or self.store),
             "--pending-dir", str(self.pending)], capture_output=True, text=True)

    def trusted_baseline(self):
        r = self.baseline()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        p = self.sign_and_promote()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def lock_store(self):
        """Simulate root ownership: nothing in the store is writable by the test user."""
        for p in self.store.iterdir():
            os.chmod(p, 0o444)
        os.chmod(self.store, 0o555)

    def unlock_store(self):
        os.chmod(self.store, 0o755)
        for p in self.store.iterdir():
            os.chmod(p, 0o644)

    def can_write(self, path: Path) -> bool:
        try:
            with open(path, "ab"):
                pass
            return True
        except OSError:
            return False
