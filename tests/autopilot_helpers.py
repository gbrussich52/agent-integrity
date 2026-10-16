"""Shared pieces for the autopilot tests: in-process module, fake local LLM, watch runner."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from helpers import SCRIPT, Env

_spec = importlib.util.spec_from_file_location("agent_integrity_mod", SCRIPT)
ai = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ai)

HOUR = 3600.0
T0 = 1_800_000_000.0


class FakeLLM:
    """Ollama-shaped backend on 127.0.0.1. `reply(body) -> str` decides the model's content."""

    def __init__(self, reply=None, models=("gemma3:12b",)):
        self.requests: list[dict] = []
        self.reply = reply or (lambda body: json.dumps({"summary": "ok", "risk": "low", "why": "fine"}))
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, obj):
                data = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/api/tags":
                    self._send({"models": [{"name": m} for m in models]})
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(body)
                self._send({"message": {"role": "assistant", "content": outer.reply(body)}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def chats(self):
        return self.requests


class AutoEnv(Env):
    def setUp(self):
        super().setUp()
        self.user = self.tmp / "user"
        self.user.mkdir()

    def fake(self, reply=None, **kw):
        f = FakeLLM(reply, **kw)
        self.addCleanup(f.close)
        self.set_user_cfg(explain_ollama_url=f.url)
        return f

    def set_user_cfg(self, **cfg):
        p = self.user / "config.json"
        cur = json.loads(p.read_text()) if p.exists() else {}
        cur.update(cfg)
        p.write_text(json.dumps(cur))

    def parse(self, cmd, *extra):
        return ai.build_parser().parse_args([
            cmd, "--store", str(self.store), "--home", str(self.home), "--project", str(self.project),
            "--tier", "all", "--user-dir", str(self.user), *extra])

    def watch(self, *extra, now=T0, notifier=None):
        """-> (exit, stdout, alerts sent)"""
        alerts: list = []
        args = self.parse("watch", "--now", str(now), *extra)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ai.cmd_watch(args, notifier=notifier or alerts.append)
        return rc, buf.getvalue(), alerts

    def check_json(self, now=T0):
        r = self.run_tool("check", "--format", "json", "--user-dir", str(self.user), "--now", str(now))
        return json.loads(r.stdout)

    def item(self, doc, needle):
        for it in doc["items"]:
            if needle in it["key"]:
                return it
        raise AssertionError(f"no item matching {needle}: {[i['key'] for i in doc['items']]}")

    def set_settings(self, obj, rel=".claude/settings.json"):
        self.write(rel, json.dumps(obj))
