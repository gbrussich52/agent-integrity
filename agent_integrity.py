#!/usr/bin/env python3
"""agent-integrity: tamper-evidence for the files AI coding agents treat as instructions.

Skills, agents, commands, hooks, settings, rules files and MCP server definitions are code:
an agent loads them with your permissions. This records what they hashed to when you last
reviewed them, signs that record with a key the agent cannot read, and reports every change
since, plus a regex scan for the behaviours a poisoned instruction file needs (fetch-and-run,
decode-and-run, credential reads, exfiltration hosts, "do not tell the user", persistence,
invisible unicode).

  baseline  scan, then write a PENDING manifest to your user dir (refuses on unreviewed
            high-severity signature hits in new/changed files)
  sign      you (interactive passphrase) sign the pending manifest and promote it
  promote   verify a signed pending manifest and install it into the store (root-owned
            store: run it with sudo; it only installs what verifies)
  check     verify the signed manifest, then report drift and heartbeat staleness
  scan      pattern-scan only; no manifest needed
  status    print the last result the root daemon recorded (what a SessionStart hook runs)

Exit codes: 0 clean, 1 drift or new signature hits, 2 no manifest / usage,
            3 manifest untrusted (bad or missing signature, rollback), 4 STALE heartbeat.

Honest limits are in README.md. Stdlib only. macOS first, Linux paths included.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
NAMESPACE = "agent-integrity"   # ssh-keygen -Y namespace: a signature made for another purpose won't verify
PRINCIPAL = "agent-integrity"
SELF = Path(__file__).resolve()

EXIT_CLEAN, EXIT_DRIFT, EXIT_USAGE, EXIT_UNTRUSTED, EXIT_STALE = 0, 1, 2, 3, 4

# --- Surfaces: one table, so supporting another agent is one entry ------------------------
# kind: dir  = every code-ish file below it
#       file = one file, or a glob pattern relative to base (settings*.json)
#       mcp  = one key of a JSON file, hashed as a unit (the file also holds unrelated state)
# base: home | project.  tier "1" = files you author (cheap, runs often);
#       tier "2" = installed third-party plugins (thousands of files).
SURFACES = [
    # Claude Code
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "home", "path": ".claude/skills"},
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "home", "path": ".claude/agents"},
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "home", "path": ".claude/commands"},
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "home", "path": ".claude/output-styles"},
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "home", "path": ".claude/hooks"},
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "home", "path": ".claude/routines"},
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "home", "path": ".claude/rules"},
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "home", "path": ".claude/workflows"},
    {"agent": "claude-code", "tier": "1", "kind": "file", "base": "home", "path": ".claude/settings*.json"},
    {"agent": "claude-code", "tier": "1", "kind": "file", "base": "home", "path": ".claude/CLAUDE.md"},
    {"agent": "claude-code", "tier": "1", "kind": "mcp", "base": "home", "path": ".claude.json", "jsonkey": "mcpServers"},
    {"agent": "claude-code", "tier": "2", "kind": "dir", "base": "home", "path": ".claude/plugins"},
    {"agent": "claude-code", "tier": "1", "kind": "dir", "base": "project", "path": ".claude"},
    {"agent": "claude-code", "tier": "1", "kind": "file", "base": "project", "path": "CLAUDE.md"},
    {"agent": "claude-code", "tier": "1", "kind": "file", "base": "project", "path": ".mcp.json"},
    # Codex
    {"agent": "codex", "tier": "1", "kind": "file", "base": "home", "path": ".codex/config.toml"},
    {"agent": "codex", "tier": "1", "kind": "file", "base": "home", "path": ".codex/AGENTS.md"},
    {"agent": "codex", "tier": "1", "kind": "dir", "base": "home", "path": ".codex/prompts"},
    {"agent": "codex", "tier": "1", "kind": "dir", "base": "home", "path": ".codex/skills"},
    {"agent": "codex", "tier": "1", "kind": "file", "base": "project", "path": "AGENTS.md"},
    # Cursor
    {"agent": "cursor", "tier": "1", "kind": "file", "base": "home", "path": ".cursor/mcp.json"},
    {"agent": "cursor", "tier": "1", "kind": "dir", "base": "project", "path": ".cursor/rules"},
    {"agent": "cursor", "tier": "1", "kind": "file", "base": "project", "path": ".cursorrules"},
    {"agent": "cursor", "tier": "1", "kind": "file", "base": "project", "path": ".cursor/mcp.json"},
]

CODEISH = {".md", ".mdc", ".json", ".sh", ".py", ".js", ".mjs", ".ts", ".toml", ".yaml", ".yml",
           ".bash", ".zsh", ".txt"}
# Never watched: tool caches, VCS internals, and the agent's own scratch areas, which churn
# constantly and would bury a real change.
SKIP_PARTS = {"node_modules", ".git", "__pycache__", ".venv", "logs", ".DS_Store", ".trash", "worktrees"}

# The plugin installer clones into scratch dirs under plugins/cache/ and deletes them when the
# install settles. Baselining them produces permanent REMOVED drift the next time it cleans up.
# Only this ephemeral naming pattern is excluded, never plugins/ wholesale.
EPHEMERAL_PLUGIN_CLONE_RE = re.compile(
    r"/\.claude/plugins/cache/temp_(?:git|subdir)_\d+_[A-Za-z0-9]+(?:\.clone)?(?:/|$)")

# Behaviours a poisoned agent file needs. Each is legitimate somewhere, which is what the
# allowlist is for; the point is that a NEW one appears loudly, not that all are forbidden.
SIGNATURES = [
    ("remote-exec", re.compile(r"(?:curl|wget)\b[^|\n]*\|[^|\n]*\b(?:sh|bash|zsh|python3?|node)\b", re.I)),
    ("decode-exec", re.compile(r"base64\s+(?:-{1,2}d\w*)|atob\s*\(|\bexec\s*\(\s*(?:base64|atob)", re.I)),
    ("credential-read", re.compile(r"\.ssh/id_|\.aws/credentials|\.config/gcloud|security\s+find-generic-password|"
                                   r"\.claude/\.credentials\.json|Login\ Data|\bcookies\.sqlite|"
                                   r"wallet\.dat|\.env(?:\.local)?\b[^\n]{0,40}(?:cat|read|upload|post)", re.I)),
    ("exfil", re.compile(r"webhook\.site|pastebin\.com/api|ngrok\.io|transfer\.sh|0x0\.st|file\.io|"
                         r"\bnc\s+-\w*\s*\d+\.\d+\.\d+\.\d+|"
                         r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
                         r"\d+\.\d+\.\d+\.\d+", re.I)),
    ("self-conceal", re.compile(r"do\s+not\s+(?:tell|inform|mention|show)\s+the\s+user|without\s+(?:telling|informing|"
                                r"notifying)\s+the\s+user|silently\s+(?:download|install|run|send)|"
                                r"hide\s+this\s+(?:from|instruction)", re.I)),
    ("persistence", re.compile(r"launchctl\s+load|crontab\s+-|LaunchAgents/[^\s]+\.plist|~/\.zshrc|~/\.bash_profile", re.I)),
    ("hidden-unicode", re.compile(
        # Escapes, not literals: spelled out, this line matches itself and a remediator
        # built on it would quarantine its own source. U+200D is excluded: it joins emoji.
        "[​‌‎‏‪-‮⁦-⁩﻿­]")),
]
SIG_RX = dict(SIGNATURES)
HIGH = {"hidden-unicode", "decode-exec", "exfil", "remote-exec"}
SIG_DESC = {
    "remote-exec": "Fetches content from the network and pipes it into a shell or interpreter.",
    "decode-exec": "Decodes base64/atob data and executes it.",
    "credential-read": "References credential stores, key files or browser secrets.",
    "exfil": "References a known exfiltration host or a raw public IP.",
    "self-conceal": "Instructs the agent to hide actions from the user.",
    "persistence": "Installs persistence (launchd, cron, shell rc files).",
    "hidden-unicode": "Contains invisible or bidirectional-control unicode.",
}

# Marketplaces whose plugin updates may be auto-accepted: only when the SIGNED manifest
# recorded the marketplace with a source matching one of these prefixes (or a config override).
DEFAULT_OFFICIAL_SOURCES = ["anthropics/", "github.com/anthropics/", "https://github.com/anthropics/"]
DEFAULT_STALE_AFTER = 3 * 3600   # root check runs hourly; three missed runs = stale
MAX_SCAN_BYTES = 2 * 1024 * 1024

# Content the host app rewrites on its own schedule with no security meaning. Only the named
# field of the named file is dropped; an unparseable file falls back to raw bytes.
VOLATILE_JSON_FIELDS = {"/.claude/plugins/known_marketplaces.json": {"lastUpdated"}}


# --- Paths and store -----------------------------------------------------------------------
def default_store() -> Path:
    env = os.environ.get("AGENT_INTEGRITY_STORE")
    if env:
        return Path(env)
    if platform.system() == "Darwin":
        return Path("/Library/Application Support/agent-integrity")
    return Path("/var/lib/agent-integrity")


def default_pending_dir() -> Path:
    return Path(os.environ.get("AGENT_INTEGRITY_HOME") or Path.home() / ".agent-integrity")


class Store:
    """The directory the verifier trusts. Root-owned after install-root.sh; a temp dir in tests."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.manifest = self.root / "manifest.json"
        self.sig = self.root / "manifest.json.sig"
        self.allowed = self.root / "allowed_signers"
        self.last_seen = self.root / "last_seen.json"
        self.heartbeat = self.root / "heartbeat.json"
        self.config_path = self.root / "config.json"
        self.allow_path = self.root / "allow.json"

    def config(self) -> dict:
        return load_json(self.config_path)

    def allow(self) -> dict:
        return load_json(self.allow_path)


def load_json(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def atomic_write(path: Path, data: bytes | str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    if isinstance(data, str):
        data = data.encode()
    tmp.write_bytes(data)
    os.replace(tmp, path)


# --- Hashing and enumeration ---------------------------------------------------------------
def sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _drop_fields(obj, fields):
    if isinstance(obj, dict):
        return {k: _drop_fields(v, fields) for k, v in obj.items() if k not in fields}
    if isinstance(obj, list):
        return [_drop_fields(v, fields) for v in obj]
    return obj


class Ctx:
    """Everything path-dependent in one object: home, projects, and key<->path mapping."""

    def __init__(self, home: Path, projects: list[Path]):
        self.home = Path(home)
        self.projects = [Path(p) for p in projects]

    def key(self, p: Path) -> str:
        s = str(p)
        h = str(self.home)
        return "~" + s[len(h):] if s == h or s.startswith(h + os.sep) else s

    def path(self, key: str) -> Path:
        return Path(str(self.home) + key[1:]) if key.startswith("~") else Path(key)

    def digest(self, p: Path) -> str:
        if p.is_symlink():
            return "symlink:" + os.readlink(p)
        for suffix, fields in VOLATILE_JSON_FIELDS.items():
            if str(p).endswith(suffix):
                try:
                    stripped = _drop_fields(json.loads(p.read_text()), fields)
                    return hashlib.sha256(json.dumps(stripped, sort_keys=True).encode()).hexdigest()
                except Exception:
                    break   # unparseable -> raw bytes, never hashed more loosely
        return sha_file(p)


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_PARTS]
        # A symlink is recorded by its target, never followed (os.walk doesn't follow dirs).
        for name in list(dirnames):
            p = Path(dirpath) / name
            if p.is_symlink():
                dirnames.remove(name)
                yield p
        for name in filenames:
            if name in SKIP_PARTS:
                continue
            p = Path(dirpath) / name
            if EPHEMERAL_PLUGIN_CLONE_RE.search(str(p)):
                continue
            if p.is_symlink() or p.suffix.lower() in CODEISH or Path(dirpath).name in {"hooks", "gates"}:
                yield p


def surface_files(ctx: Ctx, tier: str):
    """Yield (agent, Path) for every watched file at this tier."""
    seen = set()
    bases = {"home": [ctx.home], "project": ctx.projects}
    for s in SURFACES:
        if tier != "all" and s["tier"] != tier:
            continue
        if s["kind"] == "mcp":
            continue
        for base in bases[s["base"]]:
            if s["kind"] == "dir":
                root = base / s["path"]
                cands = _walk(root) if root.is_dir() and not root.is_symlink() else ([root] if root.is_symlink() else [])
            else:
                cands = [p for p in base.glob(s["path"]) if p.is_file() or p.is_symlink()]
            for p in cands:
                if p not in seen:
                    seen.add(p)
                    yield s["agent"], p


def mcp_entries(ctx: Ctx, tier: str) -> dict[str, str]:
    out = {}
    for s in SURFACES:
        if s["kind"] != "mcp" or (tier != "all" and s["tier"] != tier):
            continue
        cfg = ctx.home / s["path"]
        if not cfg.is_file():
            continue
        try:
            servers = json.loads(cfg.read_text()).get(s["jsonkey"], {})
        except Exception:
            continue
        blob = json.dumps(servers, sort_keys=True)
        out[f"~/{s['path']}#{s['jsonkey']}"] = hashlib.sha256(blob.encode()).hexdigest()
    return out


def snapshot(ctx: Ctx, tier: str) -> dict[str, str]:
    out = {}
    for _agent, p in surface_files(ctx, tier):
        try:
            out[ctx.key(p)] = ctx.digest(p)
        except OSError:
            pass
    out.update(mcp_entries(ctx, tier))
    return out


def is_plugin_key(k: str) -> bool:
    return k.startswith("~/.claude/plugins")


def in_tier(k: str, tier: str) -> bool:
    return tier == "all" or (tier == "2") == is_plugin_key(k)


# --- Source grouping (reviewable drift) ----------------------------------------------------
_PLUGIN_RE = re.compile(r"^~/\.claude/plugins/cache/([^/]+)/([^/]+)/")
_MARKET_RE = re.compile(r"^~/\.claude/plugins/marketplaces/([^/]+)/")
_CACHE_MP_RE = re.compile(r"^~/\.claude/plugins/cache/([^/]+)/")


def marketplace_of(k: str) -> str | None:
    m = _CACHE_MP_RE.match(k) or _MARKET_RE.match(k)
    return m.group(1) if m else None


def agent_of(k: str) -> str:
    if "/.codex/" in k or k.endswith("AGENTS.md"):
        return "codex"
    if "/.cursor/" in k or k.endswith(".cursorrules"):
        return "cursor"
    return "claude-code"


def group_of(k: str) -> str:
    m = _PLUGIN_RE.match(k)
    if m:
        return f"plugin {m.group(1)}/{m.group(2)}"
    m = _MARKET_RE.match(k)
    if m:
        return f"marketplace {m.group(1)}"
    if is_plugin_key(k):
        return "claude-code plugin registry"
    return agent_of(k)


# --- Signatures ----------------------------------------------------------------------------
def read_text(p: Path) -> str | None:
    try:
        with p.open("rb") as fh:
            return fh.read(MAX_SCAN_BYTES).decode("utf-8", "ignore")
    except OSError:
        return None


def sig_hits(p: Path, high_only: bool) -> list[str]:
    text = read_text(p)
    if text is None:
        return []
    return [n for n, rx in SIGNATURES if (not high_only or n in HIGH) and rx.search(text)]


def unreviewed_high(p: Path, digest: str, allow: dict, reviewed: set[str] = frozenset()) -> list[str]:
    hits = sig_hits(p, True)
    if not hits or allow.get(digest) or any(digest.startswith(r) for r in reviewed):
        return []
    return hits


# --- Signed manifest -----------------------------------------------------------------------
def verify_signature(store: Store, manifest_bytes: bytes, sig_path: Path | None = None) -> tuple[bool, str]:
    sig_path = sig_path or store.sig
    if not store.allowed.is_file():
        return False, f"no allowed_signers in store ({store.allowed}); run the root install"
    if not sig_path.is_file():
        return False, f"no signature file ({sig_path.name})"
    try:
        r = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(store.allowed), "-I", PRINCIPAL,
             "-n", NAMESPACE, "-s", str(sig_path)],
            input=manifest_bytes, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"ssh-keygen unavailable: {e}"
    if r.returncode != 0:
        return False, "signature does not verify against allowed_signers"
    return True, "ok"


class Untrusted(Exception):
    pass


def load_trusted_manifest(store: Store) -> tuple[dict, str]:
    """Verified manifest dict + its sha256, or raise Untrusted. Fails closed on every doubt."""
    if not store.manifest.is_file():
        raise Untrusted("no signed manifest in store")
    raw = store.manifest.read_bytes()
    ok, why = verify_signature(store, raw)
    if not ok:
        raise Untrusted(why)
    try:
        m = json.loads(raw)
        seq, created = int(m["seq"]), str(m["created"])
        m["files"]
    except (ValueError, KeyError, TypeError):
        raise Untrusted("signed manifest is malformed")
    msha = hashlib.sha256(raw).hexdigest()
    last = load_json(store.last_seen)
    if last:
        if seq < int(last.get("seq", 0)):
            raise Untrusted(f"ROLLBACK: manifest seq {seq} is older than last seen {last['seq']}")
        if created < str(last.get("created", "")):
            raise Untrusted("ROLLBACK: manifest timestamp is older than last seen")
        if seq == int(last.get("seq", 0)) and msha != last.get("sha256"):
            raise Untrusted(f"manifest at seq {seq} differs from the one last seen (replaced)")
    if not last or seq > int(last.get("seq", 0)):
        try:   # only root can; a user-run check just doesn't advance the mark
            atomic_write(store.last_seen, json.dumps({"seq": seq, "created": created, "sha256": msha}))
        except OSError:
            pass
    return m, msha


def marketplace_sources(home: Path) -> dict[str, str]:
    """name -> source string (repo or url) from known_marketplaces.json."""
    data = load_json(home / ".claude/plugins/known_marketplaces.json")
    out = {}
    for name, entry in data.items():
        src = entry.get("source", {}) if isinstance(entry, dict) else {}
        out[name] = str(src.get("repo") or src.get("url") or src.get("path") or "")
    return out


def is_official(source: str, official: list[str]) -> bool:
    return bool(source) and any(source.startswith(p) for p in official)


# --- Result model --------------------------------------------------------------------------
class Result:
    def __init__(self, command: str, tier: str):
        self.command, self.tier = command, tier
        self.status = "clean"
        self.exit = EXIT_CLEAN
        self.reason = ""
        self.seq: int | None = None
        self.items: list[dict] = []        # {kind, key, group, sigs}
        self.auto_accepted = 0
        self.scanned = 0
        self.notes: list[str] = []

    def counts(self) -> dict:
        c = {"changed": 0, "added": 0, "removed": 0}
        for it in self.items:
            if it["kind"] in c:
                c[it["kind"]] += 1
        return c

    def to_json(self) -> dict:
        return {"tool": "agent-integrity", "version": VERSION, "command": self.command, "tier": self.tier,
                "status": self.status, "exit": self.exit, "reason": self.reason, "seq": self.seq,
                "scanned": self.scanned, "counts": self.counts(),
                "auto_accepted": self.auto_accepted, "notes": self.notes, "items": self.items}


# --- check ---------------------------------------------------------------------------------
def heartbeat_state(store: Store, cfg: dict, now: float, stale_after: int) -> tuple[bool, str]:
    """(stale?, why). Required whenever the root install said so; a missing file then IS stale."""
    required = bool(cfg.get("heartbeat_required"))
    hb = load_json(store.heartbeat)
    if not hb:
        return (True, "no heartbeat from the root check") if required else (False, "")
    age = now - float(hb.get("ts", 0))
    if age > stale_after:
        return True, f"last root check was {int(age // 3600)}h {int(age % 3600 // 60)}m ago (limit {stale_after // 3600}h)"
    return False, ""


def run_check(args, store: Store) -> Result:
    res = Result("check", args.tier)
    now = args.now if args.now is not None else time.time()
    cfg = store.config()
    try:
        manifest, _msha = load_trusted_manifest(store)
    except Untrusted as e:
        res.status, res.exit, res.reason = "untrusted", EXIT_UNTRUSTED, str(e)
        if not store.manifest.is_file():
            res.status, res.exit = "no-manifest", EXIT_USAGE
        return res
    res.seq = int(manifest["seq"])
    old = manifest["files"]
    home = Path(args.home) if args.home else Path(cfg.get("home") or Path.home())
    projects = [Path(p) for p in (args.project or manifest.get("projects") or cfg.get("projects") or [])]
    ctx = Ctx(home, projects)
    new = snapshot(ctx, args.tier)
    res.scanned = len(new)
    scope = set(new) | {k for k in old if in_tier(k, args.tier)}
    added = sorted(k for k in scope if k in new and k not in old)
    removed = sorted(k for k in scope if k in old and k not in new)
    changed = sorted(k for k in scope if k in old and k in new and old[k] != new[k])
    allow = store.allow()
    if args.allow:
        allow.update(load_json(Path(args.allow)))

    official = cfg.get("official_sources") or DEFAULT_OFFICIAL_SOURCES
    signed_mp = manifest.get("marketplaces", {})
    live_mp = marketplace_sources(ctx.home)

    def trusted_marketplace(k: str) -> bool:
        mp = marketplace_of(k)
        # Provenance = the SIGNED manifest recorded this marketplace, from an official source,
        # and its source today is the same. A marketplace added after signing never qualifies.
        return bool(mp) and signed_mp.get(mp) is not None and signed_mp[mp] == live_mp.get(mp) \
            and is_official(signed_mp[mp], official)

    def sigs_for(k: str) -> list[str]:
        p = ctx.path(k)
        return unreviewed_high(p, new.get(k, ""), allow) if p.is_file() and not p.is_symlink() else []

    for kind, keys in (("changed", changed), ("added", added), ("removed", removed)):
        for k in keys:
            sigs = sigs_for(k) if kind != "removed" else []
            # Nothing left to scan on removal: provenance alone is the basis.
            if is_plugin_key(k) and trusted_marketplace(k) and not sigs:
                res.auto_accepted += 1
                continue
            res.items.append({"kind": kind, "key": k, "group": group_of(k), "sigs": sigs})

    stale, why = heartbeat_state(store, cfg, now, args.stale_after or int(cfg.get("stale_after", DEFAULT_STALE_AFTER)))
    if getattr(args, "write_heartbeat", False):
        stale = False          # this run IS the heartbeat; it cannot be stale about itself
    if res.items:
        res.status, res.exit = "drift", EXIT_DRIFT
    elif stale:
        res.status, res.exit, res.reason = "stale", EXIT_STALE, "STALE: " + why
    if stale and res.items:
        res.notes.append("STALE: " + why)
    return res


# --- Rendering -----------------------------------------------------------------------------
def render_text(res: Result, limit: int = 3, max_lines: int = 20) -> list[str]:
    if res.status == "no-manifest":
        return [f"agent-integrity: {res.reason}", "Run: agent_integrity.py baseline, then sign."]
    if res.status == "untrusted":
        return [f"AGENT-INTEGRITY: MANIFEST UNTRUSTED ({res.reason}).",
                "Nothing below this point can be relied on. Do not re-baseline over it; "
                "investigate who wrote to the store."]
    if res.status == "stale":
        return [f"AGENT-INTEGRITY: {res.reason}",
                "The root check has stopped running or been disabled. Clean results are not "
                "trustworthy until it runs again."]
    if res.status == "clean":
        out = [f"agent-integrity: clean ({res.scanned} files, tier {res.tier}, manifest seq {res.seq})"]
        if res.auto_accepted:
            out.insert(0, auto_line(res.auto_accepted))
        return out
    c = res.counts()
    head = f"AGENT FILE DRIFT (tier {res.tier}): {c['changed']} changed, {c['added']} added, {c['removed']} removed"
    out = [head]
    if res.auto_accepted:
        out.append(auto_line(res.auto_accepted))
    out.extend(res.notes)
    footer = "Read each one before an agent loads it. Then: baseline, sign."
    budget = max_lines - len(out) - 1

    flagged = [it for it in res.items if it["sigs"]]
    if flagged and budget > 0:
        shown = flagged[: max(1, min(limit + 2, budget))]
        for it in shown:
            out.append(f"  ! {it['kind'].upper()} {it['key']}  [{', '.join(it['sigs'])}]")
        if len(flagged) > len(shown):
            out.append(f"  ! ... +{len(flagged) - len(shown)} more with high-severity signatures")
        budget = max_lines - len(out) - 1

    groups: dict[str, list[dict]] = {}
    for it in res.items:
        groups.setdefault(it["group"], []).append(it)
    plain = sorted(g for g in groups if not g.startswith(("plugin ", "marketplace ")))
    bulk = sorted(g for g in groups if g.startswith(("plugin ", "marketplace ")))

    def tally(items):
        t = {"changed": 0, "added": 0, "removed": 0}
        for i in items:
            t[i["kind"]] += 1
        return ", ".join(f"{v} {k}" for k, v in t.items() if v)

    lines: list[str] = []
    for g in plain:
        lines.append(f"  {g}: {tally(groups[g])}")
        for it in groups[g][:limit]:
            lines.append(f"    {it['kind'].upper()} {it['key']}")
        if len(groups[g]) > limit:
            lines.append(f"    ... +{len(groups[g]) - limit} more")
    if bulk:
        allb = [i for g in bulk for i in groups[g]]
        if len(bulk) <= 2:
            for g in bulk:
                lines.append(f"  {g}: {tally(groups[g])}")
        else:
            lines.append(f"  plugins/marketplaces: {len(bulk)} sources, {tally(allb)}")
    if len(lines) > budget:
        keep = max(budget - 1, 0)
        hidden = len(lines) - keep
        lines = lines[:keep] + [f"  ... {hidden} more line(s); use --format json for everything"]
    out += lines
    out.append(footer)
    return out[:max_lines]


def auto_line(n: int) -> str:
    return f"agent-integrity: auto-accepted {n} official-marketplace file(s) on provenance + clean signature scan (E8)"


def sarif(res: Result, findings: list[dict] | None = None) -> dict:
    """SARIF 2.1.0. `findings` = signature hits [{key, path, sigs}]; drift items come from res."""
    rule_ids: dict[str, dict] = {}

    def rule(rid: str, desc: str):
        rule_ids.setdefault(rid, {"id": rid, "name": rid.split("/")[-1],
                                  "shortDescription": {"text": desc},
                                  "helpUri": "https://github.com/OWNER/agent-integrity#threat-model"})

    results = []

    def add(rid, level, text, uri=None, sha=None):
        r = {"ruleId": rid, "level": level, "message": {"text": text}}
        if uri:
            r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        if sha:
            r["partialFingerprints"] = {"sha256/v1": sha}
        results.append(r)

    desc = {"changed": "A watched agent file changed since the signed baseline.",
            "added": "A new agent file appeared since the signed baseline.",
            "removed": "A watched agent file disappeared since the signed baseline."}
    for it in res.items:
        rid = f"agent-integrity/drift/{it['kind']}"
        rule(rid, desc[it["kind"]])
        add(rid, "error" if it["sigs"] else "warning",
            f"{it['kind']}: {it['key']}" + (f" (high-severity: {', '.join(it['sigs'])})" if it["sigs"] else ""),
            file_uri(it["key"]))
    for f in findings or []:
        for s in f["sigs"]:
            rid = f"agent-integrity/signature/{s}"
            rule(rid, SIG_DESC[s])
            add(rid, "error" if s in HIGH else "warning", f"{SIG_DESC[s]} ({f['key']})",
                file_uri(f["key"]), f.get("sha"))
    if res.status == "untrusted":
        rule("agent-integrity/manifest-untrusted", "The signed manifest failed verification or was rolled back.")
        add("agent-integrity/manifest-untrusted", "error", res.reason)
    if res.status == "stale":
        rule("agent-integrity/stale", "The root-owned check has not run recently.")
        add("agent-integrity/stale", "error", res.reason)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "agent-integrity", "version": VERSION,
                                      "informationUri": "https://github.com/OWNER/agent-integrity",
                                      "rules": list(rule_ids.values())}},
                  "results": results}],
    }


def file_uri(key: str) -> str:
    # Keys use `~` for the scanned user's home; keep it literal so reports are portable.
    return Path(key).as_uri() if os.path.isabs(key) else key


def emit(res: Result, fmt: str, args, findings=None) -> None:
    if fmt == "json":
        d = res.to_json()
        if findings is not None:
            d["findings"] = findings
        print(json.dumps(d, indent=1))
    elif fmt == "sarif":
        print(json.dumps(sarif(res, findings), indent=1))
    else:
        if getattr(args, "quiet", False) and res.status == "clean":
            return
        for line in render_text(res, args.limit, args.max_lines):
            print(line)


# --- Commands ------------------------------------------------------------------------------
def make_ctx(args, store: Store | None = None, manifest: dict | None = None) -> Ctx:
    home = Path(args.home) if args.home else Path.home()
    projects = args.project or (manifest or {}).get("projects") or [os.getcwd()]
    return Ctx(home, [Path(p) for p in projects])


def cmd_check(args) -> int:
    store = Store(args.store)
    res = run_check(args, store)
    emit(res, args.format, args)
    if args.write_heartbeat:
        hb = {"ts": args.now if args.now is not None else time.time(),
              "iso": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "status": res.status, "exit": res.exit, "seq": res.seq, "counts": res.counts(),
              "report": render_text(res, args.limit, args.max_lines)}
        try:
            atomic_write(store.heartbeat, json.dumps(hb, indent=1))
        except OSError as e:
            print(f"agent-integrity: could not write heartbeat: {e}", file=sys.stderr)
    return res.exit


def cmd_status(args) -> int:
    """Read-only: what the root check last recorded. Never scans, never writes."""
    store = Store(args.store)
    cfg = store.config()
    hb = load_json(store.heartbeat)
    now = args.now if args.now is not None else time.time()
    if not hb:
        print("AGENT-INTEGRITY: no root check result found. Run the root install, or `check` by hand "
              "(detection-only).")
        return EXIT_USAGE
    stale, why = heartbeat_state(store, cfg, now, args.stale_after or int(cfg.get("stale_after", DEFAULT_STALE_AFTER)))
    if stale:
        print(f"AGENT-INTEGRITY: STALE: {why}")
        return EXIT_STALE
    for line in hb.get("report", []):
        print(line)
    return int(hb.get("exit", EXIT_USAGE))


def cmd_scan(args) -> int:
    store = Store(args.store)
    ctx = make_ctx(args)
    allow = store.allow()
    findings = []
    for _a, p in surface_files(ctx, args.tier):
        if p.resolve() == SELF or p.is_symlink():
            continue
        hits = sig_hits(p, args.severity == "high")
        if not hits:
            continue
        d = sha_file(p)
        if allow.get(d):
            continue
        findings.append({"key": ctx.key(p), "sigs": hits, "sha": d})
    res = Result("scan", args.tier)
    res.scanned = len(findings)
    if findings:
        res.status, res.exit = "signatures", EXIT_DRIFT
    if args.format == "text":
        if not findings:
            if not args.quiet:
                print(f"agent-integrity scan: no unacknowledged signatures (tier {args.tier})")
        else:
            print(f"AGENT FILE SIGNATURES: {len(findings)} file(s) with unreviewed behaviour (tier {args.tier})")
            for f in findings[: args.limit]:
                print(f"  {f['key']}\n    -> {', '.join(f['sigs'])}  sha={f['sha'][:12]}")
            if len(findings) > args.limit:
                print(f"  ... +{len(findings) - args.limit} more")
            print("Review each. To accept one, add its sha256 with a reason to allow.json in the store.")
    else:
        emit(res, args.format, args, findings)
    return res.exit


def cmd_baseline(args) -> int:
    store = Store(args.store)
    pend = Path(args.pending_dir)
    ctx = make_ctx(args)
    try:
        prev, _ = load_trusted_manifest(store)
    except Untrusted:
        prev = {}
    old = prev.get("files", {})
    new = snapshot(ctx, args.tier)
    allow = store.allow()
    reviewed = set(args.i_reviewed or [])

    # Guard: never bless a file carrying a high-severity signature nobody has looked at.
    blocked = []
    for k, d in new.items():
        if old.get(k) == d:
            continue
        p = ctx.path(k)
        if not p.is_file() or p.is_symlink():
            continue
        hits = unreviewed_high(p, d, allow, reviewed)
        if hits:
            blocked.append((k, hits, d))
    if blocked:
        print(f"REFUSING TO BASELINE: {len(blocked)} new/changed file(s) carry high-severity signatures:")
        for k, hits, d in blocked[: max(args.limit, 10)]:
            print(f"  {k}\n    -> {', '.join(hits)}\n    reviewed it? add: --i-reviewed {d[:16]}")
        print("Read each file. Re-run with --i-reviewed <sha> per file you have judged safe.")
        return EXIT_DRIFT

    if args.tier != "all":
        new = {**{k: v for k, v in old.items() if not in_tier(k, args.tier)}, **new}
    projects = sorted({str(p) for p in ctx.projects} | set(prev.get("projects", [])))
    last = load_json(store.last_seen)
    seq = max(int(last.get("seq", 0)), int(prev.get("seq", 0))) + 1
    manifest = {"version": 1, "seq": seq, "created": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                "projects": projects, "marketplaces": marketplace_sources(ctx.home),
                "files": dict(sorted(new.items()))}
    pend.mkdir(parents=True, exist_ok=True)
    out = pend / "manifest.json"
    out.write_bytes(json.dumps(manifest, indent=1, sort_keys=True).encode() + b"\n")
    sigf = pend / "manifest.json.sig"
    if sigf.exists():
        sigf.unlink()   # a stale signature must never sit beside a different manifest
    print(f"baselined {len(new)} files -> PENDING {out} (seq {seq}); not trusted until signed.")
    print(f"Next: python3 {SELF.name} sign --key <your private key>")
    return EXIT_CLEAN


def install_signed(store: Store, manifest_path: Path, sig_path: Path) -> None:
    """Verify then install. Raises Untrusted on any failure, PermissionError if store is not writable."""
    raw = manifest_path.read_bytes()
    ok, why = verify_signature(store, raw, sig_path)
    if not ok:
        raise Untrusted(why)
    m = json.loads(raw)
    seq, created = int(m["seq"]), str(m["created"])
    last = load_json(store.last_seen)
    if last and (seq <= int(last.get("seq", 0)) or created < str(last.get("created", ""))):
        raise Untrusted(f"seq {seq} does not advance past last seen {last.get('seq')}")
    atomic_write(store.manifest, raw)
    atomic_write(store.sig, sig_path.read_bytes())
    atomic_write(store.last_seen, json.dumps({"seq": seq, "created": created,
                                              "sha256": hashlib.sha256(raw).hexdigest()}))


def cmd_promote(args) -> int:
    store = Store(args.store)
    pend = Path(args.pending_dir)
    try:
        install_signed(store, pend / "manifest.json", pend / "manifest.json.sig")
    except Untrusted as e:
        print(f"promote refused: {e}", file=sys.stderr)
        return EXIT_UNTRUSTED
    except PermissionError:
        print(f"promote needs write access to {store.root} (root-owned). Run:\n"
              f"  sudo python3 {SELF} promote --store '{store.root}' --pending-dir '{pend}'", file=sys.stderr)
        return EXIT_USAGE
    print(f"promoted signed manifest into {store.root}")
    return EXIT_CLEAN


def cmd_sign(args) -> int:
    pend = Path(args.pending_dir)
    mf = pend / "manifest.json"
    if not mf.is_file():
        print("no pending manifest; run baseline first", file=sys.stderr)
        return EXIT_USAGE
    sigf = pend / "manifest.json.sig"
    if sigf.exists():
        sigf.unlink()
    # Inherits the terminal: ssh-keygen prompts for the passphrase itself; this process never sees it.
    r = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", args.key, "-n", NAMESPACE, str(mf)])
    if r.returncode != 0:
        print("signing failed", file=sys.stderr)
        return EXIT_USAGE
    return cmd_promote(args)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="agent-integrity", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(s, scan=False):
        s.add_argument("--store", default=str(default_store()),
                       help="trusted store dir (root-owned after install-root.sh)")
        s.add_argument("--home", help="home dir to inspect (default: current user's)")
        s.add_argument("--project", action="append", help="project dir (repeatable; default: manifest's, or cwd)")
        s.add_argument("--tier", choices=["1", "2", "all"], default="1")
        s.add_argument("--quiet", action="store_true")
        s.add_argument("--limit", type=int, default=3, help="items listed per group in text output")
        s.add_argument("--max-lines", type=int, default=20)
        s.add_argument("--allow", help="extra allowlist json (sha256 -> reason)")
        s.add_argument("--now", type=float, help=argparse.SUPPRESS)
        s.add_argument("--stale-after", type=int, default=None, help="seconds before the root heartbeat is STALE")

    for name, fn in (("check", cmd_check), ("scan", cmd_scan)):
        s = sub.add_parser(name)
        common(s)
        s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
        s.add_argument("--severity", choices=["high", "all"], default="all")
        if name == "check":
            s.add_argument("--write-heartbeat", action="store_true", help="root daemon only: record this run")
        s.set_defaults(fn=fn)
    s = sub.add_parser("status")
    common(s)
    s.set_defaults(fn=cmd_status)
    s = sub.add_parser("baseline")
    common(s)
    s.add_argument("--pending-dir", default=str(default_pending_dir()))
    s.add_argument("--i-reviewed", action="append", metavar="SHA", help="file sha256 (prefix >= 12) you reviewed")
    s.set_defaults(fn=cmd_baseline)
    for name, fn in (("sign", cmd_sign), ("promote", cmd_promote)):
        s = sub.add_parser(name)
        s.add_argument("--store", default=str(default_store()))
        s.add_argument("--pending-dir", default=str(default_pending_dir()))
        if name == "sign":
            s.add_argument("--key", required=True, help="your private key (passphrase-protected)")
        s.set_defaults(fn=fn)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "i_reviewed", None):
        bad = [r for r in args.i_reviewed if len(r) < 12]
        if bad:
            print("--i-reviewed needs at least 12 hex chars of the file sha256", file=sys.stderr)
            return EXIT_USAGE
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
