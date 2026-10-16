#!/usr/bin/env python3
"""PreToolUse gate: refuse any Bash command that executes code fetched over the network.

Why: in August 2026 a developer asked an AI assistant for a transcription app, was handed an
unverified link to a copycat site, and pasted that site's terminal command. It ran instantly,
and the malware then wrote a poisoned SKILL.md into the agent's configuration. The infection
step was a single fetch piped into a shell. This gate removes that step: the bytes must land on
disk and be read before anything runs them.

Blocked shapes: curl|sh, wget|bash, bash <(curl ...), sh -c "$(curl ...)", source <(curl ...),
a path-qualified or env-wrapped interpreter, a bare interpreter fed stdin, and
download-and-run chains. There is no override.

Wire it as a Claude Code PreToolUse hook on Bash. Exit 2 + stderr = block, message shown to the agent.
This is a regex gate: it raises the cost of the common one-liner, it does not stop a determined
attacker who can phrase the fetch another way. See README.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

# A real fetch carries a URL or a variable holding one. Requiring that keeps prose
# ("a curl|sh install line") from tripping the gate — found 2026-08-29 when this gate
# blocked its own registry entry for containing the phrase.
FETCH = r"(?:curl|wget|aria2c|httpie)\b[^|\n]*?(?:https?://|\$\{?\w)"
# A bare shell run on fetched bytes always executes them.
# `(?:/\S*/)?` because `| /bin/bash` is the same shell as `| bash`; `env` because
# `| env bash` is too. `source`/`.` execute their argument, which is what `<(curl …)` is.
SHELL = r"(?<![\w.-])(?:source\b|\.\s|(?:/\S*/)?(?:env\s+)?(?:sh|bash|zsh|ksh|csh|tcsh|dash|fish|osascript)\b)"
# Scripting interpreters more often PARSE fetched data than run it (`curl ... | python3 -c` to
# read JSON). Blocking those outright made this gate block its own author on day two, and a gate
# that gets routed around is worse than no gate — so they count only when the inline code hands
# the bytes to an evaluator.
SCRIPT = r"(?<![\w.-])(?:/\S*/)?(?:env\s+)?(?:python3?|node|deno|bun|perl|ruby|php)\b"
# An interpreter handed fetched bytes EXECUTES them. Only these shapes demonstrably do not:
# `-m json.tool`/`-m base64` style module invocations, and `-c`/`-e` inline code that never
# reaches an evaluator. Anything else — bare `| ruby`, `| python3` — runs what it reads.
PARSE_ONLY_MODULE = re.compile(r"-m\s+(?:json\.tool|base64|gzip|zlib|csv|plistlib)\b")
INLINE_CODE = re.compile(r"-(?:c|e)\b")
EVAL = re.compile(
    r"\b(?:exec|eval|compile|system|popen|execSync|spawnSync|Function)\s*\(|"
    r"\bos\.system\b|\bsubprocess\b|\bchild_process\b|"
    r"\b__import__\s*\(|\bgetattr\s*\(|\brequire\s*\(\s*['\"]child_process", re.I)


def interpreter_only_parses(cmd: str) -> bool:
    """True only when the interpreter demonstrably parses stdin instead of running it."""
    if PARSE_ONLY_MODULE.search(cmd):
        return True
    if INLINE_CODE.search(cmd) and not EVAL.search(cmd):
        return True
    return False


# `cat > f <<'EOF' ... EOF` writes data. Its body is not executed, so attack strings may appear
# there as test fixtures or documentation. Bodies fed to an interpreter are NOT stripped.
HEREDOC = re.compile(r"<<-?\s*'?\"?(\w+)'?\"?(.*?)^\1$", re.S | re.M)
REDIRECTED = re.compile(r"(?:>|>>|\btee\b)\s*\S+[^\n]*<<-?\s*'?\"?\w+", re.M)

PATTERNS = [
    # curl https://... | sh      (allows intermediate filters: | tar |, | tee |, sudo)
    (re.compile(rf"{FETCH}[^|;&]*\|[^|;]*{SHELL}", re.I), "fetch piped into a shell"),
    (re.compile(rf"{FETCH}[^|;&]*\|[^|;]*{SCRIPT}", re.I),
     "fetch piped into an interpreter that evaluates it"),
    # bash <(curl ...)
    (re.compile(rf"{SHELL}[^\n]*<\(\s*{FETCH}", re.I), "process substitution from a fetch"),
    # sh -c "$(curl ...)"  /  eval "$(curl ...)"  /  eval `curl ...`
    (re.compile(rf"(?:{SHELL}[^\n]*|eval[^\n]*)(?:\$\(|`)\s*{FETCH}", re.I), "command substitution from a fetch"),
    # python -c 'urlopen(...).read()'  / node -e 'fetch(...)'
    (re.compile(r"\b(?:python3?|node|deno|bun|ruby|perl)\b[^\n]*-(?:c|e)\b[^\n]*(?:urlopen|urlretrieve|requests\.get|fetch\(|https?://)", re.I),
     "inline interpreter fetching and running remote code"),
    # curl -o /tmp/x URL && sh /tmp/x  — download-then-run in one breath means nothing read it.
    # Written out rather than reusing FETCH: the -o flag can sit before or after the URL.
    (re.compile(r"(?:curl\b(?=[^\n]*(?:-[oO]\b|--output\b|>))|wget\b)(?=[^\n]*https?://)"
                r"[^\n]*?(?:&&|;|\|\|)\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node|perl|ruby|\./|chmod\s+\+x)\b", re.I),
     "download-and-run chained in one command (nothing read it)"),
]


def strip_data_heredocs(cmd: str) -> str:
    """Blank out heredoc bodies that are written to a file rather than piped to an interpreter.

    Without this the gate blocks any command that WRITES about an attack — a test fixture, a
    runbook, this file's own docstring. It blocked exactly that on 2026-08-30.
    """
    if not REDIRECTED.search(cmd):
        return cmd
    return HEREDOC.sub(lambda m: f"<<{m.group(1)}\n\n{m.group(1)}", cmd)


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    if data.get("tool_name") != "Bash":
        return 0
    cmd = (data.get("tool_input") or {}).get("command") or ""
    if not cmd:
        return 0

    scanned = strip_data_heredocs(cmd)
    hits = []
    for rx, why in PATTERNS:
        if not rx.search(scanned):
            continue
        if why.endswith("that evaluates it") and interpreter_only_parses(scanned):
            continue  # demonstrably parsing fetched data, not running it
        hits.append(why)
    if not hits:
        return 0

    log(cmd, hits)
    sys.stderr.write(
        "BLOCKED: remote code execution: " + "; ".join(hits) + ".\n\n"
        "Fetched bytes must be saved to a file, read, and only then run. Do this instead:\n"
        "  1. download to a file (curl -fsSL URL -o installer.sh)\n"
        "  2. read it (and confirm the domain against the vendor's own documentation)\n"
        "  3. run the file you read\n"
        "If a package manager has the tool (brew install <pkg>), use that and skip the question.\n\n"
        "There is no override: a comment cannot make fetched bytes safe.\n"
    )
    return 2


def log(cmd: str, hits: list) -> None:
    d = os.environ.get("AGENT_INTEGRITY_LOG_DIR") or os.path.join(
        os.environ.get("AGENT_INTEGRITY_HOME") or os.path.expanduser("~/.agent-integrity"), "logs")
    try:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "remote-exec-gate.log"), "a") as fh:
            fh.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "verdict": "blocked",
                "reasons": hits,
                "command": cmd[:800],
            }) + "\n")
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
