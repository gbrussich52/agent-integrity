#!/usr/bin/env python3
"""Explanation clarity benchmark. Not part of the CLI path and not a CI gate: it needs a local model.

Runs the real EXPLAIN_SYSTEM prompt against a local Ollama model over bench/scenarios.json and scores each
answer with plain deterministic checks (no model grades another model). Exit 1 if the pass rate is under 90%.

    python3 bench/run.py --model gpt-oss:20b
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import secrets
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import agent_integrity as ai  # noqa: E402

JARGON = ["exfiltration", "exfiltrate", "rce", "arbitrary code execution", "persistence", "lateral", "privilege escalation",
          "attack surface", "threat actor", "payload", "obfuscat", "vector", "supply chain", "ioc", "tampering"]
VERBS = {"review", "remove", "check", "open", "revert", "restore", "delete", "disable", "ask", "verify", "confirm", "keep",
         "undo", "inspect", "read", "look", "turn", "put", "reenable", "reinstall", "update", "stop", "do", "make", "compare",
         "run", "reject", "uninstall", "readd", "add", "set", "change", "accept", "approve", "treat", "make", "contact"}
RANK = {"low": 0, "medium": 1, "high": 2}


def syllables(word: str) -> int:
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return 0
    groups = re.findall(r"[aeiouy]+", w)
    n = len(groups)
    if w.endswith("e") and not w.endswith(("le", "ee")) and n > 1:
        n -= 1
    return max(1, n)


def prose(text: str) -> str:
    """Drop names a developer must see verbatim (paths, commands, setting keys) so they do not count as long
    words; a sentence-ending mark on such a name is kept so sentence counts stay honest."""
    out = []
    for t in text.split():
        core = t.rstrip(".,;!?")
        if re.search(r"[/~()\\_.=:@*]", core):
            if t[len(core):] in (".", "!", "?"):
                out.append(t[len(core):])
            continue
        out.append(t)
    return " ".join(out).replace(" .", ".")


def flesch(text: str) -> float:
    text = prose(text)
    sents = [s for s in re.split(r"[.!?]+(?:\s|$)", text) if s.strip()]
    words = re.findall(r"[A-Za-z][A-Za-z'\-]*", text)
    if not sents or not words:
        return 0.0
    syl = sum(syllables(w) for w in words)
    return 206.835 - 1.015 * (len(words) / len(sents)) - 84.6 * (syl / len(words))


def sentence_count(text: str) -> int:
    return len([s for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()])


def score(sc: dict, raw: str) -> dict:
    checks: dict[str, bool] = {}
    v = ai.parse_verdict(raw)
    checks["valid_json"] = v is not None
    v = v or {}
    summary, why = v.get("summary", ""), v.get("why", "")
    detail, action = v.get("detail", ""), v.get("action", "")
    checks["summary_short"] = bool(summary) and sentence_count(summary) <= 2 and len(summary.split()) <= 40
    fre = flesch(". ".join(t.rstrip(" .!?") for t in (summary, why) if t.strip()) + ".")   # a missing full stop must not merge two sentences
    checks["readable"] = fre >= 55
    low = summary.lower()
    checks["no_jargon"] = bool(summary) and not any(j in low for j in JARGON)
    hay = (summary + " " + detail).lower()
    missing = [m for m in sc["must_mention"] if m.lower() not in hay]
    checks["mentions_facts"] = bool(summary) and not missing
    first = re.sub(r"[^a-z\-]", "", (action.replace("\u2011", "-").split() or [""])[0].lower()).replace("-", "")
    checks["action_imperative"] = bool(action) and (first in VERBS or action.lower().startswith("nothing to do"))
    fix = ("remove", "revert", "restore", "delete", "turn", "put", "pin", "rotate", "undo", "uninstall", "disable", "keep",
           "add", "change", "set")   # concrete edits; "Review X" / "Check X" alone are not
    checks["action_concrete"] = action.lower().startswith("nothing to do") or any(
        re.search(rf"\b{f}\b", action.lower()) for f in fix)   # "Review X" alone is not a fix (judge round 1)
    checks["risk_floor"] = v.get("risk") in RANK and RANK[v["risk"]] >= RANK[sc["floor"]]
    return {"id": sc["id"], "pass": all(checks.values()), "checks": checks, "flesch": round(fre, 1),
            "missing": missing, "answer": v or raw[:400]}


def ask(url: str, model: str, sc: dict, timeout: float) -> str:
    nonce = secrets.token_hex(8)
    # Same signature wording production puts in the excerpt, so the bench cannot drift from the real format.
    excerpt = sc["excerpt"].replace("{SIGS}", "signature hits: " + ai.sig_text(sc.get("sigs", [])))
    prompt = (f"Assess this change.\nBEGIN-UNTRUSTED-{nonce}\n{excerpt}\nEND-UNTRUSTED-{nonce}\n"
              "Reply with the JSON object only.")
    be = {"kind": "ollama", "url": url, "model": model}
    return ai.llm_call(be, ai.EXPLAIN_SYSTEM, prompt, timeout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--url", default="http://127.0.0.1:11434")
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--only", help="comma-separated scenario ids")
    ap.add_argument("--tag", default="", help="suffix for the results file, e.g. v3")
    a = ap.parse_args()
    if not ai.is_loopback(a.url):
        print("bench only talks to a loopback model", file=sys.stderr)
        return 2
    scenarios = json.loads((HERE / "scenarios.json").read_text())
    if a.only:
        keep = set(a.only.split(","))
        scenarios = [s for s in scenarios if s["id"] in keep]
    rows = []
    for sc in scenarios:
        t0 = time.time()
        try:
            raw = ask(a.url, a.model, sc, a.timeout)
        except Exception as e:                      # a dead model is a failed scenario, not a crash
            raw = f"ERROR {type(e).__name__}: {e}"
        r = score(sc, raw)
        r["seconds"] = round(time.time() - t0, 1)
        rows.append(r)
    names = ["valid_json", "summary_short", "readable", "no_jargon", "mentions_facts", "action_imperative", "action_concrete", "risk_floor"]
    print(f"{'scenario':<24}{'pass':<6}{'flesch':<8}" + " ".join(n[:6] for n in names))
    for r in rows:
        print(f"{r['id']:<24}{'PASS' if r['pass'] else 'FAIL':<6}{r['flesch']:<8}" +
              " ".join(("ok" if r['checks'][n] else "XX").ljust(6) for n in names)
              + ("  missing: " + ", ".join(r["missing"]) if r["missing"] else ""))
    ok = sum(r["pass"] for r in rows)
    rate = ok / len(rows) if rows else 0.0
    print(f"\n{a.model}: {ok}/{len(rows)} scenarios pass ({rate:.0%}); prompt chars={len(ai.EXPLAIN_SYSTEM)}")
    out = HERE / "results" / f"{datetime.date.today().isoformat()}-{a.model.replace(':', '_').replace('/', '_')}{('-' + a.tag) if a.tag else ''}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"model": a.model, "pass_rate": rate, "passed": ok, "total": len(rows), "results": rows},
                              indent=1) + "\n")
    print(f"wrote {out.relative_to(HERE.parent)}")
    return 0 if rate >= 0.9 else 1


if __name__ == "__main__":
    sys.exit(main())
