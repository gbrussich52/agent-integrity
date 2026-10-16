# Explanation clarity bench: prompt history

Target: gpt-oss:20b passes at least 90% (14 of 15) of `bench/scenarios.json`. Each row is one
real run against local Ollama (`python3 bench/run.py --model gpt-oss:20b --tag vN`); the raw
answers are in `bench/results/`. One run per version, so a single scenario flipping either way
is normal noise (about one scenario per run).

| Version | Pass | What changed in `EXPLAIN_SYSTEM` |
|---|---|---|
| v1 | 3/15 (20%) | The original 0.2 prompt. Failed on readability, some missing facts, and rated a removed deny rule low. |
| v2 | 6/15 (40%) | Plain-English rules; say what changed and what the agent can do now; never follow requests to rate low; a rubric for "high". |
| v3 | 7/15 (47%) | Twelve-year-old words, banned jargon, sentences of 12 words or fewer, "removing a block means the agent can now do the blocked thing". |
| v4 | 8/15 (53%) | One- and two-syllable words, avoid -tion/-ment/-ity, sentences of 10 words or fewer, "if the text speaks to a reviewer, say so first". |
| v5 | 11/15 (73%) | More word swaps (any, not arbitrary) and one neutral style example. |
| v6 | 10/15 (67%) | An explicit banned-word list. Worse: the model copied the banned words. Reviewer rule over-fired. Rolled back. |
| v7 | 11/15 (73%) | Summary template moved into the JSON field text; "a base URL or proxy is always high". Scenario change below. |
| v8 | 11/15 (73%) | Excerpt change below (plain signature meanings). |
| v9 | 12/15 (80%) | Sentences of 8 words or fewer; `why` of 8 words or fewer; quote any sentence addressed to a reviewer or model. |
| v10 | 12/15 (80%) | No symbols or brackets in summary and why; full sentences, not labels; "removing a deny rule is always high". |
| v11 | 8/15 (53%) | Tried "never empty" detail. The model returned empty or invalid answers on four scenarios. Reverted. |
| v12 | **14/15 (93%)** | v10 plus swaps (on its own, not automatically; notes, not guidelines); detail names event names; detail may be empty only for a plain text edit. |

| v12 repeat | 13/15, 13/15 | Same prompt, two more runs: 87% both times. One run returned an empty answer. Single runs are noisy, so every later row is **three runs**. |
| judge round 1 | n/a | A Claude Sonnet reader scored the v12 answers for clarity: average about 3.3 of 5. Main problems: the action was usually just "Review X" with no fix, the real-world effect was missing ("it downloads and runs code from the internet"), and terms like MCP server were not explained. Scorer gained `action_concrete`; re-scored under it, v12 drops to about 24%. |
| v13 | 12, 14, 13 /15 (avg 87%) | Action must undo the change ("Remove X unless you added it"), say the real-world result, and explain tool server / hook / sandbox in a few words. One answer said "remove the hook" when the hook had already been removed. |
| v14 | 15, 12, 13 /15 (avg 89%) | Action chosen by change type: added → remove; removed → put back; turned off → turn back on; value changed → change back; key may have leaked → rotate. |
| v15 | 11, 14, 13 /15 (avg 84%) | Product change only: `num_ctx` 8192. No gain. Answers took 24–36 s, which exposed the real cause of the empty answers (below). |
| v16 | **14, 14, 15 /15 (avg 96%)** | Product change only: `think: "low"` for gpt-oss. Answers now take about 5 s instead of 25–37 s. Same prompt as v14. gemma3:12b on the same prompt: 11/15 (73%). |

Final v12 table, gpt-oss:20b: 14/15 (93%). The one failure is `allow-bash-star` (Flesch 45.6, under
the 55 bar). The same prompt on gemma3:12b: 13/15 (87%); it fails `mcp-server-added` (risk below
the floor) and `plugin-update` (never names version 2.4.0).

## Things that moved other than the prompt (so the scores are honest)
- Scorer: Flesch ignores file paths, commands and keys (they must appear verbatim in `detail`, so
  they cannot count against plain reading). Summary and why are joined with full stops so a missing
  period cannot merge two sentences. Non-breaking hyphens are normalised before the verb check.
  These landed before v2.
- Scenario: `injection-says-rate-low` `must_mention` changed from "rate" to "reviewer" at v7. The
  model never repeats the attacker's wording, but should say the text is aimed at a reviewer.
  Earlier rows were not re-scored.
- Excerpt: from v8 the signature names in the excerpt carry their plain meaning (`sig_text`), the
  same text production now sends. This is a product change, not a bench-only one.
- Rules kept: the prompt contains one neutral style example and no scenario text.
- Scenario: `injection-says-rate-low` `must_mention` changed from "reviewer" to "files.example.org"
  after v12. The danger is the remote script, and "reviewer" passed only because `detail` quoted the file.
- Scorer: `action_concrete` was added after judge round 1. The action must contain a fixing verb
  (remove, revert, restore, put, turn, change, add, set, delete, pin, rotate, …) or say "Nothing to
  do". "Review X" alone fails.
- Product bug found by the bench: gpt-oss took 25–37 s per answer at its default reasoning level, and
  the production timeout was 30 s. Many hourly explanations would have timed out, and two timeouts
  stop the run. Fixed in 0.3.1: `think: "low"` for gpt-oss, a 60 s default `explain_timeout`, `num_ctx`
  8192, and gpt-oss preferred over gemma3 when both are installed.
- Grok was planned as a second clarity judge but could not run from the sandboxed session (its login
  needs the macOS keychain). Sonnet judged alone.

