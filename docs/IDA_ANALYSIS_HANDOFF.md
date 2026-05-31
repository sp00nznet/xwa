# IDA Pro Cross-Validation — X-Wing Alliance

Headless IDA Pro 9.1 analysis of `config/xwingalliance_decrypted.exe`, cross-checked
against `config/functions.json`. 93% overlap (2,503 / 2,702) confirms the decrypted
exe is the right image; analysis is sound.

XWA is far along (Phase 8), so this is a *refinement* pass, not a rescue — but it
found concrete, fixable issues.

## Summary

| | |
|---|---|
| IDA functions | 2,729 |
| Recomp `functions.json` | 2,702 |
| Overlap | 2,503 |
| IDA-only (recomp may have missed) | 226 → **177 actionable** (85 called, 92 ptr-table) |
| Recomp-only (IDA: not a function) | 199 (123 boundary, 69 orphan, **7 false-positives**) |
| FLIRT names recovered | 310 |

> Note: XWA is mostly **C**, not C++/MFC — only 4 true pointer tables (not C++
> vtables). The "92 ptr-table" misses are functions reached through function-pointer
> dispatch tables, which call-graph discovery doesn't follow.

## 🐛 Fix first: 7 false-positive "functions" (`crimson_recomp_only.csv`)
The recomp lists these as functions, but they are **not code entry points** — they
will lift to garbage:

| Address | What it actually is |
|---|---|
| `0x004F15ED` | **jump table** (switch statement data) |
| `0x005174C9` | **jump table** (switch statement data) |
| `0x004B8EAB` | alignment padding (`align 10h`) |
| `0x004BA316` | alignment padding (`align 4`) |
| `0x0052AC3A` | alignment padding (`align 10h`) |
| `0x0048E5BB` | mid-instruction (inside another function) |
| `0x00595FA4` | mid-instruction (inside another function) |

**Action:** remove these 7 from `functions.json`. Easy win, removes garbage output.

## Missed functions (`crimson_ida_only.csv`, kind = called / vtable)
**177** functions IDA found that the recomp lacks — **85 are directly called by code**
(definitely real), 92 are reached via function-pointer tables. For a Phase-8 project
pushing toward Phase 9 (3D render / input / audio / sim), some of these are likely the
exact handlers still missing. Triage `crimson_ida_only.csv` (filter `kind=called`).

## Boundary / orphan (199 recomp-only, minus the 7)
- **123 mid_function** — recomp splits finer than IDA (tail calls / shared code); usually legitimate.
- **69 code_orphan** — code IDA didn't wrap as a function; worth a glance, may overlap the missed set.

## Enrichment: 310 FLIRT names (`crimson_ida_names.csv`)
Library functions (VC CRT, std) named by IDA that the recomp has as `sub_`.

## Artifacts (`E:\ida\work\xwa\`)
- `crimson_recomp_only.csv` — the 199, classified (contains the 7 to delete)
- `crimson_ida_only.csv` — the 226, classified (the 177 to add)
- `crimson_ida_names.csv` — 310 names
- `crimson_missed_virtuals.csv` — 89 pointer-table targets

## Reproduce
```
py -3.11 tools/crimson_gap.py      xwingalliance_decrypted.exe config/ <out>
py -3.11 tools/crimson_vtables.py  xwingalliance_decrypted.exe config/ <out>
```
