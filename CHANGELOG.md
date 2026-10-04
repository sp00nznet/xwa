# Changelog

All notable changes. Format: [Keep a Changelog](https://keepachangelog.com/), versions follow
SemVer. No release has been tagged yet; everything so far is `Unreleased`.

## [Unreleased]

### Added
- `XWA_AUTOPLAY=1`: headless test harness that plays 1b0m1fw through the game's own pickup/dock/
  hyperspace commands and in-flight messages (`tools/hooks/msg-tap.hook`). Gets through the hangar
  launch and the first pickup.
- Lifter patchers `tools/fix_carry.py`, `tools/fix_shiftflags.py`; host-chain sampling profiler.
- netlab build and test: `tools/netlab_run.cmd` (the campaign mission load on a Windows test VM,
  per-experiment knobs from `xwa_knobs.cmd` in the game dir); CMake `GEN_OPT` and a static CRT so
  the clang-cl farm build runs on a machine without the VC++ redistributable.
- `XWA_MEMFIND=<text>`: find a string in guest memory and the `.data` pointers to it.
- `tools/fix_fnstsw.py`, `tools/audit/` and `docs/lifter-audit.md`.
- Single-player campaign: mission `1b0m1fw` loads through the engine's own barracks -> loading ->
  flight route and flies the mission's own craft (YT-1300), with the real station and hangar models.
  Supplied state lives in `tools/hooks/` (DirectPlay host path, roster seed, player FG craft, player
  craft type, seat-player), each default-on with an `XWA_NO*` off switch. See `docs/campaign.md`.
- Diagnostics: `XWA_MODELDBG`, `XWA_INPUTDBG`, `XWA_KEYINFLIGHT`, `XWA_HANGARDBG`, `XWA_HANGARON`.
- `tools/play.sh` for hand play; `tools/run_tests.sh` regression suite (7 tests).
- `tools/apply_hooks.py` and `tools/hooks/`: env-gated patches that survive a regeneration.
- Texture-mapped 3D flight from the game's own OPT models (native renderer, `XWA_NATIVEDRAW`).
- `CHANGELOG.md`, `ROADMAP.md`, `docs/architecture.md`, `docs/building.md`, `docs/campaign.md`,
  `docs/bringup.md`.

### Changed
- README restructured to the house layout; deep-dive sections moved into `docs/`.

### Fixed
- `XWA_RENDERFN` freed a bogus pointer (0x7828D0 = 1): heap corruption behind the old
  `L_0048967D` crash. MKCTX/RENDERFN/RUNSCENE dropped from the netlab run.
- Host FILE streams read through the game's CRT fgetc/fread; EOF bit mirrored for game code.
- `fnstsw` was lifted as a comment, so every `fcom; fnstsw ax; test ah,N; jcc` float compare (595
  sites) branched on a stale AH. Lifter fixed; gen patched in place by `tools/fix_fnstsw.py`.
- DirectInput buffered keyboard mock ignored `DIGDD_PEEK` and never carried real keys, so the
  in-flight hangar menu could not be driven by a script or a person. ENTER now selects Launch.
- `com_ensure_d3d_device` was used before its declaration (clang-cl rejected the implicit `int`).
- Native drawer read the object index (`+0`) as the craft type instead of `+2`, so every ship drew
  with the wrong model.
- x87 pop-arithmetic in the lifter: `fOPp st(i)` ignored its index and `fsubp`/`fsubrp`,
  `fdivp`/`fdivrp` were reversed (239 wrong sites), ported from pcrecomp.
- The game read the machine's mouse and keyboard while unfocused; input now follows window focus
  (`XWA_REALMOUSE=1` restores the old behaviour).
- `XWA_WINKEY` key injection was spliced into `PostQuitMessage`; moved to `GetAsyncKeyState`.
- Dispatch table rebuilt from function definitions: eight lifted functions were unreachable by
  indirect call.
- Stack-buffer overflow in the IDirect3DViewport vtable setup.

### Removed
- Binary-derived tables from version control (`config/functions.json`,
  `config/ghidra_func_bounds.csv`, `config/pe_analysis.json`, live-memory snapshots in `docs/`),
  and `CLAUDE.md`. They are produced locally; history still contains the old copies.
