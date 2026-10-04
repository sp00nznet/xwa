# Changelog

All notable changes. Format: [Keep a Changelog](https://keepachangelog.com/), versions follow
SemVer. No release has been tagged yet; everything so far is `Unreleased`.

## [Unreleased]

### Added
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
