# Changelog

All notable changes. Format: [Keep a Changelog](https://keepachangelog.com/), versions follow
SemVer. No release has been tagged yet; everything so far is `Unreleased`.

## [Unreleased]

### Added
- The single-player campaign plays through: mission 1 completes, lands, is debriefed and scored,
  the campaign records it, the family room shows its award, and mission 2 (`1b0m2fw`) loads.
  `XWA_AUTOPLAY=1` drives all of it headlessly (`XWA_DEBRSEL`, briefing skip, room pictures
  `shot_room*.bmp`). See `docs/campaign.md` steps 7-11.
- Mission 1 now runs through both pickups, the jump to Harlequin Station, the delivery there and
  the fuel-cell pickup; the hyper buoy home (waiting on the wingman) is the open blocker. The
  intermittent heap-corruption crash is fixed (`XWA_FGFILL` pool overrun). See `docs/campaign.md`.
- `tools/func_extent.py` (real function extent by control-flow walk); `XWA_NOFREE`, `XWA_WATCHOBJ`,
  `XWA_WATCHPICK`, `XWA_FGDUMP` diagnostics.
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
- HUD text and other colour-keyed textures drew on black boxes: the key (black) only became
  transparent if the colour key happened to be on when the texture was first uploaded, and the
  shader never tested it. Black texels now carry alpha 0 and are discarded while
  `COLORKEYENABLE` is on. Texture surfaces also remember their pixel format (an ARGB1555 request
  decodes as 1555); `SetColorKey` no longer overwrites the remembered caps.
- Flight textures: the game's own 3D draws (cockpit, HUD text, nearby craft) came out flat white/grey
  once more than 256 textures had been created -- the renderer's handle table was capped at 256 and
  handles were never reused. Handles now belong to the surface and are recycled when it is released.
- Native model drawer: craft whose textures the engine had not uploaded yet drew untextured. Their
  8-bit textures are now read from the `.OPT` files on disk (indexed once by texture id; the file is
  confirmed by its header), palette level 13 (`XWA_PALLEVEL`, measured with `XWA_PALCHECK`).
  `XWA_TEXSTATS` counts texture binds by outcome.
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
