# X-Wing Alliance Static Recompilation

A static recompilation of **Star Wars: X-Wing Alliance** (1999) by Totally Games / LucasArts, targeting modern Windows with native x86 execution and a modern graphics pipeline.

## Project Status

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 0** | **Complete** | Binary analysis, PE parsing, section mapping |
| **Phase 1** | **Complete** | SafeDisc decryption, memory dump from runtime |
| **Phase 2** | **Complete** | Function discovery (2,674 functions, 443,224 instructions) |
| **Phase 3** | **Complete** | x86-to-C code generation (2,701 functions, 606,424 lines of C) |
| **Phase 4** | **Complete** | Compilation and linking (0 errors, 1 warning) |
| **Phase 5** | **Complete** | Runtime execution — CRT init, import bridging, game startup |
| **Phase 6** | **Complete** | Win32/DirectX HAL — COM mocks operational, main loop running |
| **Phase 7** | **Complete** | D3D11 rendering backend — device, shaders, execute buffer parser, 2D surface pipeline |
| **Phase 8** | **In Progress** | Frontend menu rendering — CBM decode, RLE blit, surface compositing |
| Phase 9 | Pending | Game tick (sub_005397D0), 3D rendering, audio, full game logic |

### Runtime Progress

The recompiled binary boots through full initialization, loads game assets, and renders the concourse menu:

- **Stable main loop**: 29M+ PeekMessage calls per 15-second run, zero crashes
- **VC6 CRT initialization**: heap, locks, stdio, atexit all functional
- **Native file I/O**: 8 VFS-level CRT functions replaced with host CRT (fopen/fread/fclose/fseek/ftell/fwrite) — game's recompiled CRT was corrupted
- **39 .dat resource files** + **CBM concourse backgrounds** loaded successfully
- **Window creation**: "X-Wing Alliance" window at 1920x1080 (native resolution)
- **DirectX COM mocks**: Full mock objects for IDirectDraw, IDirectDrawSurface, IDirect3D, IDirect3DDevice, IDirectInput, IDirectInputDevice, IDirectSound, IDirectSoundBuffer (178 vtable bridges)
- **357 total bridges** registered (179 Win32 API + 178 COM vtable)
- **45 manual overrides** including 6 callback functions missed by code generator
- **Callee-saved register protection**: g_ebx/g_esi/g_edi automatically preserved across all calls
- **6 SafeDisc-encrypted jump tables** reconstructed with switch/goto
- **D3D11 rendering backend**: Device (feature level 11.0), swap chain, HLSL shaders, execute buffer parser, texture manager, 2D surface blit (RGB565→BGRA8)
- **2D rendering pipeline**: CBM RLE decode → offscreen surface → BltFast → back buffer → D3D11 upload → present. ~23% surface coverage per frame (menu background with transparency)

### Fixes Applied During Runtime Bringup

| # | Fix | Impact |
|---|-----|--------|
| 1 | SafeDisc function stubs (4 encrypted functions) | Bypass copy protection checks |
| 2 | SafeDisc jump table reconstruction (6 switch statements) | Correct control flow in CRT + game |
| 3 | Null function pointer guard (ICALL(0) → no-op) | Prevent crash on null callback |
| 4 | Retry/fail dialog stub (sub_00433C50 → returns 'F') | Avoid infinite retry loop |
| 5 | SBH (small block heap) disabled, heap handle set | Use system heap instead of VC6 SBH |
| 6 | 36 CRT lock objects pre-initialized | Multi-threaded CRT support |
| 7 | `_initstdio` manual implementation | stdin/stdout/stderr FILE structs |
| 8 | VEH crash handler with ring buffer trace | Diagnostics for runtime crashes |
| 9 | `TEST x,x; jge/jg/jle` codegen fix (1,122 instances) | Correct signed-negative checks |
| 10 | `repne scasb` / `repe cmpsb` codegen fix (961 instances) | Correct string operations |
| 11 | `TEST x,x; jbe/ja` codegen fix (208 instances) | Correct unsigned flag checks |
| 12 | `DEC x; jcc` codegen fix (1,205 instances) | Compare result vs 0, not 1 |
| 13 | COM mock infrastructure (IDirectDraw, IDirect3D, etc.) | Game passes DirectX init |
| 14 | Callee-saved register protection in RECOMP_CALL | Fixes systemic ebx/esi/edi corruption |
| 15 | 6 callback function manual overrides | Missed entry points for function pointers |
| 16 | Watchdog uses TerminateProcess (avoids loader lock) | Clean shutdown on hang |
| 17 | D3D11 rendering backend (device, shaders, pipeline) | Modern GPU rendering via execute buffer translation |
| 18 | IDirect3DTexture mock with GetHandle/Load | Texture handle tracking for execute buffer rendering |
| 19 | Native CRT file I/O (8 VFS functions replaced) | Game's recompiled CRT was corrupted; host CRT works |
| 20 | `rep stosw` implementation (32 instances) | RLE pixel fill was silently no-op'd |
| 21 | Display BPP global (0x9F700A) initialization | All 2D blit functions use this for 8/16bpp path selection |
| 22 | `test REG; mov REG; jcc` codegen fix | Flag evaluation used wrong (post-mov) register value |
| 23 | BltFast surface copy implementation | Offscreen→back buffer compositing for menu rendering |

## Binary Analysis

| Property | Value |
|----------|-------|
| **Target** | `xwingalliance.exe` (2.44 MB) |
| **Compiler** | Visual C++ 6.0 (Visual Studio 98) |
| **Build Date** | 1999-06-15 |
| **Architecture** | x86-32, PE32, fixed base 0x00400000 |
| **Code (.text)** | 0x00401000 - 0x005A8B20 (1.7 MB, 1,735,456 bytes) |
| **Read-only Data (.rdata)** | 0x005A9000 - 0x005ADA24 (18 KB) |
| **Read/Write Data (.data)** | 0x005AE000 - 0x00B0F974 (5.4 MB) |
| **Copy Protection** | SafeDisc v1 (.bind section, runtime decryption) |
| **ASLR** | None (fixed image base, no relocations) |

### Recompilation Statistics

| Metric | Value |
|--------|-------|
| Functions recompiled | 2,701 |
| Total lines of C | 606,424 |
| Generated code size | 33.4 MB |
| Source files | 6 + header + dispatch table |
| Code generation time | ~7 seconds |
| Compilation errors | 0 |
| Link errors | 0 |
| Warnings | 1 (harmless shift count) |

### DirectX API Surface

The game uses **DirectX 5/6 era** APIs:

| API | DLL | Usage |
|-----|-----|-------|
| **DirectDraw** | ddraw.dll | Surface management, 2D rendering |
| **Direct3D Immediate Mode** | (via DirectDraw) | 3D rendering with execute buffers (pre-DrawPrimitive) |
| **DirectSound** | dsound.dll | Sound effects and audio |
| **DirectInput** | dinput.dll | Joystick and keyboard input |
| **DirectPlay** | dplayx.dll | Multiplayer networking |
| **iMUSE** | (statically linked) | LucasArts interactive music engine |
| **SMUSH** | tgsmush.dll | FMV video playback (5 exports) |

### Import Summary

| DLL | Functions | Purpose |
|-----|-----------|---------|
| KERNEL32.dll | 100 | Core Win32 APIs |
| USER32.dll | 34 | Window management, input |
| GDI32.dll | 14 | Font/text rendering |
| WINMM.dll | 13 | Joystick, timers, CD audio |
| tgsmush.dll | 5 | SMUSH video playback |
| ADVAPI32.dll | 4 | Registry (settings) |
| ole32.dll | 3 | COM initialization |
| DDRAW.dll | 2 | DirectDraw |
| DINPUT.dll | 1 | DirectInput |
| DSOUND.dll | 1 | DirectSound |
| DPLAYX.dll | 1 | DirectPlay (multiplayer) |
| SHELL32.dll | 1 | ShellExecute |

## Architecture

```
xwa-recomp/
├── tools/                      # Python toolchain
│   ├── pe_analyze.py           # PE header/section/import parser
│   ├── disasm.py               # Capstone-based x86 disassembler + function finder
│   ├── lifter.py               # x86 instruction → C code lifter
│   ├── generate.py             # Linear sweep code generator (fast)
│   ├── translator.py           # Full pipeline orchestrator (legacy)
│   ├── dump_memory.py          # SafeDisc runtime decryption dumper
│   ├── fix_test_cond.py        # Fix TEST codegen bug (same-register CMP → TEST_NS/G/LE)
│   └── regen_0000.py           # Targeted regeneration of recomp_0000.c + dispatch/header
├── src/
│   ├── game/
│   │   ├── main.c              # Entry point, VEH handler, memory setup, manual overrides
│   │   ├── imports.c           # Win32/DirectX import bridges (179 functions)
│   │   ├── com_mocks.c         # COM mock objects (DirectDraw, Direct3D, DirectInput, etc.)
│   │   ├── com_mocks.h         # COM mock types and creation APIs
│   │   └── recomp/
│   │       ├── recomp_types.h  # Register model, memory macros, dispatch
│   │       └── gen/            # Auto-generated code (gitignored)
│   └── hal/
│       ├── d3d11_renderer.c    # D3D11 backend: device, execute buffer parser, textures
│       ├── d3d11_renderer.h    # D3D5 structures, render state enums, renderer API
│       └── shaders.h           # HLSL shader source (compiled at runtime)
├── config/
│   ├── pe_analysis.json        # PE metadata
│   └── functions.json          # Function list with addresses/sizes
├── CMakeLists.txt              # MSVC 2022 x86 build
├── CLAUDE.md                   # AI assistant project context
└── README.md                   # This file
```

## Recompilation Approach

### Global Register Model

x86 registers are mapped to C global variables following the [burnout3](https://github.com/sp00nznet/burnout3) pattern:

```c
/* Volatile (caller-saved) */
uint32_t g_eax, g_ecx, g_edx, g_esp;

/* Callee-saved (auto-preserved by RECOMP_CALL/RECOMP_ICALL macros) */
uint32_t g_ebx, g_esi, g_edi;

/* ebp is local per-function (FPO) */
```

Callee-saved registers (ebx, esi, edi) are automatically saved/restored around every `RECOMP_CALL` and `RECOMP_ICALL`, enforcing the x86 calling convention even when recompiled functions have stack imbalances.

### Memory Access

Original data sections are mapped at their original virtual addresses. Memory access uses macros that translate through a base offset:

```c
#define MEM32(addr) (*(volatile uint32_t *)ADDR(addr))
```

### Indirect Call Dispatch

Three-tier lookup for indirect calls (vtables, function pointers):

1. **Manual overrides** — hand-implemented replacements
2. **Auto dispatch table** — binary search over 2,674 recompiled functions
3. **Import bridges** — Win32/DirectX API translations

### Condition Generation

Flags are pattern-matched from setter (cmp/test/sub) to consumer (jcc/setcc/cmovcc):

```c
/* cmp eax, 5; jb target → */
if (CMP_B(eax, 5u)) goto L_target;
```

## Build Requirements

- **CMake** 3.20+
- **Visual Studio 2022** (MSVC, x86/Win32 target)
- **Python 3.10+** with `capstone`, `pefile`

## Building

```bash
# Generate recompiled code (requires decrypted binary)
python -m tools config/xwingalliance_decrypted.exe --all -o src/game/recomp/gen

# Configure and build
cmake -B build -G "Visual Studio 17 2022" -A Win32
cmake --build build --config Release
```

## SafeDisc Note

The Steam distribution of X-Wing Alliance encrypts the `.text` section with SafeDisc v1. The code is decrypted at runtime by the `.bind` section stub. Use `tools/dump_memory.py` to launch the game via Steam and dump the decrypted code:

```bash
# Launch game through Steam first, then:
python tools/dump_memory.py --pid <PID> "path/to/xwingalliance.exe" config/xwingalliance_decrypted.exe
```

## Known Engine Details

- **Developer**: Totally Games (dev path: `K:\XWA\dev\`)
- **Debug system**: `Deus debugging enabled, type %d, mask 0x%.8x`
- **Console**: `XWing Alliance Console` (debug build feature)
- **Sound engine**: `Aldraw_Init_Sound_Engine`
- **3D renderer**: `std3D_CacheTextureSurface`, D3D execute buffer model
- **Hardware detection**: 3dfx Voodoo / Glide checks
- **Registry**: `SOFTWARE\LucasArts Entertainment Company LLC\X-Wing Alliance\V2.0`
- **Command line**: `XwingAlliance.exe %d skipintro`

## Legal

This project is for game preservation purposes. You must own a legal copy of Star Wars: X-Wing Alliance to use this tool. No copyrighted game assets are included in this repository.

## Related Projects

Part of the [sp00nznet](https://github.com/sp00nznet) recompilation collection. See also:
- [burnout3](https://github.com/sp00nznet/burnout3) — Original Xbox x86 recomp (reference for x86-to-C lifter)
- [bw](https://github.com/sp00nznet/bw) — Black & White Win32 recomp (reference for Win32 game patterns)
- [civ](https://github.com/sp00nznet/civ) — Civilization DOS recomp (reference for 16-bit x86 lifting)
