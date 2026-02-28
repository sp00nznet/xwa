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
| Phase 5 | Pending | Win32/DirectX HAL (D3D11 rendering, DirectSound, DirectInput) |
| Phase 6 | Pending | Game loop execution, import bridging |

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
│   └── dump_memory.py          # SafeDisc runtime decryption dumper
├── src/
│   └── game/
│       ├── main.c              # Entry point, VEH handler, memory setup
│       └── recomp/
│           ├── recomp_types.h  # Register model, memory macros, dispatch
│           └── gen/            # Auto-generated code (gitignored)
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

/* Callee-saved (global for implicit parameter passing) */
uint32_t g_ebx, g_esi, g_edi;

/* ebp is local per-function (FPO) */
```

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
