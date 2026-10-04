# Architecture

Two languages, one pipeline: a Python toolchain (`tools/`) lifts the decrypted PE to C, and a
C runtime (`src/`) links that C against a Win32/DirectX HAL. The generated tree
(`src/game/recomp/gen/`) is local output and is never committed.

### Architecture

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
│   ├── fix_test_flags.py       # Fix TEST+JBE/JA codegen bug in generated output
│   ├── fix_string_ops.py       # Fix repne scasb / repe cmpsb codegen
│   ├── disasm_jmptbl.py        # Reconstruct unresolved switch/jump tables
│   ├── insert_func.py          # Lift a single missing function and splice it into the gen files
│   ├── read_real.py / poll_real.py / dbg_real.py  # Live guest-memory read/poll/debug helpers
│   ├── regen_0000.py           # Targeted regeneration of recomp_0000.c + dispatch/header
│   └── relift_func.py          # Re-lift a single function in place (codegen-bug iteration)
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

### Recompilation Approach

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

### Binary Analysis

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
| Functions recompiled | 2,702 |
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

### Known Engine Details

- **Developer**: Totally Games (dev path: `K:\XWA\dev\`)
- **Debug system**: `Deus debugging enabled, type %d, mask 0x%.8x`
- **Console**: `XWing Alliance Console` (debug build feature)
- **Sound engine**: `Aldraw_Init_Sound_Engine`
- **3D renderer**: `std3D_CacheTextureSurface`, D3D execute buffer model
- **Hardware detection**: 3dfx Voodoo / Glide checks
- **Registry**: `SOFTWARE\LucasArts Entertainment Company LLC\X-Wing Alliance\V2.0`
- **Command line**: `XwingAlliance.exe %d skipintro`

