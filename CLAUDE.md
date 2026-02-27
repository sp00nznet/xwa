# X-Wing Alliance Static Recompilation

## Project Overview
Static recompilation of Star Wars: X-Wing Alliance (1999) from its original Win32 PE32 x86 binary into clean, compilable C code that runs natively on modern Windows with a modern graphics backend.

## Source Binary
- **Target**: `xwingalliance.exe` (2,554,896 bytes, compiled 1999-06-15)
- **Compiler**: Visual C++ 6.0 (Visual Studio 98)
- **Architecture**: x86-32, PE32, fixed base 0x00400000, no relocations
- **Code section**: .text at 0x00401000, 1,735,456 bytes (~1.7 MB)
- **Data section**: .data at 0x005AE000, 5,642,612 bytes (~5.4 MB)
- **SafeDisc**: .bind section present but neutered (Steam distribution)

## DirectX APIs Used
- DirectDraw (surface management, 2D)
- Direct3D Immediate Mode with execute buffers (DX5/6 era)
- DirectSound (audio)
- DirectInput (joystick/keyboard)
- DirectPlay (multiplayer via DPLAYX.dll)
- iMUSE (LucasArts interactive music engine, statically linked)
- SMUSH (FMV video via tgsmush.dll - 5 exports)

## Build Requirements
- CMake 3.20+
- Visual Studio 2022 (MSVC, x86 target)
- Python 3.10+ with capstone, pefile, lief

## Build Commands
```bash
cmake -B build -G "Visual Studio 17 2022" -A Win32
cmake --build build --config Release
```

## Code Generation
```bash
python -m tools.recomp "path/to/xwingalliance.exe" --all --split 1000
```
Generated code goes to `src/game/recomp/gen/` (gitignored).

## Architecture
- **tools/**: Python toolchain (PE analyzer, disassembler, lifter, translator)
- **src/game/**: Game entry point, recomp infrastructure, manual overrides
- **src/kernel/**: Win32 API bridges and compatibility
- **src/hal/**: Hardware abstraction (D3D11 rendering, audio, input)
- **config/**: Function tables, switch tables, manual annotations

## Key Patterns
- Global register model: g_eax, g_ecx, g_edx, g_ebx, g_esi, g_edi, g_esp (ebp is local)
- Memory access: MEM8/MEM16/MEM32/MEMF macros with base offset translation
- Indirect calls: RECOMP_ICALL dispatch with 3-tier lookup (manual, auto, API)
- Conditions: Pattern-matched from flag-setter to flag-consumer (CMP_EQ, TEST_Z, etc.)
- Stack: PUSH32/POP32 macros operating on simulated stack via g_esp
