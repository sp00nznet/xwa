cmake_minimum_required(VERSION 3.20)
project(XWingAllianceRecomp VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)

# ============================================================
# Compiler / Linker Settings
# ============================================================

if(MSVC)
    # Disable ASLR - we need fixed address mapping
    add_link_options(/DYNAMICBASE:NO)

    # Move our image base to 0x10000000 so the original game's address
    # space (0x00300000-0x00B10000) is free for VirtualAlloc mapping
    add_link_options(/BASE:0x10000000)

    # Large native stack (recompiled code creates deep call chains)
    add_link_options(/STACK:8388608)  # 8 MB

    # Suppress warnings in generated code
    add_compile_options(/W1)
    add_compile_options(/wd4996)  # deprecated functions
    add_compile_options(/wd4244)  # conversion warnings
    add_compile_options(/wd4146)  # unary minus on unsigned
    add_compile_options(/wd4102)  # unreferenced label
    add_compile_options(/wd4013)  # undefined function (forward refs)
    add_compile_options(/wd4101)  # unreferenced local variable
    add_compile_options(/wd4267)  # size_t to int
    add_compile_options(/wd4018)  # signed/unsigned mismatch

    # Optimization for Release
    # NOTE: /GL (whole program optimization) disabled - it causes MSVC to misoptimize
    # cross-function global register variable accesses in the recompiled code.
    # /Zi + /DEBUG: keep a PDB for Release. The crash handler uses it to name the exact
    # generated-C line for a faulting host address, and every generated line carries the
    # guest instruction in a comment -- so a crash points straight at the guest opcode.
    # Does not change codegen (/Zi is debug info only) and costs nothing at runtime.
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /Oi /Zi")

    # /MP: compile each translation unit in its own cl.exe process.
    # MSBuild hands EVERY source file of a project to ONE cl.exe invocation, so a single
    # compiler process accumulates state across all of them -- and the generated tree is
    # ~38 MB of C (recomp_0000.c alone is 12 MB). That process runs out of heap partway
    # through, reported as "fatal error C1002: compiler is out of heap space in pass 2" at
    # a DIFFERENT line each run, which reads like a code bug and is not one. It also is not
    # fixed by the x64-hosted toolset: the machine had 80 GB free when this first bit.
    # /FS serializes PDB writes, which /Zi needs once several processes are compiling at once.
    add_compile_options(/MP /FS)
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /DEBUG /OPT:REF /OPT:ICF")
    #set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
endif()

# ============================================================
# Source Files
# ============================================================

# Runtime / manually written sources
set(RUNTIME_SOURCES
    src/game/main.c
    src/game/imports.c
    src/game/com_mocks.c
    src/hal/d3d11_renderer.c
)

# Generated recompiled code (if present)
file(GLOB GENERATED_SOURCES "src/game/recomp/gen/recomp_*.c")

# Only include generated dispatch if it exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/game/recomp/gen/recomp_dispatch.c")
    list(APPEND GENERATED_SOURCES
        "src/game/recomp/gen/recomp_dispatch.c"
    )
endif()

# ============================================================
# Executable Target
# ============================================================

add_executable(xwa_recomp
    ${RUNTIME_SOURCES}
    ${GENERATED_SOURCES}
)

# Static CRT: the netlab test VMs have no VC++ redistributable, and a missing DLL exits
# 0xC0000135 before a single test runs.
set_property(TARGET xwa_recomp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# GEN_OPT: optimisation for the generated C only. clang-cl's /O2 loop unswitching is quadratic on
# the lift's huge functions (kotor, Rise of Legends); the netlab recipe passes /O1.
set(GEN_OPT "" CACHE STRING "extra optimisation flag for the generated C, e.g. /O1")
if(GEN_OPT)
    set_source_files_properties(${GENERATED_SOURCES} PROPERTIES COMPILE_OPTIONS "${GEN_OPT}")
endif()

target_include_directories(xwa_recomp PRIVATE
    src/game
    src/game/recomp
    src/game/recomp/gen
    src/hal
)

# ============================================================
# Libraries
# ============================================================

target_link_libraries(xwa_recomp PRIVATE
    # Windows system libraries
    kernel32
    user32
    gdi32
    advapi32
    shell32
    ole32
    winmm
    dbghelp
    psapi

    # DirectX libraries for HAL
    d3d11
    dxgi
    dxguid
    d3dcompiler
)

# ============================================================
# 32-bit target check
# ============================================================

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(WARNING "Building as 64-bit! XWA recomp should be built as 32-bit (-A Win32).")
    message(WARNING "Use: cmake -B build -G \"Visual Studio 17 2022\" -A Win32")
endif()

# ============================================================
# Custom target for code generation
# ============================================================

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_custom_target(codegen
        COMMAND ${Python3_EXECUTABLE} -m tools --all
            "$ENV{XWA_EXE_PATH}"
            -o "${CMAKE_CURRENT_SOURCE_DIR}/src/game/recomp/gen"
            --split 1000
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating recompiled code from xwingalliance.exe"
    )
endif()
