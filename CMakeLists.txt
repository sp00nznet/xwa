cmake_minimum_required(VERSION 3.20)
project(XWingAllianceRecomp VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)

# ============================================================
# Compiler / Linker Settings
# ============================================================

if(MSVC)
    # Disable ASLR - we need fixed address mapping
    add_link_options(/DYNAMICBASE:NO)

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
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /Oi /GL")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
endif()

# ============================================================
# Source Files
# ============================================================

# Runtime / manually written sources
set(RUNTIME_SOURCES
    src/game/main.c
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

target_include_directories(xwa_recomp PRIVATE
    src/game
    src/game/recomp
    src/game/recomp/gen
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

    # TODO: DirectX libraries for HAL
    # d3d11
    # dxgi
    # dxguid
    # xinput
    # xaudio2
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
