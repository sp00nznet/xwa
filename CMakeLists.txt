# =============================================================================
# X-Wing Alliance - static recompilation host (32-bit, MSVC x86)
#
#   py -3 run_lift.py --all  # -> src/recomp/gen/  (needs work/functions.json)
#   build.cmd                # vcvarsall x86 + CMake + Ninja -> build/xwingrecomp.exe
#   build\xwingrecomp.exe --run --headless --watchdog 60
# =============================================================================
cmake_minimum_required(VERSION 3.20)
project(xwa C)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "the host must be 32-bit: use build.cmd (vcvarsall x86)")
endif()
if(NOT MSVC)
  message(FATAL_ERROR "runtime/native32 is MSVC x86 inline assembly")
endif()
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
# The C runtime linked in: a test VM has no 32-bit VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(PCRECOMP "${CMAKE_SOURCE_DIR}/../pcrecomp" CACHE PATH "pcrecomp checkout")
function(game_host T GEN OUT)
  file(GLOB SRC CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/${GEN}/*.c")
  add_executable(${T}
    src/runtime/host.c
    src/runtime/softdd.c
    src/runtime/gpu.c
    src/runtime/d3d.c
    src/runtime/settings.c
    src/runtime/flight.c
    src/runtime/sound.c
    src/runtime/dplay.c
    src/runtime/music.c
    ${PCRECOMP}/runtime/native32/native32.c
    ${PCRECOMP}/runtime/recomp32/image_loader.c
    ${PCRECOMP}/runtime/recomp32/recomp_trace.c
    ${SRC}
  )
  target_include_directories(${T} PRIVATE
    src/runtime ${GEN} ${PCRECOMP}/runtime/native32 ${PCRECOMP}/runtime/recomp32)
  target_compile_definitions(${T} PRIVATE RECOMP_RETADDR=0u _CRT_SECURE_NO_WARNINGS
                                              RECOMP_FLAT_MEMORY RECOMP_LOCAL_REGS)
  # Linked high and not relocatable, so the guest's 0x00400000..0x009D5000 is free.
  target_link_options(${T} PRIVATE /BASE:0x60000000 /FIXED:NO /DYNAMICBASE:NO
                                         /NXCOMPAT /LARGEADDRESSAWARE /STACK:0x1000000
                                         /MANIFESTUAC:NO /MANIFEST:NO /MAP)
  set(GEN_OPT "/O2" CACHE STRING "optimisation for the generated C")
  set_source_files_properties(${SRC} PROPERTIES COMPILE_OPTIONS "/w;${GEN_OPT}")
  set_source_files_properties(src/runtime/host.c PROPERTIES COMPILE_OPTIONS "/W3")
  target_link_libraries(${T} PRIVATE user32 gdi32 kernel32 ole32 uuid dxguid winmm ws2_32 dinput8 dsound shlwapi d3d11 dxgi windowscodecs xinput)

  set_target_properties(${T} PROPERTIES OUTPUT_NAME ${OUT})
  if(TF_TRACE)
    target_compile_definitions(${T} PRIVATE RECOMP_TRACE=1)
  endif()
endfunction()

option(TF_TRACE "record a ring buffer of lifted function entries" OFF)
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/src/recomp/gen")
  message(FATAL_ERROR "src/recomp/gen is empty -- run `py -3 run_lift.py --all` first")
endif()
# The output names keep Windows' compatibility database off the host.
game_host(xwa src/recomp/gen xwarecomp)
