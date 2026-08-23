#!/bin/sh
# Flight through the GAME'S OWN mission-load path -- barracks -> campaign -> loading -> flight,
# with none of the force-launch fabrication that tools/run_flight.sh relies on (no XWA_SKIRMISH,
# no XWA_ADDCRAFT/CRAFTSLOT, no XWA_MPATH; the engine picks and opens its own .tie).
#
# Usage:  tools/run_engine_flight.sh <logfile> [extra env assignments...]
#
# The knob set is three groups:
#   entry     XWA_BARRSEL=4 picks the campaign route off the barracks screen; XWA_NONAV skips nav.
#   session   XWA_DPSP + XWA_DPOBJ -- XWA runs single player through a local DirectPlay session,
#             and without these sub_0049AFC0 blocks world build for 60s waiting on a peer (#602).
#   guards    the player craft record is still unassigned (0xFFFF) when worldinit's first two
#             consumers read it; ROGUARD/NAMEGUARD/STRGUARD keep those reads off the cliff until
#             the loader at 0x0051066D assigns it for real.
#
# Flight entry is flaky (~1 in 3), so this retries until the render list is non-empty.
LOG="${1:-/tmp/engine_flight.log}"; shift
cd "$(dirname "$0")/../../Star Wars X-Wing Alliance" || exit 1
for i in 1 2 3 4 5 6; do
  rm -f rt_flight.bmp
  env "$@" \
    XWA_BARRSEL=4 XWA_NONAV=1 XWA_AUTOPILOT=1 XWA_PILOT=Test XWA_FLYDEMO=1 \
    XWA_DPSP=1 XWA_DPOBJ=1 \
    XWA_ROGUARD=1 XWA_NAMEGUARD=1 XWA_STRGUARD=1 \
    XWA_NATIVEDRAW=1 XWA_ALLOBJ=1 XWA_LOADALL=1 XWA_TBLGUARD=1 XWA_MKCTX=1 XWA_RENDERFN=1 \
    XWA_RUNSCENE=1 XWA_KEEP3D=1 XWA_3DFLAG=1 XWA_ZEROFILL=1 XWA_FGFILL=1 XWA_RTDUMP=1 \
    XWA_NOLST=1 XWA_NATIVESCANF=1 XWA_D3DCAPS=1 XWA_RENDERINIT=1 XWA_PUMPFIX=1 \
    XWA_WAITEXIT=1 XWA_WAITAFTER=150 \
    timeout 200 ../recomp/build/Release/xwa_recomp.exe \
      ../recomp/config/xwingalliance_decrypted.exe > "$LOG" 2>&1
  n=$(grep -ac NATIVEDRAW "$LOG")
  echo "try$i: NATIVEDRAW=$n  rt_flight.bmp=$([ -f rt_flight.bmp ] && echo yes || echo no)"
  [ "$n" != "0" ] && [ -f rt_flight.bmp ] && break
done
