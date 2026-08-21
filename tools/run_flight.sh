#!/bin/sh
# Flight run harness -- the verified knob set that reaches flight with geometry (#580).
# Usage:  tools/run_flight.sh <logfile> [extra env assignments...]
#   e.g.  tools/run_flight.sh /tmp/a.log XWA_MESHSCAN=1
# Flight entry is flaky (~1 in 2), so this retries until [NATIVEDRAW] appears (max 4 tries).
LOG="${1:-/tmp/flight.log}"; shift
cd "$(dirname "$0")/../../Star Wars X-Wing Alliance" || exit 1
for i in 1 2 3 4 5 6 7 8; do
  rm -f rt_flight.bmp
  env "$@" \
    XWA_NATIVEDRAW=1 XWA_TBLGUARD=1 XWA_MKCTX=1 XWA_RENDERFN=1 XWA_RUNSCENE=1 \
    XWA_KEEP3D=1 XWA_3DFLAG=1 XWA_AUTOPILOT=1 XWA_PILOT=Test XWA_FLYDEMO=1 XWA_SKIRMISH=1 \
    XWA_NOLST=1 XWA_NATIVESCANF=1 XWA_D3DCAPS=1 XWA_RENDERINIT=1 XWA_PUMPFIX=1 \
    XWA_ADDCRAFT=1 XWA_CRAFTSLOT=1 XWA_NOPHASE=1 XWA_PUSHLOAD=1 XWA_SETUPCALL=1 \
    XWA_ZEROFILL=1 XWA_DPOBJ=1 XWA_DPLOOP=1 XWA_DPHOST=1 XWA_MPATH2=1 XWA_FGFILL=1 \
    XWA_ROGUARD=1 XWA_PCGUARD=1 XWA_STRGUARD=1 XWA_SETSLOT=0 XWA_ACTIVATE=1 \
    XWA_WAITEXIT=1 XWA_WAITAFTER=150 XWA_MPATH='missions\1B0M1FW.TIE' \
    timeout 110 ../recomp/build/Release/xwa_recomp.exe \
      ../recomp/config/xwingalliance_decrypted.exe > "$LOG" 2>&1
  n=$(grep -ac NATIVEDRAW "$LOG")
  echo "try$i: NATIVEDRAW=$n  rt_flight.bmp=$([ -f rt_flight.bmp ] && echo yes || echo no)"
  [ "$n" != "0" ] && [ -f rt_flight.bmp ] && break
done
