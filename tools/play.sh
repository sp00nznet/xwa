#!/bin/sh
# Play the game interactively -- NO timeout, no scripted clicks. Use this instead of
# run_tests.sh / run_engine_flight.sh when a human is driving.
#
#   tools/play.sh                 # campaign, engine's own UI, native renderer on
#   tools/play.sh XWA_NODPSP=1    # add/override any knob
#
# Everything is logged to <game dir>/play.log, and a fault now writes xwa_crash.log /
# xwa_seh_crash.log NEXT TO THE GAME (the old hard-coded D:\recomp path died with the move
# to G:, which is why crashes left no trace at all).
cd "$(dirname "$0")/../../Star Wars X-Wing Alliance" || exit 1
EXE=../recomp/build/Release/xwa_recomp.exe
DEC=../recomp/config/xwingalliance_decrypted.exe
[ -f "$EXE" ] || { echo "no build -- cmake --build build --config Release"; exit 1; }
rm -f xwa_crash.log xwa_seh_crash.log
echo "logging to $(pwd)/play.log   (ctrl-C or quit in-game to stop)"
# The render stack is still opt-in: XWA_NATIVEDRAW is our own mesh renderer, which is what
# actually puts ships on screen. Drop it to exercise the engine's own path instead.
env XWA_NATIVEDRAW=1 XWA_ALLOBJ=1 XWA_LOADALL=1 XWA_D3DCAPS=1 XWA_RENDERINIT=1 XWA_PUMPFIX=1 \
    XWA_ROGUARD=1 XWA_NAMEGUARD=1 XWA_STRGUARD=1 XWA_TBLGUARD=1 \
    "$@" "$EXE" "$DEC" 2>&1 | tee play.log
echo
for f in xwa_crash.log xwa_seh_crash.log; do
  [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; }
done
