#!/bin/sh
# Regression suite for the recompiled game.
#
# These are the checks that were being re-typed by hand after every change. They are cheap, they
# catch the things that actually broke in practice, and each one states what it expects.
#
#   1. default build      -- no env knobs at all: must not fault, must render the concourse, and must
#                            not leak output from any env-gated probe (a knob left on by accident).
#   2. flight (hacks)      -- the force-launch config still reaches flight and draws craft.
#   3. flight (engine path) -- the game's own barracks -> loading -> flight-init route still works.
#   4. DirectPlay session   -- XWA_DPSP takes the host path so world-build is not blocked for 60s.
#   5. engine path + render -- the game's own mission reaches flight and submits its own geometry.
#   6. hooks                -- every tools/hooks/*.hook still anchors to real generated code.
#
# Usage:  tools/run_tests.sh [1|2|3 ...]      (default: all)
#
# Note: a run that times out leaves xwa_recomp.exe alive, the next link fails with LNK1104, and the
# STALE binary then "fails" a test. The suite kills leftovers before starting for that reason.

cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
GAME="$ROOT/../Star Wars X-Wing Alliance"
EXE="$ROOT/build/Release/xwa_recomp.exe"
DEC="$ROOT/config/xwingalliance_decrypted.exe"
LOGS="${TMPDIR:-/tmp}"
WANT="${*:-1 2 3 4 5 6}"
pass=0; fail=0

taskkill //F //IM xwa_recomp.exe >/dev/null 2>&1
[ -f "$EXE" ] || { echo "no build at $EXE -- run cmake --build build --config Release"; exit 1; }

ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }

# ---- 1. default build: clean, renders, and no knob output leaks --------------------------------
case " $WANT " in *" 1 "*)
  echo "[1] default build (no knobs)"
  for i in 1 2; do
    ( cd "$GAME" && timeout 80 "$EXE" "$DEC" > "$LOGS/t1_$i.log" 2>&1 )
    av=$(grep -ac 'exception 0xC0000005' "$LOGS/t1_$i.log")
    con=$(grep -aic concourse "$LOGS/t1_$i.log")
    leak=$(grep -acE '\[(NATIVEDRAW|NOBJ|LOADALL|ALLOBJ|SIMDRIVE|PARTFIX|ARRIVEPUMP|BARRSEL|UICLICK|UIDRAG|UISURF|SWEEP|WINKEY|DPOBJ|DPSESS)\]' "$LOGS/t1_$i.log")
    [ "$av"  = "0" ] && ok "run$i: no access violations" || bad "run$i: $av access violations"
    [ "$con" -ge 1 ] 2>/dev/null && ok "run$i: concourse renders" || bad "run$i: concourse never rendered"
    [ "$leak" = "0" ] && ok "run$i: no knob output leaked" || bad "run$i: $leak lines leaked from env-gated probes"
  done
esac

# ---- 2. flight through the force-launch config --------------------------------------------------
case " $WANT " in *" 2 "*)
  echo "[2] flight, force-launch config"
  sh "$ROOT/tools/run_flight.sh" "$LOGS/t2.log" XWA_RTDUMP=1 XWA_NLOOKAT=1 XWA_NZOOM=6 >/dev/null 2>&1
  nd=$(grep -ac NATIVEDRAW "$LOGS/t2.log")
  [ "$nd" -gt 0 ] 2>/dev/null && ok "native geometry submitted ($nd)" || bad "no geometry submitted"
  [ -f "$GAME/rt_flight.bmp" ] && ok "frame captured" || bad "no frame captured"
esac

# ---- 3. flight through the engine's own mission-load path ---------------------------------------
case " $WANT " in *" 3 "*)
  echo "[3] engine's own mission-load path"
  ( cd "$GAME" && XWA_AUTOPILOT=1 XWA_PILOT=Test XWA_FLYDEMO=1 XWA_NONAV=1 XWA_BARRSEL=4 \
      XWA_NOLST=1 XWA_NATIVESCANF=1 XWA_D3DCAPS=1 XWA_PUMPFIX=1 XWA_RENDERINIT=1 \
      XWA_WAITEXIT=1 XWA_WAITAFTER=120 timeout 100 "$EXE" "$DEC" > "$LOGS/t3.log" 2>&1 )
  grep -aq 'LOADING'    "$LOGS/t3.log" && ok "reaches the loading screen"   || bad "never reached loading"
  grep -aq 'FLIGHT-INIT' "$LOGS/t3.log" && ok "reaches flight init"          || bad "never reached flight init"
  grep -aq '1b0m1fw.tie' "$LOGS/t3.log" && ok "engine picked its own mission" || bad "no mission opened"
  cr=$(grep -ac 'SEH CRASH' "$LOGS/t3.log")
  [ "$cr" = "0" ] && ok "no crash" || bad "$cr crash(es)"
esac

# ---- 4. the DirectPlay session create takes the single-player host path ------------------------
# XWA runs even single player through a local DirectPlay session ("~missions/<file>.tie" is the
# session name). sub_0049AFC0 picks its mode from two decimal strings in the launch-parameter block;
# without the multiplayer setup screens both are still "0", which selects the peer path -- and that
# then blocks world-build for a full 60s waiting on handshake messages no peer will ever send.
case " $WANT " in *" 4 "*)
  echo "[4] DirectPlay session create (XWA_DPSP)"
  ( cd "$GAME" && XWA_DPSP=1 XWA_DPSESS=1 XWA_AUTOPILOT=1 XWA_PILOT=Test XWA_FLYDEMO=1 XWA_NONAV=1       XWA_BARRSEL=4 XWA_NOLST=1 XWA_NATIVESCANF=1 XWA_D3DCAPS=1 XWA_PUMPFIX=1 XWA_RENDERINIT=1       XWA_WAITEXIT=1 XWA_WAITAFTER=120 timeout 150 "$EXE" "$DEC" > "$LOGS/t4.log" 2>&1 )
  grep -aq 'sub_0049AFC0 returned 1' "$LOGS/t4.log" && ok "session create succeeds"       || bad "session create still fails (peer wait / timeout)"
  grep -aq '49B0BC' "$LOGS/t4.log" && ok "took the host path, no 60s peer wait"       || bad "did not take the host path"
  grep -aq 'WORLDBUILD] CALLED' "$LOGS/t4.log" && ok "world build runs past the session gate"       || bad "world build never ran"
esac

# ---- 5. the engine's own mission all the way to submitted geometry ------------------------------
# Same route as [3], but carried through world build into flight with the renderer on. This is the
# one that exercises real mission content: the .tie's own flight groups, not fabricated craft.
case " $WANT " in *" 5 "*)
  echo "[5] engine's own mission -> flight with geometry"
  sh "$ROOT/tools/run_engine_flight.sh" "$LOGS/t5.log" XWA_MILE=1 >/dev/null 2>&1
  nd=$(grep -ac NATIVEDRAW "$LOGS/t5.log")
  [ "$nd" -gt 0 ] 2>/dev/null && ok "mission geometry submitted ($nd frames)" || bad "no geometry submitted"
  grep -aq '0x51066D loader' "$LOGS/t5.log" && ok "world build reaches the loader at 0x51066D"       || bad "world build stopped before the loader"
  m=$(grep -ac 'meshes=' "$LOGS/t5.log")
  [ "$m" -gt 0 ] 2>/dev/null && ok "render list is non-empty" || bad "render list empty"
  # The captured frame must contain the native geometry, not just the cleared target with the 2D
  # HUD text on it -- that is what "no visible frame" looked like for a long time.
  grep -a 'RTDUMP] capturing' "$LOGS/t5.log" | grep -qv 'native_keep=0' \
      && ok "captured frame carries native geometry" || bad "captured frame has no native geometry"
esac

# ---- 6. the generated-code hooks still anchor ---------------------------------------------------
# src/game/recomp/gen/ is gitignored and regenerated from the PE, so the hooks live in
# tools/hooks/*.hook and are re-applied by tools/apply_hooks.py. They anchor to a line of generated
# code; if the generator's output shifts, the anchor stops matching and the hook silently would not
# come back. Fail loudly here instead.
case " $WANT " in *" 6 "*)
  echo "[6] generated-code hooks"
  out=$(python -m tools.apply_hooks --check 2>&1)
  echo "$out" | grep -qE 'ANCHOR|MISSING FILE' \
      && bad "a hook anchor no longer matches -- re-derive it" \
      || ok "all hook anchors resolve"
  n=$(ls tools/hooks/*.hook 2>/dev/null | wc -l)
  [ "$n" -gt 0 ] 2>/dev/null && ok "$n hook(s) present" || bad "no hooks found"
esac

echo
echo "== $pass passed, $fail failed =="
[ "$fail" = "0" ] || exit 1
