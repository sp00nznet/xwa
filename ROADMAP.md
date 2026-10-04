# Roadmap

## Next
- **Campaign hangar launch.** Find the code that draws and handles the campaign `= HANGAR MENU =`
  and drive Launch, so `1b0m1fw` starts in the hangar and undocks. See `docs/campaign.md`.
- **Player runtime flight group.** Its craft type is set in the loader and cleared during cockpit
  setup; find who frees it.
- **Lifter sync with pcrecomp.** XWA's `tools/lifter.py` is an older fork of pcrecomp's `lift32.py`
  and lacks a run of upstream correctness fixes (flags across blocks, carry, div/mul widths, x87
  compares). Port or migrate, then re-run the suite.

## Deferred
- One-click `Setup.cmd` quick start (house rule; needs the SafeDisc dump step automated first).
- Headless mode, `--headless --record out.mp4`.
- CI and a conformance harness with a tracked pass count. The suite needs the game data, so CI can
  only build; the harness runs locally or on netlab.
- netlab recipe (`projects/xwa.env`).
- Audio, cockpit view, the rest of the campaign.

## Out of scope
- Distributing any game data, the executable, or generated source.
- Multiplayer.
