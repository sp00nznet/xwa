# Single-player campaign bring-up

What it takes to get the first campaign mission, `missions/1b0m1fw.tie` (Azzameen family station,
battle 1 mission 1), from the concourse into flight. Retail flow: concourse droid -> mission offer ->
briefing -> family hangar -> launch -> fly.

## How to reach it

`tools/run_engine_flight.sh` (or `tools/run_tests.sh 3 5 7`) goes barracks -> LOADING -> FLIGHT-INIT,
and the engine opens `1b0m1fw.tie` itself. `XWA_BARRSEL=4` picks the campaign route off the barracks
screen, skipping the concourse droid. `tools/play.sh` is the same route for a human.

## What this port has to supply

Retail fills a lot of state in on the concourse and in the multiplayer setup screens. Entering a
mission straight off the barracks skips all of it, so each missing piece is supplied by a hook in
`tools/hooks/`, applied only when the field is still at its untouched default (a real concourse run
is left alone), and each has an off switch:

| Hook | Supplies | Off switch |
|---|---|---|
| `dpsp-host-path` | DirectPlay host-with-one-player. Without it `sub_0049AFC0` takes the peer path, waits 60 s for a handshake, and world build aborts to the debrief. | `XWA_NODPSP` |
| `roster-seed` | The player's roster entry. Without it the roster scan at 0x004319C7 falls to its not-found branch and hands `sub_00433760` a stack address as a model index. | `XWA_NOROSTER` |
| `player-fg-craft` | Copies the mission flight group's craft into the roster entry, so world build's copy back (0x00415F20) is an identity. Without it the player's FG becomes craft 0, the X-wing. | `XWA_NOFGCRAFT` |
| `player-craft-type` | Player record craft type from the mission FG, via the species -> engine-type table at `0x5B0F70`. | `XWA_NOPCTYPE` |
| `seat-player` | `rec+0x15` non-zero, which the craft loader `sub_00457C20` requires before it builds the player craft (`sub_0041EF60`). | `XWA_NOSEAT` |

Five null guards (`XWA_NOGUARD` disables) route NULL slots to the engine's own "not present" path.

## Two craft numbering systems

Mixing these up produced several wrong conclusions.

- **Species**: the number in the `.tie` and in `SHIPLIST.TXT` (1-based). Mission FGs at `0x80DC80`,
  stride `0xE42`, species at `+0x6B`.
- **Engine type**: what runtime code is keyed on. Runtime FGs at `MEM32(0x7B33C4)`, stride `0x27`:
  `+0` object index, `+2` engine type.
- Converter: `MEM16(0x5B0F70 + species*2)`. Species 38 (Corellian Transport) -> type 58.

## Where it stands

Flies `1b0m1fw` as the YT-1300 with the game's own HUD and objectives; the station, canisters and
hangar models load and draw. The `= HANGAR MENU =` is up (Launch, Return to Concourse, ...) and
synthetic keys reach it (`XWA_KEYINFLIGHT=1 XWA_SENDKEY=0x1C XWA_KEYAFTER=2 XWA_KEYEVERY=8`), but
nothing launches.

## Open problem: the hangar

- `sub_0045B0D0`'s state machine (`MEM32(0x68BBA0)`) is gated by `MEM8(0x8053E5) = (MEM32(0xAE2A8A) == 1)`.
  `0xAE2A8A` is the flight mode and the campaign runs in mode 4, so that branch is **not** the
  campaign hangar. Forcing it (`XWA_HANGARON`) crashes.
- Worldinit only calls `sub_00457C20(0xFFFF)`, so the loader's mothership/hangar branch at
  0x00457F36 never runs. The real caller is `sub_004FBA80` (0x004FE459), reached from
  `sub_004F9320`, which enters a nested screen loop.
- The player's runtime FG `+2` is 58 inside the loader and 0 by the first frame: something in
  cockpit setup after 0x004581C4 frees the slot.

Next: find the code that draws `!HANGAR_MENU_CRAFT_MENU!` (STRINGS.TXT) and work back to its input
handler.
