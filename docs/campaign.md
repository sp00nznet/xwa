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
hangar models load and draw. The `= HANGAR MENU =` is up and **ENTER now selects Launch**
(2026-10-03): the hangar menu handler `sub_0045C680` takes its selection path.

## The hangar menu, mapped (2026-10-03)

- `sub_0045B0D0` (per-frame, from the flight loop) takes its `MEM16(0x9C6754) == 0x134` branch at
  0x0045C18B: hangar scene `sub_0045D910`, menu draw `sub_00460490`, then the menu input handler
  **`sub_0045C680`** at 0x0045C1C8. The `0x8053E5` gate earlier in the function is a different
  (mode-1) branch, correctly skipped in campaign mode.
- `sub_00460CB0(menu)` builds a menu; title pointers are a table at `0x9C6F80..0x9C6F9C`
  (`0x9C6F88` = `= HANGAR MENU =`). Found with `XWA_MEMFIND`.
- Keys come from the game's own kbhit/getch, `sub_0050B680` / `sub_0050B6F0`, which with
  `0x5FFDAC` set read the DirectInput keyboard's **buffered** data: kbhit with `DIGDD_PEEK`, getch
  without. Scancodes map to chars through the table at `0x5B2730` (0x1C -> 0x0D). The handler
  dispatches on 0x0D (select) and 0x1B (escape).
- **The bug that blocked it was ours:** the DirectInput mock ignored `DIGDD_PEEK`, so kbhit
  consumed the press and getch returned 0. And real keys never reached the buffered path at all,
  so a person could not use the menu either. `src/game/com_mocks.c` `didev_GetDeviceData` now keeps
  a queue that PEEK leaves in place, fed by real key edges (window focused) and `XWA_SENDKEY`.

## Open problem: the crash after Launch

After Launch the run continues on a new path (`sub_004EFE00`) and faults in the render-batch flush,
`sub_00448530 -> sub_004483C0 -> sub_00595191`. It is the same code as the long-standing
`L_0048967D` flake (which hits roughly 1 run in 2-3 before Launch too):

    READ addr=0x00004E03 -> guest function sub_004483C0

Three batch lists hang off `0x686B0C/10/14`; nodes are 0x4E0C bytes from a free-list pool
(`sub_004CC7E0` alloc, `sub_004CC8A0` free, `sub_004CC130` teardown): vertices at +0 (32 bytes
each), count at +0x3000, index data from +0x3004, its count at +0x4E04, next at +0x4E08. A head or
next pointer of -1 / garbage is what faults. Ruled out so far: the vertex capacity check (clamped to
256 of the 384 that fit). Not yet checked: the index-data writer's bound, and teardown
(`sub_004CC130`) running without the head reset (`sub_0044FCA0`).

Older open items: `sub_004F9320`'s nested screen loop; the player's runtime FG `+2` cleared during
cockpit setup.
