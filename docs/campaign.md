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

## Where the mission stands (2026-10-04)

Launch works: the player exits the family hangar into space in the YT-1300 cockpit. The
`XWA_AUTOPLAY=1` test harness then plays the mission with the game's own mechanics (target, park
in range, issue the game's pickup / dock commands, follow the in-flight message ids through the
`msg-tap` hook), with the mission clock running:

1. **C/C Xi 1 is picked up and secured** (0x14E -> 0x12B -> 0x156). A pickup completes when the
   collision pass (`sub_00408DC0`) sees the craft touch the container and attaches it.
2. **Selu flies to Xi 2 and picks it up**; the hyper buoy to Harlequin Station activates (0x163).
3. **Hyperspace works**: Space at the buoy (0x79 -> 0x71) moves the player to region 1.
4. **Delivery at Harlequin Station works** (0x15C -> 0x162).
5. **The trip home works.** The "Return Home" buoy (FG24) arrives on FG15 (cargo "Fuel Cells")
   AND FG17's special craft (special cargo "Coolant", Aeron's job) picked up -- arrival triggers
   are 6-byte records at FG+0x88 (cond 6 = picked up, var type 1 = FG, amount 6 = special craft).
   The harness picks up and releases the coolant itself, then the fuel cells; the buoy arrives,
   the jump home works and the fuel cells are delivered (0x162).
6. **Landing works**: tractor prompt (0x117), Space, hangar state 6. The hangar is the family
   station's own (map 0xB3 = model 179, the Azzameen base). The hangar menu is "= MISSION
   COMPLETED =" (item 0 "Go to Debriefing") only when `MEM8(0x807A60 + team*3)` is set (team =
   player record +0x8B94EC; +1 is "failed"); otherwise ENTER relaunches.
7. **Mission complete**: the coolant (Aeron's job) delivered on a second trip completes it
   (MSG 0x102); the hangar menu offers "Go to Debriefing".
8. **Debriefing** (0x57ECE0, a sprite room like the barracks): its init call (arg 0) scores the
   mission (`sub_00582ED0` -> `9EAA04` = 1 won). `XWA_DEBRSEL` (default 1 under autoplay) picks
   "accept" -> concourse.
9. **The campaign advances**: the flight exit's results pass `sub_0042E750` records the mission
   (played/won at `0xAED75E + id*0x30`, +0x10 = won) -- only for a player slot with a DirectPlay
   id, which `xwa_sp_dpid` supplies around that call. The concourse's mission select
   (`sub_0053AA90`) then picks the first unwon list entry: `ABC970` = 1.
10. **The family room** shows the mission-1 award ("Key to Harlequin Station",
    `frontres/medals/familyawards.txt`) and plays `N01MC06.wav`. After a flight the room's
    background is not drawn (front-end rendering), only its sprites.
11. **Mission 2 loads**: briefing reads `1b0m2fw.tie` and `B0M2\N000201.wav`, then loadprep ->
    LOADING -> FLIGHT-INIT with `session='~missions\1b0m2fw.tie'`, the .tie parses.

What it took past the landing (2026-10-05), in order of discovery:
- 31 AI order handlers (`0x5B6F08[cmd]`) and three pointer-only functions (a qsort comparator, the
  debriefing's frame partner 0x57EC50, a CRT helper) were never in functions.json; each dispatch
  to them leaked 4 bytes of guest stack. Lifted with `relift_func.py --new` (repair_gen `ADD`).
- A gen flight hack forced the screen tick to 1 after the flight screen had pushed the
  debriefing, so the debriefing never ran its init (no score). Now only while flight is current.
- Transition frame-partner callbacks (0x539760, 0x55FE90, 0x57EC50) return 4 bytes high; each one
  shifted the main loop's frame until its last-frame tick read 0x10000000 > GetTickCount and it
  never dispatched again (mission 2's briefing froze). The dispatcher restores esp (repair_gen).
- The hangar's player slot is re-found by DirectPlay id after the results pass, so the id is
  given only for that call; a stale one moved the player to an empty slot (hangar crash).
- Texture surfaces are never freed (the game keeps using released buffers); small ones now get
  4 KB guards instead of 128 KB, or the second mission load ran out of heap.

Selu never leaves region 0. After securing Xi 2 its pickup order (FG orders dumped from
`0x80DC80 + fg*0xE42`, records 0x94 bytes from FG+0xCA, 4 per region: region 0 `0x11` pick up FG2
else FG1, `0x32` hyper to region 1, ...) falls back to FG1 and goes after Xi 1, which the player
carries; the order never completes, so `0x32` never runs. The cargo-attach routine
(`sub_004B65E0`) records the carrier at craft +0x185 and clears the carrier's order cmd; what
should stop Selu targeting a carried canister is still open.

How the AI runs, for the next look: `sub_004A1D80` gates each craft on a countdown (order
block +0x32 minus elapsed, reloaded from +0x2E); `sub_004A22C0` interprets a byte-code script
(`0x7CA1D0`, base `0x9109E0[order+0x2A]`, first byte = the runtime command at order+0x5C); each op
is `op, next-script` and calls `0x5B76B8[op]`, switching scripts when the handler returns true.
Op 1 dispatches the order itself through `0x5B6F08[cmd]` (0x12 = `sub_004B0770`, pickup).

Mission flow, from the .tie text: pick up Xi 1 (Shift-P) -> target nav buoy, within 0.5 km, Space
-> at Harlequin Station dock within 1 km (Shift-D, `sub_00506CB0`) -> pick up fuel cells -> hyper
home -> deliver to the Azzameen base -> land.

## Fixed on the way (2026-10-04)

- Selu never moved: the pickup order handler `sub_004B0770` reached its local switch
  (`jmp [eax*4+0x4B2350]`) lifted as an indirect tail call, which dispatches nowhere. Re-lifted;
  `tools/fix_jmptbl.py` now also reads decimal bounds (`CMP_A(eax, 3)`), a bound tested on a copied
  register, and a `ja` lifted as a tail call.
- False collisions lost the mission at launch: the collision test `sub_0040C960` was cut at a bogus
  function start (0x0040C9C8) and returned garbage, and the collision pass itself was split in two
  at 0x0040A15D, each half tail-jumping into the other. Both are re-lifted whole. Every `RELIFT`
  range was then re-measured with `tools/func_extent.py` (walks the control flow, switch tables
  included), which also caught AI script ops missing their epilogue (`sub_004B8F70`, `sub_004B9220`).
- Intermittent ntdll heap crashes (0xC0000374, `L_0048967D`, roughly every second run): the
  gen-only `XWA_FGFILL` pass gave objects without a render object `pool + i*0xE5`, which runs past
  the pool's allocation (in one run straight into the object table at entry ~1010); the game then
  writes ro fields into whatever lives there. Slots past the pool now get their own zeroed record
  (`xwa_ro_slot`, bounded by `xwa_guest_block_size`), recorded as a `REPLACE` in
  `tools/repair_gen.py`. Also: `XWA_NOFREE=1` (on in `tools/netlab_run.cmd`) leaks guest blocks,
  keeps realloc'd ones and pads 256 bytes in front, since the game also reads freed blocks and
  bytes before a block (page heap catches both); the HeapSize bridge used the process heap for
  guest-heap blocks; surface buffers have a front guard (`XWA_HEAPWATCH=1` checks both heaps and
  the guards every tick).
- Docking at Harlequin Station: "No delivery locations" (0x15D) is the dock command's mesh ray
  test (`sub_004DE9B0`) finding every docking point behind the hull from where the player was
  parked; approaching from another side gets "Object delivered" (0x162).
- Join point at 0x004A393F (AI target filter `sub_004A36B0`) evaluated the wrong setter, like
  0x0044309B; fixed by hand (the audit counts ~59 of these).
- d3d11: the window-sized staging texture was updated from smaller surfaces with a NULL box, an
  over-read of the converted pixel buffer.
- The mission clock (0x8053FA) was frozen until `tools/fix_narrowcmp.py` (signed compares on 8/16-bit
  operands); with it running, the exterior hangar map (0xB3) is what the game picks -- the interior
  map seen before was the missing carry in `neg al; sbb eax,eax`.

- `XWA_RENDERFN` wrote 1 into 0x7828D0 (the ALERTBOXBUFFER pointer, not a flag) -> free(1) ->
  heap corruption: the long-standing "L_0048967D flake" and the contained exception at ~930K calls
  in every run. `XWA_MKCTX`, `XWA_RENDERFN` and `XWA_RUNSCENE` are no longer needed and are out
  of `tools/netlab_run.cmd`. `XWA_KEEP3D`/`XWA_3DFLAG` are still needed: without them the engine
  takes the software rasterizer, which patches its own code (`MEM8(eax + 0x12345678)`).
- Native fgetc/fread for host streams (`tools/hooks/native-fgetc.hook`, `native-fread.hook`), with
  the MSVC6 `_IOEOF` bit (0x10 at +0xC) mirrored for game code that tests it directly -- UCRT's
  EOF bit is 0x08 and 0x10 is `_IOERROR` there.
- Lifter: carry flag publishing (`tools/fix_carry.py`, 1264 sites) and conditions after shifts
  (`tools/fix_shiftflags.py`, 38 sites: `sar ebp,8; je` let sub_0040BD20 divide by zero).

## Older: the batch-list crash after Launch (fixed)


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
