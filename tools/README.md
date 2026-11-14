# tools

`hookbake.c` / `hookbake.cmd`, `hook_jumps.txt`, `hook_codewrites.txt`: the
X-Wing Alliance Upgrade build, see [docs/xwau.md](../docs/xwau.md).

`mission1.keys` flies campaign mission 1 (Aeron's Lesson) from the intro to
victory: pickup, hyperspace, delivery, the Viraxo, the fuel cells, home.

    build\xwarecomp.exe --run --keys "<contents of mission1.keys>"

Key script steps (host.c), besides keys, clicks and `stick:X:Y`:

| step | does |
|---|---|
| `on:a\|b` | wait until the game opens a file matching a or b; times count from there |
| `near:N` | wait until the target is within N game units (1 km is about 40000) |
| `T:shift+p` | a key with left shift held |
| `T:target:MODEL` | target the nearest object of that model |
| `T:aim` / `T:aimfire` / `T:noaim` | the autopilot steers at the target (and fires when lined up) |
| `T:peek:EXPR:LEN` | hex-dump guest memory; `7B33C4@+23@` follows pointers |

The autopilot (flight.c `flight_aim`) is game-neutral: a title supplies one
function giving its target's right/up/forward from the ship. XWA's is
`xwa_target` in host.c, from the object table at [0x7B33C4] and the player
table at 0x8B94E0.
