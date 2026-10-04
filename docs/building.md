# Building: the traps

Each of these cost at least one wrong diagnosis. The commands themselves are in the
[README](../README.md#building-from-source).

## Compiler out of heap

**`-T host=x64` is required, and so is `/MP` (set in CMakeLists.txt).** The generated tree is
~38 MB of C and `recomp_0000.c` alone is 12 MB. MSBuild hands *every* source file of a project
to a single `cl.exe`, so one compiler process accumulates all of them and dies partway through:

```
fatal error C1002: compiler is out of heap space in pass 2
```

It reports a **different line each run**, and the line it names is fine -- this is not a code
bug, and no amount of staring at that line will help. `/MP` gives each translation unit its own
process; `host=x64` gives each one more than the 32-bit compiler's ~3 GB. Both are needed:
`/MP` alone still fails on the 12 MB file, and `host=x64` alone still dies with all files in one
process. If a build has already failed this way, **reconfigure into a clean directory** -- a
half-populated one keeps failing.

Related trap: a failed compile **deletes its `.obj`**, but a *successful* link can still reuse a
stale one from an earlier build. That is how a `recomp_dispatch.c` that had been overwritten
with an unrelated file still produced a working exe for three days. If behaviour and source
disagree, check `build/xwa_recomp.dir/Release/*.obj` timestamps before believing either.

## `cmake --build` can exit 0 without relinking

Seen twice: after `apply_hooks` edited a generated file, the build rebuilt its `.obj` but left
`build/Release/xwa_recomp.exe` at the old timestamp, without the new code, and exited 0. A second
identical invocation linked it. Verify the exe, not the exit code: grep it for a string only the
new code contains (`grep -ac SOMEKNOB build/Release/xwa_recomp.exe`).

## A stuck process starves the machine

A hung run can survive `taskkill /F /IM xwa_recomp.exe`. While it lives, later runs exit cleanly
after ~680 log lines with `NtTerminateProcess status=0`, which looks exactly like a regression.
Check `ps -W | grep -ci xwa_recomp` first and kill by PID. `tools/run_tests.sh` does this.

## Never run the test suite while someone is playing

`tools/run_tests.sh` starts with `taskkill /F /IM xwa_recomp.exe`, and a test timeout killing the
window looks exactly like the game crashing on the next screen.

## Flaky tests: run three times before blaming a change

Test 2 (force-launch) and test 3 (`L_0048967D`) fail intermittently on unchanged builds. Two wrong
conclusions came from single runs.
