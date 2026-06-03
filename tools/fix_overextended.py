"""
Fix over-extended functions: functions.json records some function sizes that run
PAST the real function end (into jump-table data / padding), so the linear-sweep
lifter decodes that data as garbage instructions (bogus `out`/`ljmp`/`retf`/wild
`jmp 0x........`), which corrupts control flow and prevents switch reconstruction.

config/ghidra_func_bounds.csv holds Ghidra's accurate (start,end) for every
function. This script finds entries where functions.json over-extends past the
Ghidra end by >= THRESHOLD bytes and re-lifts each with the correct end via
tools/relift_func.py (which now supports the 0xADDR:0xEND syntax). It SKIPS the
manual-fix functions (native CRT replacements, the printf epilogue-bail, etc.),
which must never be re-lifted.

Run after any full regen to re-apply the bounds fix. Found 181 functions / 223
reconstructed switches on the first pass (2026-06-02); boot + concourse stayed
stable and the flight path advanced to the in-flight tick.

Usage: py -3.11 tools/fix_overextended.py [--dry-run]
"""
import json, os, sys, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOUNDS = os.path.join(ROOT, 'config', 'ghidra_func_bounds.csv')
FUNCS = os.path.join(ROOT, 'config', 'functions.json')
THRESHOLD = 16

# Manual-fix functions — do NOT re-lift (would clobber native CRT replacements /
# manual edits). Keep in sync with the relift_func.py docstring + memory.
EXCLUDE = {0x52AD30, 0x52ADD0, 0x59AE30, 0x59D6A0, 0x564C50, 0x564D10,
           0x59F450, 0x59A880, 0x4CE080, 0x49AA40}

def main():
    dry = '--dry-run' in sys.argv
    funcs = sorted(json.load(open(FUNCS)), key=lambda f: f['address_int'])
    addrs = [f['address_int'] for f in funcs]
    gh = {}
    for line in open(BOUNDS):
        line = line.strip()
        if not line:
            continue
        s, e = line.split(',')
        gh[int(s, 16)] = int(e, 16)

    cmds = []
    for i, f in enumerate(funcs):
        a = f['address_int']
        if a in EXCLUDE:
            continue
        json_end = addrs[i + 1] if i + 1 < len(addrs) else a
        ge = gh.get(a)
        if ge and json_end - ge >= THRESHOLD:
            cmds.append('0x%08X:0x%08X' % (a, ge))

    print('%d over-extended functions to re-lift (excluding %d manual-fix funcs)'
          % (len(cmds), len(EXCLUDE)))
    if dry:
        print(' '.join(cmds))
        return
    if not cmds:
        return
    subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'relift_func.py')] + cmds,
                   cwd=ROOT, check=True)

if __name__ == '__main__':
    main()
