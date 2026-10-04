"""Replay every repair applied to the generated C, in order. Idempotent.

gen/ is gitignored, so fixes that live in it are lost on a regeneration. This script is the
record: run it after `python -m tools ... -o src/game/recomp/gen` (or any time) to bring gen to
the state the repo was tested in. Each step is a tool that rewrites only what still has the old
shape, so re-running is safe. See docs/lifter-audit.md for what each bug class is.

    python tools/repair_gen.py
"""
import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = sorted(glob.glob(os.path.join(ROOT, 'src', 'game', 'recomp', 'gen', 'recomp_000*.c')))
PY = sys.executable

# Functions whose gen body lost code: a func-split "merge" stubbed the pieces out but the owner was
# never re-lifted over them (sub_0040F230, the hangar-launch transfer, was 7 instructions long), or
# a local jump table was lifted as an indirect tail call. Re-lift with an explicit end.
RELIFT = """
0x0040F230:0x00411DE0 0x00413FA0:0x00414640 0x0041DB40:0x0041DF10 0x00422B70:0x004235D0
0x004242E0:0x00424820 0x00435AE0:0x00436A20 0x00444030:0x00444DF0 0x00467110:0x00467881
0x00467980:0x00468480 0x00473D00:0x00475A20 0x00489EC0:0x0048AE60 0x00497D40:0x004982C0
0x004A1850:0x004A1D80 0x004A6190:0x004A66B0 0x004AE540:0x004AFD50 0x004B63E0:0x004B64F0
0x004B7BA0:0x004B80A0 0x004C1400:0x004C28C0 0x004C7F30:0x004C8070 0x004CEEC0:0x004CF290
0x004D88D0:0x004D9190 0x004DD160:0x004DD3F0 0x004E8680:0x004E92D0 0x004EAC30:0x004EADC0
0x004EBEE0:0x004ED7F0 0x004F1610:0x004F1B00 0x004F8A40:0x004F8F90 0x004FBA80:0x00500DFE
0x005152F0:0x005174F0 0x00521860:0x00521E70 0x005223F0:0x005229F0 0x005241B0:0x005255B0
0x00529950:0x0052A250 0x00559310:0x005593B0 0x0058C657:0x0058C8A9 0x00592A19:0x00592C3B
0x005995F0:0x00599BAD
0x0040A15D 0x0053C120 0x0056E7D0 0x004A71D0 0x004B3250 0x004B9E40 0x004BD130 0x004C4970
0x00517B50 0x00517C28 0x005306C0 0x0053B4B3 0x005435E0 0x0056DDB0 0x00576520 0x00577490
0x0059F450 0x004D7880
""".split()

# One-off hand corrections (exact text replacements in gen; skipped once applied).
REPLACE = [
    # XWA_RENDERFN wrote 1 into 0x7828D0 believing it a render-enable flag; it is the ALERTBOXBUFFER
    # pointer, so sub_00511A90 later called free(1): heap corruption, the old L_0048967D crash.
    ('        if (!MEM32(0x7828D0u)) MEM32(0x7828D0u) = 1;
',
     '        /* not 0x7828D0: that is the ALERTBOXBUFFER pointer, and 1 there made sub_00511A90 free(1) */
'),
    # join point: the jge at 0x0044309B is reached from `cmp edi, ebx` @0x0044307D, not from the
    # textually preceding `cmp ebx, edi` @0x00443091 (audit: join_consumer_mismatched_setter)
    ('if (CMP_GE(ebx, edi)) goto L_004430AF; /* 0x0044309B: jge 0x4430af */',
     'if (CMP_GE(edi, ebx)) goto L_004430AF; /* 0x0044309B: jge 0x4430af */ /* join fix: setter is cmp edi,ebx @0x0044307D */'),
    # sub_00597784 was handed a float (0x3F800000) as a render node after the hangar exit; the
    # LINK_OK range test let it through
    ('    if (!LINK_OK(eax)) goto L_005977E9;',
     '    { extern int xwa_readable(uint32_t, uint32_t); if (!LINK_OK(eax) || !xwa_readable(eax, 0x8C)) goto L_005977E9; }'),
]


def run(*args):
    print('$', ' '.join(os.path.basename(a) if a.endswith('.py') else a for a in args[:3]), '...' if len(args) > 3 else '')
    subprocess.run([PY, *args], cwd=ROOT, check=True)


def main():
    run(os.path.join('tools', 'relift_func.py'), *RELIFT)
    for tool in ('fix_dec_cond', 'fix_test_cond', 'fix_fpu_pop', 'fix_fnstsw', 'fix_jmptbl',
                 'fix_postwrite', 'fix_clobbered_flags', 'fix_carry', 'fix_shiftflags'):
        run(os.path.join('tools', tool + '.py'), *GEN)
    n = 0
    for p in GEN:
        s = open(p, encoding='latin-1', newline='').read()
        t = s
        for old, new in REPLACE:
            if old in t and new not in t:
                t = t.replace(old, new); n += 1
        if t != s:
            open(p, 'w', encoding='latin-1', newline='').write(t)
    print(f'hand replacements applied: {n}')
    subprocess.run([PY, '-m', 'tools.apply_hooks'], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
