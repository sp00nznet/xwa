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
0x00408DC0:0x0040B4F0 0x0040C960:0x0040CCA0 0x0040DF00:0x0040E25D 0x0040F230:0x00411DE0 0x00413FA0:0x00414640 0x0041DB40:0x0041DF10 0x00422B70:0x004235D0 0x004240D0:0x004242D7
0x004242E0:0x00424820 0x00425490:0x00425DA0 0x00435AE0:0x00436A20 0x00444030:0x00444DF0 0x00467110:0x00467975 0x00467980:0x00468480 0x00473D00:0x00475A20 0x004873B0:0x00487680
0x00487B20:0x00487D1B 0x00489EC0:0x0048AE60 0x0048E450:0x0048E5E0 0x00497D40:0x004982C0 0x0049A490:0x0049A630 0x004A1850:0x004A1D80 0x004A6190:0x004A66B0 0x004A71D0:0x004A7350
0x004AE540:0x004AFD50 0x004B0770:0x004B2360 0x004B3250:0x004B37B0 0x004B63E0:0x004B64F0 0x004B7BA0:0x004B80A0 0x004B8F70:0x004B921B 0x004B9220:0x004B9AF2 0x004B9E40:0x004BA340
0x004BD130:0x004BD250 0x004C1400:0x004C28C0 0x004C4970:0x004C58E0 0x004C7F30:0x004C8070 0x004C8140:0x004C82F7 0x004CEEC0:0x004CF290 0x004D7880:0x004D8140 0x004D88D0:0x004D9190
0x004DD160:0x004DD3F0 0x004E8680:0x004E92D0 0x004EAC30:0x004EADC0 0x004EBEE0:0x004ED7F8 0x004F1610:0x004F1B00 0x004F8A40:0x004F8F90 0x004FBA80:0x00501B4C 0x005152F0:0x005174F0
0x00517B50:0x00517D48 0x00517EE0:0x00518528 0x00521860:0x00521E70 0x005223F0:0x005229F0 0x005241B0:0x005255B0 0x005263C0:0x00526470 0x00526470:0x0052690B 0x00529950:0x0052A250
0x005306C0:0x00530D40 0x0053B420:0x0053B4B7 0x0053C120:0x0053D7B0 0x005402C0:0x00540351 0x00540A00:0x00540A74 0x005435E0:0x00543720 0x00559310:0x005593B0 0x0056BEE0:0x0056D6BD
0x0056DDB0:0x0056E7D0 0x0056E7D0:0x0056ED70 0x00576520:0x00577140 0x00577140:0x0057748C 0x00577490:0x00577560 0x005775E0:0x00578660 0x0057B400:0x0057B782 0x005814B0:0x005827A0
0x0058C657:0x0058C8A9 0x00592A19:0x00592C3B 0x005995F0:0x00599BAD 0x0059BFA0:0x0059C060 0x0059F450:0x005A0190
""".split()

# One-off hand corrections (exact text replacements in gen; skipped once applied).
REPLACE = [
    # XWA_RENDERFN wrote 1 into 0x7828D0 believing it a render-enable flag; it is the ALERTBOXBUFFER
    # pointer, so sub_00511A90 later called free(1): heap corruption, the old L_0048967D crash.
    ('        if (!MEM32(0x7828D0u)) MEM32(0x7828D0u) = 1;\n',
     '        /* not 0x7828D0: that is the ALERTBOXBUFFER pointer, and 1 there made sub_00511A90 free(1) */\n'),
    # join point: the jge at 0x0044309B is reached from `cmp edi, ebx` @0x0044307D, not from the
    # textually preceding `cmp ebx, edi` @0x00443091 (audit: join_consumer_mismatched_setter)
    ('if (CMP_GE(ebx, edi)) goto L_004430AF; /* 0x0044309B: jge 0x4430af */',
     'if (CMP_GE(edi, ebx)) goto L_004430AF; /* 0x0044309B: jge 0x4430af */ /* join fix: setter is cmp edi,ebx @0x0044307D */'),
    # XWA_FGFILL (gen-only) gave objects without a render object pool + i*0xE5, but the pool is sized
    # for mobile objects ((n1+n2+n3)*0xE5 @0x00415A49) and handed out in order: that shared other
    # objects' ro and ran past the pool (into the object table) -> state and heap corruption
    ('                uint32_t _ro   = _pool + _i * 0xE5u;\n                if (!xwa_readable(_slot, 4) || !xwa_readable(_ro, 0xE5)) break;\n',
     '                uint32_t _ro   = _pool + _i * 0xE5u;\n                /* the pool is sized for mobile objects and handed out in order, not by object index */\n                { extern uint32_t xwa_ro_slot(uint32_t); _ro = xwa_ro_slot(_i); }\n                if (!xwa_readable(_slot, 4) || !_ro || !xwa_readable(_ro, 0xE5)) break;\n'),
    # join point: the jne at 0x004A393F is also reached by `jmp` from the `cmp [edx+0x85],0`
    # @0x004A392D path (sub_004A36B0, AI target filter); lifted, both paths tested [ebp+0x185], so a
    # canister the player carries stayed a valid pickup target for the wingman
    ('    goto L_004A393F; /* 0x004A3935: jmp 0x4a393f */',
     '    if (CMP_NE(MEM16(edx + 0x85), 0)) goto L_004A394F; goto L_004A3941; /* 0x004A3935: jmp 0x4a393f */ /* join fix: setter is cmp [edx+0x85] @0x004A392D */'),
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
                 'fix_postwrite', 'fix_clobbered_flags', 'fix_carry', 'fix_shiftflags', 'fix_narrowcmp'):
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
    # old block tracers ([G_AB]/[G_DC]/...) printed up to 200000 lines each, unconditionally
    import re
    for p in GEN:
        t = open(p, encoding='latin-1', newline='').read()
        t2 = re.sub(r'if \(g_(ab|dc|dr|em|ol|fr|st)_n < ([0-9]+) && ', r'if (g_blocktrace && g_\1_n < \2 && ', t)
        if t2 != t and 'extern int g_blocktrace;' not in t2:
            t2 = re.sub(r'(#include "recomp_funcs.h"\r?\n)', r'\1extern int g_blocktrace;\n', t2, count=1)
        if t2 != t:
            open(p, 'w', encoding='latin-1', newline='').write(t2)
    print(f'hand replacements applied: {n}')
    subprocess.run([PY, '-m', 'tools.apply_hooks'], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
