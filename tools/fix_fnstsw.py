"""Fix the fnstsw codegen bug in already-generated C.

The lifter emitted `fnstsw` as a comment, so `fcom; fnstsw ax; test ah,N; jcc` -- every MSVC float
compare, 595 sites in XWA -- branched on whatever AH last held. The lifter is fixed; this patches
gen/ in place without a regeneration (gen carries hand edits). Idempotent: it only touches lines that
still carry the old comment. See docs/lifter-audit.md.

    python tools/fix_fnstsw.py src/game/recomp/gen/recomp_000*.c
"""
import re
import sys

OLD = '/* fnstsw - FPU status to ax */ '
REG = re.compile(r'/\* fnstsw - FPU status to ax \*/ (/\* 0x[0-9A-F]{8}: fn?stsw ax \*/)')
# fnstsw word ptr [reg +/- n]
MEM = re.compile(r'/\* fnstsw - FPU status to ax \*/ (/\* 0x[0-9A-F]{8}: fn?stsw word ptr '
                 r'\[(e[a-ds][xpi]) ([+-]) (0x[0-9a-f]+|\d+)\] \*/)')


def fix(text):
    text, n1 = REG.subn(r'SET_LO16(eax, FPU_SW(_fpu_cmp)); \1', text)
    text, n2 = MEM.subn(lambda m: f'MEM16({m[2]} + ({m[3]}{m[4]})) = (uint16_t)FPU_SW(_fpu_cmp); {m[1]}', text)
    return text, n1 + n2, text.count(OLD)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        a = 'x /* fnstsw - FPU status to ax */ /* 0x00402AD4: fnstsw ax */\n' \
            'y /* fnstsw - FPU status to ax */ /* 0x00401234: fnstsw word ptr [ebp - 2] */\n'
        out, n, left = fix(a)
        assert n == 2 and left == 0, out
        assert 'SET_LO16(eax, FPU_SW(_fpu_cmp));' in out and 'MEM16(ebp + (-2))' in out, out
        assert fix(out)[1] == 0  # idempotent
        print('self-test ok')
    for path in sys.argv[1:]:
        src = open(path, encoding='latin-1', newline='').read()
        out, n, left = fix(src)
        if n:
            open(path, 'w', encoding='latin-1', newline='').write(out)
        print(f'{path}: {n} fixed' + (f', {left} UNMATCHED (hand-check)' if left else ''))
