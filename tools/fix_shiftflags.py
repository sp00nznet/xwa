"""Make conditions that follow a shift test the shift's result.

The lifter does not treat shl/sal/shr/sar as flag setters, so a jcc/setcc after one is paired with
whatever set flags earlier: `sar ebp, 8; je` became `if (/* add result */ CMP_EQ(esp, 4))` from an
`add esp, 4` two lines up -- never true, so sub_0040BD20's zero check never fired and its idiv
divided by zero. (docs/lifter-audit.md: shifts publish no flags, #5.)

For every jcc/setcc whose nearest preceding flag-writing instruction in the same basic block is a
shift by a NONZERO immediate, the condition is rewritten on the shift's destination r at its width w:
    e/z  r == 0        ne/nz  r != 0        s  sx(r) < 0        ns  sx(r) >= 0
    l  sx(r) < 0       ge  sx(r) >= 0       g  sx(r) > 0        le  sx(r) <= 0
(for count > 1, or any sar, OF is 0, so the signed forms reduce to SF/ZF). Carry-based conditions
(b/ae/a/be) and count-1 shl/shr signed forms are left alone and reported.

    python tools/fix_shiftflags.py [--dry] src/game/recomp/gen/recomp_000*.c
    python tools/fix_shiftflags.py         # self-test
"""
import re
import sys

sys.path.insert(0, __import__('os').path.dirname(__file__))
from fix_carry import INSN, LABEL, KEEP_CF, operand  # noqa: E402

SHIFTS = {'shl', 'sal', 'shr', 'sar'}
FLAGLESS = KEEP_CF - {'inc', 'dec'} | {'push', 'pop', 'mov', 'lea', 'movzx', 'movsx', 'nop', 'xchg', 'cdq'}
COND = {'je': 'eq', 'jz': 'eq', 'jne': 'ne', 'jnz': 'ne', 'js': 's', 'jns': 'ns',
        'jl': 'l', 'jnge': 'l', 'jge': 'ge', 'jnl': 'ge', 'jg': 'g', 'jnle': 'g', 'jle': 'le', 'jng': 'le'}


def cond_expr(c, r, w):
    u = f'((uint{w}_t)({r}))'
    s = f'((int{w}_t)({r}))'
    return {'eq': f'({u} == 0)', 'ne': f'({u} != 0)', 's': f'({s} < 0)', 'ns': f'({s} >= 0)',
            'l': f'({s} < 0)', 'ge': f'({s} >= 0)', 'g': f'({s} > 0)', 'le': f'({s} <= 0)'}[c]


def fix_lines(lines):
    n, why = 0, {}
    for i, line in enumerate(lines):
        m = INSN.search(line)
        if not m:
            continue
        mn = m[2]
        key = mn if mn.startswith('j') else ('j' + mn[3:] if mn.startswith('set') else None)
        if not key or key == 'jmp' or key not in COND and not key.startswith('j'):
            continue
        if 'shift fixed' in line:
            continue
        # nearest flag writer above, same block
        j, setter = i - 1, None
        while j >= 0:
            L = lines[j]
            if LABEL.match(L) or L.startswith('void ') or L.startswith('}'):
                break
            mm = INSN.search(L)
            if mm:
                if mm[2] in FLAGLESS or mm[2].startswith('j') or mm[2].startswith('set'):
                    j -= 1; continue
                setter = (mm[2], mm[3] or '')
                break
            j -= 1
        if not setter or setter[0] not in SHIFTS:
            continue
        parts = [p.strip() for p in re.split(r',\s*(?![^\[]*\])', setter[1])]
        if len(parts) != 2 or not re.match(r'^(0x[0-9a-f]+|\d+)$', parts[1]):
            why['variable count'] = why.get('variable count', 0) + 1; continue
        cnt = int(parts[1], 0) & 31
        if cnt == 0:
            continue
        c = COND.get(key)
        if c is None:
            why[f'{key} after shift'] = why.get(f'{key} after shift', 0) + 1; continue
        if c in ('l', 'ge', 'g', 'le') and cnt == 1 and setter[0] != 'sar':
            why['signed after 1-bit shl/shr'] = why.get('signed after 1-bit shl/shr', 0) + 1; continue
        op = operand(parts[0])
        if not op:
            why['operand'] = why.get('operand', 0) + 1; continue
        expr = cond_expr(c, op[0], op[1] or 32)
        if mn.startswith('j'):
            mm2 = re.match(r'^(\s*if \()(.*)(\) (?:goto L_[0-9A-F]{8}|\{ RECOMP_ITAIL\(0x[0-9A-F]+u\); return; \});.*)$', line, re.S)
            if not mm2:
                why['jcc form'] = why.get('jcc form', 0) + 1; continue
            lines[i] = f'{mm2[1]}/* shift fixed */ {expr}{mm2[3]}'
        else:
            mm2 = re.match(r'^(\s*SET_LO8\((e[a-d]x), )\((.*)\) \? 1 : 0(\);.*)$', line, re.S)
            if not mm2:
                why['setcc form'] = why.get('setcc form', 0) + 1; continue
            lines[i] = f'{mm2[1]}(/* shift fixed */ {expr}) ? 1 : 0{mm2[4]}'
        n += 1
    return n, why


def selftest():
    t = ['    esp = esp + 4; /* 0x0040BDFC: add esp, 4 */\n',
         '    ebp = (uint32_t)((int32_t)ebp >> 8); /* 0x0040BE02: sar ebp, 8 */\n',
         '    if (/* add result, fixed */ (((uint32_t)(esp)) == 0)) goto L_0040BF0B; /* 0x0040BE05: je 0x40bf0b */\n']
    n, why = fix_lines(t)
    assert n == 1 and '(((uint32_t)(ebp)) == 0)) goto L_0040BF0B' in t[2], (n, why, t)
    assert fix_lines(t)[0] == 0
    print('self-test ok')


def main(argv):
    if not argv:
        selftest(); return
    dry = '--dry' in argv
    tot, allwhy = 0, {}
    for p in [a for a in argv if not a.startswith('--')]:
        lines = open(p, encoding='latin-1', newline='').read().splitlines(keepends=True)
        n, why = fix_lines(lines)
        for k, v in why.items():
            allwhy[k] = allwhy.get(k, 0) + v
        if n and not dry:
            open(p, 'w', encoding='latin-1', newline='').write(''.join(lines))
        tot += n
        print(f'{p}: {n} fixed')
    print(f'total {tot}; not fixed: {allwhy}')


if __name__ == '__main__':
    main(sys.argv[1:])
