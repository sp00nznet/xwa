"""Signed conditions on 8/16-bit operands, compared at their real width.

The runtime's CMP_L/CMP_GE/... macros cast both operands to int32, and the lifter passes narrow
operands zero-extended (LO8(eax), MEM16(p), ...). So `cmp al, 0x10; jl` treats al=0xF0 as +240
instead of -16, and `test cx, cx; js` can never be true. Equality and unsigned conditions are
unaffected. (docs/lifter-audit.md: narrow-operand signed flags, #4.)

Rewrites CMP_{L,GE,G,LE,S,NS}(a, b) and TEST_{S,NS,L,GE,G,LE}(a, b) when a is narrow (LO8/HI8/MEM8
-> 8 bits, LO16/MEM16 -> 16 bits), as explicit signed comparisons at that width:
    CMP_L(a,b)  -> ((intW)(a) < (intW)(b))              CMP_S(a,b) -> ((intW)((a) - (b)) < 0)
    TEST_S(a,b) -> ((intW)((a) & (b)) < 0)              TEST_LE(a,b) -> ((intW)((a) & (b)) <= 0)
OF is ignored for CMP_S/NS exactly as the macros do. Already-rewritten conditions (post-write fixes)
have no macro left and are untouched. Idempotent.

    python tools/fix_narrowcmp.py [--dry] src/game/recomp/gen/recomp_000*.c
    python tools/fix_narrowcmp.py         # self-test
"""
import re
import sys

MAC = re.compile(r'\b(CMP_(?:L|GE|G|LE|S|NS)|TEST_(?:S|NS|L|GE|G|LE))\(')


def split_args(s, i):
    depth, start, args = 0, i, []
    while i < len(s):
        c = s[i]
        if c == '(':
            depth += 1
        elif c == ')':
            if depth == 0:
                args.append(s[start:i].strip()); return args, i + 1
            depth -= 1
        elif c == ',' and depth == 0:
            args.append(s[start:i].strip()); start = i + 1
        i += 1
    raise ValueError


def width(a):
    if re.match(r'^(LO8|HI8|MEM8)\(', a):
        return 8
    if re.match(r'^(LO16|MEM16)\(', a):
        return 16
    return 32


def rewrite(mac, a, b):
    w = width(a)
    if w == 32:
        return None
    S = f'int{w}_t'
    if mac.startswith('CMP_'):
        op = mac[4:]
        if op in ('S', 'NS'):
            r = f'(({S})(({a}) - ({b})))'
            return f'({r} {"<" if op == "S" else ">="} 0)'
        rel = {'L': '<', 'GE': '>=', 'G': '>', 'LE': '<='}[op]
        return f'((({S})({a})) {rel} (({S})({b})))'
    op = mac[5:]
    r = f'(({S})(({a}) & ({b})))'
    return f'({r} {{"S": "<", "NS": ">=", "L": "<", "GE": ">=", "G": ">", "LE": "<="}}[op] 0)'.replace(
        '{"S": "<", "NS": ">=", "L": "<", "GE": ">=", "G": ">", "LE": "<="}[op]',
        {"S": "<", "NS": ">=", "L": "<", "GE": ">=", "G": ">", "LE": "<="}[op])


def fix(text):
    out, pos, n = [], 0, 0
    for m in MAC.finditer(text):
        if m.start() < pos:
            continue
        # skip the macro definitions themselves / non-code
        line_start = text.rfind('\n', 0, m.start()) + 1
        if text[line_start:m.start()].lstrip().startswith(('#', '/*', '*')):
            continue
        try:
            args, end = split_args(text, m.end())
        except ValueError:
            continue
        if len(args) != 2:
            continue
        new = rewrite(m[1], args[0], args[1])
        if not new:
            continue
        out.append(text[pos:m.start()]); out.append(new); pos = end; n += 1
    out.append(text[pos:])
    return ''.join(out), n


def selftest():
    s, n = fix('if (CMP_L(LO8(eax), 0x10u)) goto L_1; if (TEST_S(LO16(ecx), LO16(ecx))) goto L_2; if (CMP_L(eax, 1)) goto L_3;')
    assert n == 2, s
    assert '((int8_t)(LO8(eax))) < ((int8_t)(0x10u))' in s and '((int16_t)((LO16(ecx)) & (LO16(ecx)))) < 0' in s, s
    assert 'CMP_L(eax, 1)' in s
    assert fix(s)[1] == 0
    print('self-test ok')


def main(argv):
    if not argv:
        selftest(); return
    dry = '--dry' in argv
    tot = 0
    for p in [a for a in argv if not a.startswith('--')]:
        src = open(p, encoding='latin-1', newline='').read()
        new, n = fix(src)
        if n and not dry:
            open(p, 'w', encoding='latin-1', newline='').write(new)
        tot += n
        print(f'{p}: {n} fixed')
    print(f'total {tot}')


if __name__ == '__main__':
    main(sys.argv[1:])
