"""Fix conditions the lifter evaluated on an ALREADY-WRITTEN destination.

For `sub/add/and/or/xor X, Y; jcc` the lifter emits
    X = X - Y;  if (/* sub result */ CMP_xx(X, Y)) ...
i.e. the condition macro is applied to the NEW X and Y, as if it were `cmp X, Y`. That is wrong for
almost every condition (`sub eax, 0x15; je` fired for eax == 0x2A, not 0x15). Each case has an
exact rewrite from the result r and the source b, at the operand's width w:

  any op, e/ne/s/ns          result tests:  r == 0, r != 0, sx(r) < 0, sx(r) >= 0
  sub, relational            original a = r + b (mod 2^w):  CMP_xx(a, b) at width w
  sub, o/no                  overflow of a - b
  add, signed l/ge/g/le      true sum sx(a) + sx(b) (a = r - b) compared with 0, in 64 bits
  add, unsigned b/ae/a/be    carry = ur < ub;  a: !carry && r != 0;  be: carry || r == 0
  add, o/no                  true sum != sx(r)
  and/or/xor (CF=OF=0)       TEST_Z/NZ/S/NS/G/LE/L/GE -> tests on r; CMP_BE -> r == 0; CMP_A -> r != 0
  p/np (any)                 parity of the low byte of r

Width comes from the operand wrapper: LO8/HI8/MEM8 = 8, LO16/MEM16 = 16, else 32. Idempotent: rewritten
sites lose the `/* op result */` marker. Unrecognised forms are counted and left alone.
See docs/lifter-audit.md (post-write setters, narrow signed conditions).

    python tools/fix_postwrite.py [--dry] src/game/recomp/gen/recomp_000*.c
    python tools/fix_postwrite.py            # self-test
"""
import re
import sys

MARK = re.compile(r'/\* (sub|add|and|or|xor) result \*/ ((?:CMP|TEST)_[A-Z]+)\(')


def split_args(s, i):
    """s[i] is just past '('. Return (args, index just past the matching ')')."""
    depth, start, args = 0, i, []
    while i < len(s):
        c = s[i]
        if c == '(':
            depth += 1
        elif c == ')':
            if depth == 0:
                args.append(s[start:i].strip())
                return args, i + 1
            depth -= 1
        elif c == ',' and depth == 0:
            args.append(s[start:i].strip()); start = i + 1
        i += 1
    raise ValueError('unbalanced')


def width(a):
    if re.match(r'(LO8|HI8|MEM8)\(', a) or a.startswith('(uint8_t)'):
        return 8
    if re.match(r'(LO16|MEM16)\(', a) or a.startswith('(uint16_t)'):
        return 16
    return 32


U = {8: 'uint8_t', 16: 'uint16_t', 32: 'uint32_t'}
S = {8: 'int8_t', 16: 'int16_t', 32: 'int32_t'}


def rewrite(op, mac, a, b):
    w = width(a)
    u = lambda x: f'(({U[w]})({x}))'
    sx = lambda x: f'(({S[w]})({x}))'
    r = a
    res = {'CMP_EQ': f'({u(r)} == 0)', 'CMP_NE': f'({u(r)} != 0)', 'CMP_S': f'({sx(r)} < 0)',
           'CMP_NS': f'({sx(r)} >= 0)', 'TEST_Z': f'({u(r)} == 0)', 'TEST_NZ': f'({u(r)} != 0)',
           'TEST_S': f'({sx(r)} < 0)', 'TEST_NS': f'({sx(r)} >= 0)'}
    lb = f'((uint8_t)({r}))'
    par = f'(((0x6996u >> (({lb} ^ ({lb} >> 4)) & 0xFu)) & 1u) == 0)'
    if mac in ('CMP_P', 'TEST_P'):
        return par
    if mac in ('CMP_NP', 'TEST_NP'):
        return f'(!{par})'
    if mac in res:
        return res[mac]
    if op in ('and', 'or', 'xor'):
        logic = {'TEST_G': f'({sx(r)} > 0)', 'TEST_LE': f'({sx(r)} <= 0)', 'TEST_L': f'({sx(r)} < 0)',
                 'TEST_GE': f'({sx(r)} >= 0)', 'CMP_G': f'({sx(r)} > 0)', 'CMP_LE': f'({sx(r)} <= 0)',
                 'CMP_L': f'({sx(r)} < 0)', 'CMP_GE': f'({sx(r)} >= 0)', 'CMP_BE': f'({u(r)} == 0)',
                 'CMP_A': f'({u(r)} != 0)', 'TEST_BE': f'({u(r)} == 0)', 'TEST_A': f'({u(r)} != 0)',
                 'CMP_O': '(0)', 'CMP_NO': '(1)'}
        return logic.get(mac)
    if b is None:
        return None
    if op == 'sub':
        orig = f'(({U[w]})(({U[w]})({r}) + ({U[w]})({b})))'
        rel = {'CMP_B': '<', 'CMP_AE': '>=', 'CMP_A': '>', 'CMP_BE': '<='}
        srel = {'CMP_L': '<', 'CMP_GE': '>=', 'CMP_G': '>', 'CMP_LE': '<='}
        if mac in rel:
            return f'({orig} {rel[mac]} {u(b)})'
        if mac in srel:
            return f'((({S[w]}){orig}) {srel[mac]} {sx(b)})'
        if mac in ('CMP_O', 'CMP_NO'):
            ov = f'((((({S[w]}){orig}) ^ {sx(b)}) & ((({S[w]}){orig}) ^ {sx(r)})) < 0)'
            return ov if mac == 'CMP_O' else f'(!{ov})'
        return None
    if op == 'add':
        orig = f'(({U[w]})(({U[w]})({r}) - ({U[w]})({b})))'
        tsum = f'((int64_t)(({S[w]}){orig}) + (int64_t){sx(b)})'
        srel = {'CMP_L': '<', 'CMP_GE': '>=', 'CMP_G': '>', 'CMP_LE': '<='}
        if mac in srel:
            return f'({tsum} {srel[mac]} 0)'
        carry = f'({u(r)} < {u(b)})'
        if mac == 'CMP_B':
            return carry
        if mac == 'CMP_AE':
            return f'(!{carry})'
        if mac == 'CMP_A':
            return f'(!{carry} && {u(r)} != 0)'
        if mac == 'CMP_BE':
            return f'({carry} || {u(r)} == 0)'
        if mac in ('CMP_O', 'CMP_NO'):
            ov = f'({tsum} != (int64_t){sx(r)})'
            return ov if mac == 'CMP_O' else f'(!{ov})'
    return None


def fix(text):
    out, pos, n, skipped = [], 0, 0, {}
    for m in MARK.finditer(text):
        if m.start() < pos:
            continue
        args, end = split_args(text, m.end())
        a = args[0]
        b = args[1] if len(args) > 1 else None
        new = rewrite(m[1], m[2], a, b)
        if new is None:
            skipped[f'{m[1]} {m[2]}'] = skipped.get(f'{m[1]} {m[2]}', 0) + 1
            continue
        out.append(text[pos:m.start()]); out.append(f'/* {m[1]} result, fixed */ {new}')
        pos = end; n += 1
    out.append(text[pos:])
    return ''.join(out), n, skipped


def selftest():
    import ctypes
    def ev(expr, env):
        e = expr
        for k, v in env.items():
            e = re.sub(r'\b%s\b' % k, str(v), e)
        e = e.replace('(uint8_t)', 'U8').replace('(uint16_t)', 'U16').replace('(uint32_t)', 'U32')
        e = e.replace('(int8_t)', 'S8').replace('(int16_t)', 'S16').replace('(int32_t)', 'S32').replace('(int64_t)', '')
        e = e.replace('&&', ' and ').replace('||', ' or ').replace('!(', ' not (').replace('0x6996u', '0x6996').replace('0xFu', '0xF').replace('1u', '1')
        for t, f in (('U8', 'u8'), ('U16', 'u16'), ('U32', 'u32'), ('S8', 's8'), ('S16', 's16'), ('S32', 's32')):
            e = e.replace(t, f)
        g = dict(u8=lambda x: x & 0xFF, u16=lambda x: x & 0xFFFF, u32=lambda x: x & 0xFFFFFFFF,
                 s8=lambda x: ctypes.c_int8(x).value, s16=lambda x: ctypes.c_int16(x).value,
                 s32=lambda x: ctypes.c_int32(x).value)
        return bool(eval(e, g))
    # reference x86 flags for 32-bit sub/add
    def flags(op, a, b):
        M = 0xFFFFFFFF
        r = (a - b) & M if op == 'sub' else (a + b) & M
        cf = (a < b) if op == 'sub' else (a + b > M)
        sa, sb, sr = [ctypes.c_int32(x).value for x in (a, b, r)]
        of = ((sa ^ sb) & (sa ^ sr)) < 0 if op == 'sub' else ((sa ^ sr) & (sb ^ sr)) < 0
        zf, sf = r == 0, sr < 0
        return r, dict(CMP_EQ=zf, CMP_NE=not zf, CMP_S=sf, CMP_NS=not sf, CMP_B=cf, CMP_AE=not cf,
                       CMP_A=not cf and not zf, CMP_BE=cf or zf, CMP_L=sf != of, CMP_GE=sf == of,
                       CMP_G=not zf and sf == of, CMP_LE=zf or sf != of, CMP_O=of, CMP_NO=not of)
    vals = [0, 1, 2, 0x15, 0x2A, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE, 1234567]
    bad = 0
    for op in ('sub', 'add'):
        for a in vals:
            for b in vals:
                r, want = flags(op, a, b)
                for mac, w in want.items():
                    got = ev(rewrite(op, mac, 'eax', 'ebx'), {'eax': r, 'ebx': b})
                    if got != w:
                        bad += 1
                        if bad < 5: print('MISMATCH', op, mac, hex(a), hex(b), got, w)
    s, n, _ = fix('if (/* sub result */ CMP_EQ(eax, 0x15u)) goto L_1;')
    assert n == 1 and 'fixed' in s and fix(s)[1] == 0, s
    assert bad == 0, f'{bad} mismatches'
    print('self-test ok')


def main(argv):
    if not argv:
        selftest(); return
    dry = '--dry' in argv
    tot, allskip = 0, {}
    for p in [a for a in argv if not a.startswith('--')]:
        src = open(p, encoding='latin-1', newline='').read()
        new, n, sk = fix(src)
        for k, v in sk.items():
            allskip[k] = allskip.get(k, 0) + v
        if n and not dry:
            open(p, 'w', encoding='latin-1', newline='').write(new)
        tot += n
        print(f'{p}: {n} fixed')
    print(f'total {tot} fixed; left alone: {allskip}')


if __name__ == '__main__':
    main(sys.argv[1:])
