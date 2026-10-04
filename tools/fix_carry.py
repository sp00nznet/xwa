"""Publish the carry flag where the lifter never did.

The lifter models CF as a variable `_cf` that only shifts/clc/stc write. `cmp`, `sub`, `add`, `neg`
and the logical ops never set it, so every `sbb`/`adc`/`rcl`/`rcr` that consumes their carry reads
whatever an earlier shift left there: `cmp; sbb r,r` booleans, `sbb r,r; sbb r,-1` strcmp sign
tails, 64-bit `add; adc` / `sub; sbb`. (docs/lifter-audit.md: CF publishing, ~850 sites.)

For each consumer this walks back through the same basic block (stopping at a label or call) to the
instruction that really produced CF -- skipping instructions that leave CF alone (mov, lea, push,
pop, inc, dec, not, setcc, `sbb r,r` which preserves CF) -- and inserts, just before that setter,
the carry it produces, computed from its operands before they are written:

    cmp/sub a, b  ->  _cf = (u(a) < u(b))           add a, b  ->  _cf = (u(a) + u(b)) >> w
    neg a         ->  _cf = (u(a) != 0)             test/and/or/xor  ->  _cf = 0

at the operand width w. Operands come from the instruction comment (asm syntax), translated to the
runtime's macros. Idempotent (inserted lines are tagged). Sites it cannot prove are counted.

    python tools/fix_carry.py [--dry] src/game/recomp/gen/recomp_000*.c
    python tools/fix_carry.py           # self-test
"""
import re
import sys

INSN = re.compile(r'/\* 0x([0-9A-F]{8}): ([a-z][a-z0-9 ]*?)(?: (.*?))? \*/')
LABEL = re.compile(r'^\s*L_[0-9A-F]{8}:')
TAG = '/* fix_carry */'

R32 = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'}
R16 = {'ax': 'eax', 'bx': 'ebx', 'cx': 'ecx', 'dx': 'edx', 'si': 'esi', 'di': 'edi', 'bp': 'ebp', 'sp': 'esp'}
R8L = {'al': 'eax', 'bl': 'ebx', 'cl': 'ecx', 'dl': 'edx'}
R8H = {'ah': 'eax', 'bh': 'ebx', 'ch': 'ecx', 'dh': 'edx'}
SIZES = {'byte': (8, 'MEM8'), 'word': (16, 'MEM16'), 'dword': (32, 'MEM32')}
KEEP_CF = {'mov', 'movzx', 'movsx', 'lea', 'push', 'pop', 'inc', 'dec', 'not', 'nop', 'xchg', 'cdq', 'cwde',
           'cbw', 'fld', 'fstp', 'fst', 'fild', 'fistp', 'fxch', 'fmul', 'fadd', 'fsub', 'fdiv', 'fsubr', 'fdivr',
           'fmulp', 'faddp', 'fsubp', 'fdivp', 'fsubrp', 'fdivrp', 'fchs', 'fabs', 'fldz', 'fld1'}
SETCC = re.compile(r'^set[a-z]+$|^cmov[a-z]+$')


def operand(op):
    """asm operand -> (C expression, width) or None"""
    op = op.strip()
    if op in R32:
        return op, 32
    if op in R16:
        return f'LO16({R16[op]})', 16
    if op in R8L:
        return f'LO8({R8L[op]})', 8
    if op in R8H:
        return f'HI8({R8H[op]})', 8
    m = re.match(r'^(byte|word|dword) ptr (?:[cdes]s:)?\[(.+)\]$', op)
    if m:
        if 'fs:' in op or 'gs:' in op:
            return None
        w, mac = SIZES[m[1]]
        inner = re.sub(r'\b(0x[0-9a-f]+)\b', lambda x: x[1] + 'u', m[2])
        return f'{mac}({inner})', w
    m = re.match(r'^(-?0x[0-9a-f]+|-?\d+)$', op)
    if m:
        v = int(m[1], 0) & 0xFFFFFFFF
        return f'0x{v:X}u', 0
    return None


def u(expr, w):
    return f'((uint{w}_t)({expr}))'


def carry_for(mn, ops):
    parts = [p for p in re.split(r',\s*(?![^\[]*\])', ops)] if ops else []
    if mn in ('test', 'and', 'or', 'xor'):
        return '_cf = 0;'
    if mn in ('cmp', 'sub', 'add') and len(parts) == 2:
        a, b = operand(parts[0]), operand(parts[1])
        if not a or not b:
            return None
        w = a[1] or b[1] or 32
        if mn in ('cmp', 'sub'):
            return f'_cf = ({u(a[0], w)} < {u(b[0], w)});'
        return f'_cf = (uint32_t)(((uint64_t){u(a[0], w)} + (uint64_t){u(b[0], w)}) >> {w});'
    if mn == 'neg' and len(parts) == 1:
        a = operand(parts[0])
        if not a:
            return None
        return f'_cf = ({u(a[0], a[1] or 32)} != 0);'
    return None


def _setters(lines, j, fstart, fend, depth, seen):
    """Walk back from line j (exclusive) to the CF producer(s) of every path reaching it.
    Returns a list of (line index, mnemonic, operands) or a string saying why it cannot."""
    if depth > 6:
        return 'deep'
    out = []
    while j > fstart:
        j -= 1
        L = lines[j]
        lm = LABEL.match(L)
        if lm:
            lab = L.strip().rstrip(':')
            if lab in seen:
                return out
            seen = seen | {lab}
            # every jump to this label is a predecessor
            for k in range(fstart, fend):
                if 'goto ' + lab + ';' in lines[k] and k != j:
                    r = _setters(lines, k, fstart, fend, depth + 1, seen)
                    if isinstance(r, str):
                        return r
                    out += r
            continue                                     # and the fall-through, below
        if TAG in L:
            return out                                   # already published on this path
        mm = INSN.search(L)
        if not mm:
            continue
        mn, ops = mm[2], mm[3] or ''
        if mn == 'jmp' or 'return;' in L.split('/*')[0]:
            return out                                   # no fall-through into what follows
        if mn.startswith('j') or mn in KEEP_CF or SETCC.match(mn):
            continue
        if mn == 'sbb':
            p = [x.strip() for x in ops.split(',')]
            if len(p) == 2 and p[0] == p[1]:
                continue                                 # sbb r,r preserves CF
        if mn == 'call':
            return 'call'
        if carry_for(mn, ops) is None:
            return f'setter {mn}'
        out.append((j, mn, ops))
        return out
    return 'function start'


def fix_lines(lines):
    n, why = 0, {}
    fstart = 0
    i = 0
    while i < len(lines):
        if lines[i].startswith('void sub_'):
            fstart = i
        m = INSN.search(lines[i])
        if not m or m[2] not in ('sbb', 'adc', 'rcl', 'rcr') or '_cf' not in lines[i].split('/*')[0]:
            i += 1
            continue
        fend = i
        while fend < len(lines) and not lines[fend].startswith('}'):
            fend += 1
        r = _setters(lines, i, fstart, fend, 0, frozenset())
        if isinstance(r, str):
            why[r] = why.get(r, 0) + 1
            i += 1
            continue
        todo = sorted({(j, mn, ops) for j, mn, ops in r if not (j > 0 and TAG in lines[j - 1])}, reverse=True)
        for j, mn, ops in todo:
            ind = re.match(r'[ \t]*', lines[j]).group(0)
            nl = '\r\n' if lines[j].endswith('\r\n') else '\n'
            lines.insert(j, f'{ind}{carry_for(mn, ops)} {TAG}{nl}')
            n += 1
            if j <= i:
                i += 1
        i += 1
    return n, why


def selftest():
    t = ['    /* cmp eax, 0x15u */ /* 0x00401000: cmp eax, 0x15 */\n',
         '    eax = _cf ? 0xFFFFFFFFu : 0; /* 0x00401003: sbb eax, eax */\n',
         '    eax = eax - 0xFFFFFFFFu - _cf; /* 0x00401005: sbb eax, -1 */\n',
         '    edx = edx + ecx; /* 0x00401010: add edx, ecx */\n',
         '    eax = eax + 0 + _cf; /* 0x00401012: adc eax, 0 */\n',
         'L_00401020:\n',
         '    ecx = ecx + 0 + _cf; /* 0x00401020: adc ecx, 0 */\n',
         '    SET_LO8(eax, -LO8(eax)); /* 0x00401030: neg al */\n',
         '    ebx = _cf ? 0xFFFFFFFFu : 0; /* 0x00401032: sbb ebx, ebx */\n']
    n, why = fix_lines(t)
    s = ''.join(t)
    assert n == 3, (n, why, s)  # cmp, add, neg; the L_00401020 adc follows the add through the label
    assert '_cf = (((uint32_t)(eax)) < ((uint32_t)(0x15u)));' in s, s
    assert '>> 32);' in s and '_cf = (((uint8_t)(LO8(eax))) != 0);' in s, s
    assert fix_lines(t)[0] == 0
    assert operand('dword ptr [ebp - 0x10]') == ('MEM32(ebp - 0x10u)', 32)
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
