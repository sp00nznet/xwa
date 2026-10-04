"""Snapshot cmp/test operands when a register they read is overwritten before the flags are used.

The lifter keeps flag state as LIVE operand expressions: `test esi, esi; pop esi; sete al` lifts to
    /* test esi, esi */ ...  esi = POP32_VAL(esp);  SET_LO8(eax, (TEST_Z(esi, esi)) ? 1 : 0);
so the condition reads the caller's esi that `pop` just restored, not the value tested. That is how
the CRT's _handle_exc (sub_005A7EE0) reported a masked acos() DOMAIN error as unhandled and raised
0xC0000090. For each consumer whose operands match the nearest preceding `/* cmp|test A, B */`
setter, if a register in A or B is assigned in between, this rewrites
    _fsa = (A); _fsb = (B); /* cmp A, B */      ...      MACRO(_fsa, _fsb)
declaring `uint32_t _fsa, _fsb` in the function. Only straight-line runs (no label between setter
and consumer) are touched; join points are a separate bug class. Idempotent. See
docs/lifter-audit.md.

    python tools/fix_clobbered_flags.py [--dry] src/game/recomp/gen/recomp_000*.c
"""
import re
import sys

REGS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')
SETTER = re.compile(r'^(?P<ind>[ \t]*)/\* (?P<op>cmp|test) (?P<a>.+?), (?P<b>.+?) \*/ /\* 0x[0-9A-F]{8}: (?:cmp|test) ')
CONSUMER = re.compile(r'\b(?P<mac>(?:CMP|TEST)_[A-Z]+)\((?P<args>[^;]*?)\)')
LABEL = re.compile(r'^L_[0-9A-F]{8}:')
FUNC = re.compile(r'^void sub_[0-9A-F]{8}\(void\) \{')


def regs_in(expr):
    return {r for r in REGS if re.search(r'\b%s\b' % r, expr)}


def writes(line, reg):
    code = line.split('/*')[0]
    return bool(re.search(r'(^\s*|[;{]\s*)%s\s*(=(?!=)|\+=|-=|\|=|&=|\^=|<<=|>>=)' % reg, code)
                or re.search(r'SET_(LO8|HI8|LO16)\(%s\b' % reg, code)
                or re.search(r'\b%s\s*(\+\+|--)' % reg, code))


def fix_lines(lines):
    n = 0
    func_start = None
    need_decl = set()
    setter = None  # (index, a, b)
    for i, line in enumerate(lines):
        if FUNC.match(line):
            func_start = i; setter = None; continue
        if LABEL.match(line):
            setter = None; continue
        m = SETTER.match(line)
        if m:
            setter = (i, m['a'], m['b']); continue
        if setter is None:
            continue
        si, a, b = setter
        for cm in CONSUMER.finditer(line.split('/*')[0] if line.lstrip().startswith('if') or 'SET_' in line else line):
            args = cm['args']
            if args.replace(' ', '') != f'{a},{b}'.replace(' ', ''):
                continue
            clob = [r for r in regs_in(a + ' ' + b) if any(writes(lines[k], r) for k in range(si + 1, i))]
            # the consumer line itself may write a register before evaluating? (e.g. SET_LO8(eax, ...))
            # that is evaluated first in C, so only the in-between lines matter.
            if not clob:
                continue
            sl = lines[si]
            ind = re.match(r'[ \t]*', sl).group(0)
            lines[si] = f'{ind}_fsa = (uint32_t)({a}); _fsb = (uint32_t)({b}); ' + sl.lstrip()
            lines[i] = line[:cm.start()] + f"{cm['mac']}(_fsa, _fsb)" + line[cm.end():]
            need_decl.add(func_start)
            n += 1
            setter = None
            break
    # declare in each touched function, right after its opening line
    for fs in sorted(need_decl, reverse=True):
        nl = '\r\n' if lines[fs].endswith('\r\n') else '\n'
        if '_fsa' not in lines[fs + 1]:
            lines.insert(fs + 1, f'    uint32_t _fsa = 0, _fsb = 0; /* operand snapshot, fix_clobbered_flags */{nl}')
    return n


def main(argv):
    dry = '--dry' in argv
    total = 0
    for p in [a for a in argv if not a.startswith('--')]:
        lines = open(p, encoding='latin-1', newline='').read().splitlines(keepends=True)
        n = fix_lines(lines)
        if n and not dry:
            open(p, 'w', encoding='latin-1', newline='').write(''.join(lines))
        total += n
        print(f'{p}: {n} fixed')
    print(f'total {total}')


if __name__ == '__main__':
    if len(sys.argv) == 1:
        t = ['void sub_00000001(void) {\n', '    uint16_t _fpu_cw = 0x037F;\n', 'L_00000001:\n',
             '    /* test esi, esi */ /* 0x005A8205: test esi, esi */\n', '    esi = POP32_VAL(esp); /* pop */\n',
             '    SET_LO8(eax, (TEST_Z(esi, esi)) ? 1 : 0); /* 0x005A8209: sete al */\n', '}\n']
        assert fix_lines(t) == 1, t
        assert 'TEST_Z(_fsa, _fsb)' in t[6] and t[4].lstrip().startswith('_fsa = (uint32_t)(esi)') and '_fsa' in t[1], t
        assert fix_lines(t) == 0
        print('self-test ok')
    else:
        main(sys.argv[1:])
