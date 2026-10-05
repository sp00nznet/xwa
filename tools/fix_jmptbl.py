"""Reconstruct local switch jump tables the lifter emitted as indirect tail calls.

`jmp dword ptr [reg*4 + TABLE]` inside a function was lifted as
    RECOMP_ITAIL(MEM32(reg * 4 + 0xTABLE)); return;
When the targets are code of the SAME function, the dispatch finds no function there and returns
without the function's epilogue -- leaving its pushed registers on the stack, so the caller's esp
is off. That is what corrupted sub_004D5AE0's locals after sub_004D7880 (the crash after the hangar
Launch). This rewrites each such site, when the bound comes from the usual `cmp reg, N; ja` guard
and every entry is an instruction of the function, into
    switch (reg) { case 0: goto L_..; ... default: RECOMP_ITAIL(...); return; }
adding a label in front of any target instruction that has none (the lifter only labels direct
branch targets). Sites it cannot prove are reported and left alone. Idempotent.

    python tools/fix_jmptbl.py [--dry] src/game/recomp/gen/recomp_000*.c
"""
import re
import struct
import sys

import pefile

EXE = 'config/xwingalliance_decrypted.exe'
SITE = re.compile(r'^(?P<ind>[ \t]*)RECOMP_ITAIL\(MEM32\((?P<reg>e[a-ds][xpi]) \* 4 \+ 0x(?P<tbl>[0-9A-F]+)\)\); return;'
                  r'(?P<cmt> /\* 0x[0-9A-F]{8}: jmp dword ptr \[[^\]]*\] \*/)', re.M)
# the lifter writes small immediates in decimal (`CMP_A(eax, 3)`), larger ones in hex
# the ja may also leave the function (a bad func split lifts it as an ITAIL)
BOUND = re.compile(r'if \(CMP_A\((?P<reg>e[a-ds][xpi]), (?:0x(?P<n>[0-9A-F]+)u?|(?P<d>[0-9]+))\)\) '
                   r'(?:goto L_[0-9A-F]{8};|\{ RECOMP_ITAIL\(0x[0-9A-F]+u\); return; \})')
COPY = re.compile(r'(?P<dst>e[a-ds][xpi]) = (?P<src>e[a-ds][xpi]); /\* 0x[0-9A-F]{8}: mov ')


def bound_count(b):
    return (int(b['n'], 16) if b['n'] else int(b['d'])) + 1


def fix_one(src, m, pe, base):
    """Return (new_src, None) or (src, reason)."""
    fs = src.rfind('\nvoid sub_', 0, m.start())
    fe = src.find('\n}', m.end())
    body = src[fs:fe]
    reg = m['reg']
    near = src[src.rfind('\n', 0, src.rfind('\n', 0, m.start())):m.start()]   # the line before the jmp
    c = COPY.search(near)
    if c and c['dst'] == reg:      # `mov ecx, eax; jmp [ecx*4+T]` -- the guard tested eax
        reg = c['src']
    b = [x for x in BOUND.finditer(src, max(fs, m.start() - 3000), m.start()) if x['reg'] == reg]
    if not b:
        return src, 'no bound'
    cnt = bound_count(b[-1])
    if cnt > 512:
        return src, f'bound {cnt} too large'
    tbl = int(m['tbl'], 16)
    raw = pe.get_data(tbl - base, cnt * 4)
    tg = [struct.unpack_from('<I', raw, i * 4)[0] for i in range(cnt)]
    need = []
    for t in sorted(set(tg)):
        if re.search(r'^L_%08X:' % t, body, re.M):
            continue
        im = re.search(r'^[^\n]*/\* 0x%08X: ' % t, body, re.M)
        if not im:
            return src, f'target 0x{t:08X} is not in this function'
        need.append(fs + im.start())
    nl = '\r\n' if '\r\n' in body else '\n'
    ind = m['ind']
    cases = ' '.join(f'case {i}: goto L_{t:08X};' for i, t in enumerate(tg))
    rep = (f"{ind}switch ({m['reg']}) {{ /* reconstructed jump table 0x{tbl:X} */{nl}"
           f"{ind}    {cases}{nl}"
           f"{ind}    default: RECOMP_ITAIL(MEM32({m['reg']} * 4 + 0x{m['tbl']})); return;{nl}"
           f"{ind}}}{m['cmt']}")
    # edit back to front so earlier offsets stay valid
    edits = [(m.start(), m.end(), rep)]
    for off in need:
        addr = re.search(r'/\* 0x([0-9A-F]{8}): ', src[off:off + 400]).group(1)
        edits.append((off, off, f'L_{addr}:{nl}'))
    for s0, e0, txt in sorted(edits, key=lambda e: e[0], reverse=True):
        src = src[:s0] + txt + src[e0:]
    return src, None


def selftest():
    for line, n in (('    if (CMP_A(eax, 3)) goto L_004B2345;', 4), ('    if (CMP_A(ecx, 0x1Fu)) goto L_00400000;', 32),
                    ('    if (CMP_A(ecx, 8)) { RECOMP_ITAIL(0x00517D16u); return; } /* x */', 9)):
        assert bound_count(BOUND.search(line)) == n, line
    print('selftest ok')


def main(argv):
    if not argv:
        return selftest()
    dry = '--dry' in argv
    files = [a for a in argv if not a.startswith('--')]
    pe = pefile.PE(EXE, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    total = skipped = 0
    for path in files:
        src = open(path, encoding='latin-1', newline='').read()
        n, start = 0, 0
        while True:
            m = SITE.search(src, start)
            if not m:
                break
            new, why = fix_one(src, m, pe, base)
            if why:
                skipped += 1
                print(f'{path}: skip 0x{m["tbl"]}: {why}')
                start = m.end()
            else:
                n += 1
                start = new.find('reconstructed jump table 0x%X' % int(m['tbl'], 16), m.start() - 2000)
                src = new
        if n and not dry:
            open(path, 'w', encoding='latin-1', newline='').write(src)
        total += n
        print(f'{path}: {n} reconstructed')
    print(f'total {total} reconstructed, {skipped} skipped')


if __name__ == '__main__':
    main(sys.argv[1:])
