#!/usr/bin/env python3
"""Rewrite pop-arithmetic in already-generated code.

The lifter emitted `fOPp st(i), st(0)` as if i were always 1, and had the
subtract and divide directions reversed on top of that. tools/lifter.py is
fixed, but src/game/recomp/gen/ is not regenerated on every change (it carries
hand-applied fixes), and every generated line names its guest instruction in a
trailing comment -- so the same correction applies in place.

Only lines that still carry the exact buggy emission are touched; anything
hand-edited is left alone and reported.

    py -3 tools/fix_fpu_pop.py [--check]
"""
import glob, os, re, sys

CHECK = '--check' in sys.argv

# mnemonic -> (old body with _st[0], new body as a format over the real dest)
FORMS = {
    'faddp':  ('_st[0] += _v;',              '{d} += _v;'),
    'fsubp':  ('_st[0] = _v - _st[0];',      '{d} -= _v;'),
    'fsubrp': ('_st[0] -= _v;',              '{d} = _v - {d};'),
    'fmulp':  ('_st[0] *= _v;',              '{d} *= _v;'),
    'fdivp':  ('_st[0] = _v / _st[0];',      '{d} /= _v;'),
    'fdivrp': ('_st[0] /= _v;',              '{d} = _v / {d};'),
}
LINE = re.compile(r'^(\s*)\{ double _v = fp_pop\(\); (.+?) \}'
                  r' (/\* 0x[0-9A-F]{8}: (faddp|fsubp|fsubrp|fmulp|fdivp|fdivrp) st\((\d)\) \*/)\s*$')

root = os.path.join(os.path.dirname(__file__), '..', 'src', 'game', 'recomp', 'gen')
fixed = skipped = already = 0
for path in sorted(glob.glob(os.path.join(root, 'recomp_*.c'))):
    out, dirty = [], False
    for line in open(path, encoding='utf-8', errors='surrogateescape').read().split('\n'):
        m = LINE.match(line)
        if not m:
            out.append(line); continue
        indent, body, comment, mnem, idx = m.groups()
        old, new = FORMS[mnem]
        dest = f'_st[{max(int(idx) - 1, 0)}]'
        want = new.format(d=dest)
        if body == want:
            already += 1; out.append(line); continue
        if body != old:
            skipped += 1
            print(f'  skip (hand-edited): {comment}  body={body!r}')
            out.append(line); continue
        out.append(f'{indent}{{ double _v = fp_pop(); {want} }} {comment}')
        fixed += 1; dirty = True
    if dirty and not CHECK:
        open(path, 'w', encoding='utf-8', errors='surrogateescape').write('\n'.join(out))

print(f'{"would fix" if CHECK else "fixed"}: {fixed}   already correct: {already}   skipped: {skipped}')
