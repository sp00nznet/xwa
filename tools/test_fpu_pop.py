#!/usr/bin/env python3
"""Pop-arithmetic lifts to the register it names, in the direction it names.

`fOPp st(i), st(0)` computes into ST(i) and then pops, so the result lands at
index i-1 once the stack has shifted -- and fsubp/fdivp are ST(i) OP ST(0),
while the r-forms are ST(0) OP ST(i). Both were wrong here: the index was
ignored and the directions were swapped. XWA's 3D math uses `fsubp st(3)`.

    py -3 tools/test_fpu_pop.py
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from tools.lifter import Lifter

md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True

# encoding                      expected C fragment
CASES = [
    (b'\xDE\xC1', 'faddp st(1)',  '_st[0] += _v'),
    (b'\xDE\xC3', 'faddp st(3)',  '_st[2] += _v'),
    (b'\xDE\xE9', 'fsubp st(1)',  '_st[0] -= _v'),
    (b'\xDE\xEB', 'fsubp st(3)',  '_st[2] -= _v'),
    (b'\xDE\xE1', 'fsubrp st(1)', '_st[0] = _v - _st[0]'),
    (b'\xDE\xC9', 'fmulp st(1)',  '_st[0] *= _v'),
    (b'\xDE\xCD', 'fmulp st(5)',  '_st[4] *= _v'),
    (b'\xDE\xF9', 'fdivp st(1)',  '_st[0] /= _v'),
    (b'\xDE\xF1', 'fdivrp st(1)', '_st[0] = _v / _st[0]'),
]

lifter = Lifter()
bad = 0
for code, what, want in CASES:
    insn = next(md.disasm(code, 0x401000))
    out = ' '.join(lifter.lift_instruction(insn))
    if want not in out:
        print(f'FAIL {what}: want {want!r}\n     got  {out}')
        bad += 1
    else:
        print(f'ok   {what}  ->  {want}')

# The pop happens before the destination is read, so the destination index is
# relative to the SHIFTED stack: fsubp st(1) must land on _st[0], not _st[1].
assert '_st[1] -=' not in ' '.join(lifter.lift_instruction(next(md.disasm(b'\xDE\xE9', 0x401000))))
print('FAIL' if bad else 'PASS', f'({len(CASES)-bad}/{len(CASES)})')
sys.exit(1 if bad else 0)
