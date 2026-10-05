"""Real extent of a function, by walking its control flow in the decrypted exe.

functions.json splits some functions at addresses that are only branch targets (or even at the
final `ret`), so "next function start" is not the end. This follows every branch from START --
conditional and unconditional jumps, `jmp [reg*4 + table]` switches bounded by the usual
`cmp reg, N; ja` -- stopping at ret / jmps that leave the window, and prints START:END where END
is one past the highest instruction reached. Feed the result to tools/relift_func.py.

    python tools/func_extent.py 0x004B9220 [0x... ...]
"""
import struct
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

EXE = 'config/xwingalliance_decrypted.exe'
WINDOW = 0x8000          # a jump further than this from START is a tail call, not a branch


class Image:
    def __init__(self, path=EXE):
        pe = pefile.PE(path, fast_load=True)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        t = [s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text'][0]
        self.lo = self.base + t.VirtualAddress
        self.code = t.get_data()
        self.pe = pe
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True

    def insn(self, va):
        off = va - self.lo
        return next(self.cs.disasm(self.code[off:off + 16], va), None)

    def dword(self, va):
        return self.pe.get_dword_at_rva(va - self.base)


def extent(img, start):
    seen, work, prev = set(), [start], {}
    hi = start
    while work:
        va = work.pop()
        while va not in seen:
            i = img.insn(va)
            if i is None:
                break
            seen.add(va)
            hi = max(hi, va + i.size)
            m = i.mnemonic
            if m in ('ret', 'retn', 'int3', 'hlt'):
                break
            if m == 'jmp' or (m.startswith('j') and m != 'jmp'):
                op = i.operands[0]
                if op.type == X86_OP_IMM:
                    t = op.imm
                    if abs(t - start) < WINDOW:
                        work.append(t)
                elif op.type == X86_OP_MEM and op.mem.scale == 4 and op.mem.base == 0 and op.mem.disp:
                    n = bound(img, prev.get(va))
                    for k in range(n):
                        t = img.dword(op.mem.disp + 4 * k)
                        if abs(t - start) < WINDOW:
                            work.append(t)
                        hi = max(hi, op.mem.disp + 4 * n)   # the table lives inside the function
                if m == 'jmp':
                    break
            nxt = va + i.size
            prev[nxt] = va
            va = nxt
    return hi


def bound(img, va, back=6):
    """Entries of a switch table: the `cmp reg, N` before the `ja` guarding the jmp."""
    for _ in range(back):
        if va is None:
            return 0
        i = img.insn(va)
        if i and i.mnemonic == 'cmp' and i.operands[1].type == X86_OP_IMM:
            return i.operands[1].imm + 1
        va = _prev_guess(img, va)
    return 0


def _prev_guess(img, va):
    for size in range(1, 8):
        i = img.insn(va - size)
        if i and i.size == size:
            return va - size
    return None


def main(argv):
    img = Image()
    for a in argv:
        s = int(a, 16)
        print(f'0x{s:08X}:0x{extent(img, s):08X}')


if __name__ == '__main__':
    main(sys.argv[1:])
