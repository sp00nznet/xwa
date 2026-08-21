"""
Find functions whose functions.json bounds CUT THEM IN HALF.

generate.py lifts each function over [start, next_start). When functions.json has a
bogus entry starting *inside* a real function, the owner gets lifted only up to that
point and the generated C just falls off the end -- `return; /* end of function */`
without the epilogue. The guest stack frame is then never released, so every caller's
locals shift by (frame + 4) bytes and the caller reads garbage. That is silent: no
crash at the leak, only later, somewhere unrelated.

sub_005960BE was one of these (0x190 frame + ret addr = 0x198 leaked into
sub_004418A0, which then wrote through a null texture record).

Detection: disassemble [start, end) linearly; if the LAST instruction is not a
terminator (ret / unconditional jmp / int3), the range ends mid-flow => truncated.

Usage: py -3.11 tools/find_truncated.py [--verbose]
Prints `0xSTART:0xTRUE_END` lines ready to feed to tools/relift_func.py.
"""
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = 'config/xwingalliance_decrypted.exe'
TERMINATORS = {'ret', 'retf', 'jmp', 'int3', 'ud2', 'iret'}


def load_sections(f):
    pe = struct.unpack('<I', f[0x3C:0x40])[0]
    nsec = struct.unpack('<H', f[pe + 6:pe + 8])[0]
    opt = struct.unpack('<H', f[pe + 20:pe + 22])[0]
    secs, off = [], pe + 24 + opt
    for i in range(nsec):
        e = f[off + i * 40:off + (i + 1) * 40]
        vsz, va, rsz, ptr = struct.unpack('<IIII', e[8:24])
        secs.append((va, max(vsz, rsz), ptr))
    return secs


def main():
    verbose = '--verbose' in sys.argv
    f = open(EXE, 'rb').read()
    secs = load_sections(f)

    def foff(va):
        rva = va - 0x400000
        for v, sz, p in secs:
            if v <= rva < v + sz:
                return p + (rva - v)
        return None

    funcs = sorted(int(x['address'], 16) for x in json.load(open('config/functions.json')))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    truncated = []

    for i, start in enumerate(funcs):
        end = funcs[i + 1] if i + 1 < len(funcs) else start + 0x40
        o = foff(start)
        if o is None or end <= start or end - start > 0x20000:
            continue
        insns = list(md.disasm(f[o:o + (end - start)], start))
        if not insns:
            continue
        if insns[-1].address + insns[-1].size != end:
            continue                       # bad decode, not our signature
        # strip inter-function ALIGNMENT padding (nop / int3) before judging the tail
        real = list(insns)
        while real and real[-1].mnemonic in ('nop', 'int3', 'lea'):
            if real[-1].mnemonic == 'lea' and 'e' not in real[-1].op_str:
                break
            if real[-1].mnemonic == 'lea':
                break                      # `lea reg,[reg+0]` padding only; keep real leas
            real.pop()
        if not real:
            continue
        last = real[-1]
        if last.mnemonic in TERMINATORS:
            continue                       # properly terminated

        # walk forward to the real terminator to report a usable end
        tail = f[foff(end):foff(end) + 0x4000]
        true_end, depth = None, 0
        for ins in md.disasm(tail, end):
            depth += 1
            if ins.mnemonic == 'ret':
                true_end = ins.address + ins.size
                break
            if depth > 3000:
                break
        truncated.append((start, end, true_end, last.mnemonic + ' ' + last.op_str))

    print(f'truncated functions (bounds cut mid-flow): {len(truncated)}\n')
    for start, end, true_end, lastins in truncated:
        te = f'0x{true_end:08X}' if true_end else '?'
        print(f'  0x{start:08X}:{te}   (json end 0x{end:08X}, last insn: {lastins})')
    if truncated:
        print('\nfeed to: py -3.11 tools/relift_func.py ' +
              ' '.join(f'0x{s:08X}:0x{t:08X}' for s, _, t, _ in truncated if t))


if __name__ == '__main__':
    main()
