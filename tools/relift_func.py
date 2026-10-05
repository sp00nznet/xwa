"""
Re-lift specific functions with the current lifter (incl. switch-table
reconstruction) and patch them into their existing gen file, in place.

Use for functions in the manual-fix files 0001-0005 that are PURELY lifted
(no native replacement) and need the switch reconstruction applied. Do NOT use
on native-replacement functions (sub_0052AD30 fopen, sub_0059AE30 fgets,
sub_0059D6A0 fscanf, sub_00564C50 .lst loader, etc.) — those are intentional.

Usage: py -3.11 tools/relift_func.py 0x0059F450 0x00563820 0x005241B0
"""
import sys, os, re, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.pe_analyze import analyze_pe, build_iat_map
from tools.lifter import Lifter
from tools.generate import linear_disassemble_function, lift_function_linear
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = 'config/xwingalliance_decrypted.exe'
GEN = 'src/game/recomp/gen'

def main():
    # Each arg is 0xADDR (auto func_end = next function) or 0xADDR:0xEND to force an
    # explicit end — needed when functions.json wrongly splits one real function into
    # several (internal jumps to the split-off tail otherwise become leaking ITAILs).
    targets = []
    for a in sys.argv[1:]:
        if ':' in a:
            s, e = a.split(':'); targets.append((int(s, 16), int(e, 16)))
        else:
            targets.append((int(a, 16), None))
    if not targets:
        print('usage: relift_func.py 0xADDR[:0xEND] ...'); return
    funcs = json.load(open('config/functions.json'))
    all_addrs = sorted(f['address_int'] for f in funcs)
    info = analyze_pe(EXE); iat = build_iat_map(info)
    pe = open(EXE, 'rb').read()
    text = [s for s in info.sections if s.name == '.text'][0]
    code = pe[text.raw_offset: text.raw_offset + min(text.virtual_size, text.raw_size)]
    cs = code_start = info.code_start
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    lifter = Lifter(iat_map=iat, code_start=info.code_start, code_end=info.code_end)

    for addr, end_override in targets:
        if end_override is not None:
            func_end = end_override
        else:
            nxt = [a for a in all_addrs if a > addr]
            func_end = min(nxt[0], addr + 65536) if nxt else min(info.code_end, addr + 65536)
        instrs, leaders, switches = linear_disassemble_function(md, code, code_start, addr, func_end)
        if not instrs:
            print(f'0x{addr:08X}: no instructions'); continue
        trimmed = []; seen_ret = False
        for ins in instrs:
            # int3 terminates the current run (it's padding, or a 0xCC byte a `je +1`
            # skips over). Don't break — real blocks may follow that are only reachable
            # via a forward jcc (their jumps would otherwise leak as ITAILs). Resume at
            # the next basic-block leader.
            if ins.mnemonic == 'int3':
                seen_ret = True
                continue
            if seen_ret:
                if ins.address not in leaders: continue
                seen_ret = False
            trimmed.append(ins)
            if ins.is_ret: seen_ret = True
        name = f'sub_{addr:08X}'
        lifter._flag_state = None
        new_code = lift_function_linear(lifter, name, trimmed, leaders, addr, switches)
        nsw = new_code.count('reconstructed jump table')
        # find the gen file containing this function and replace the body
        patched = False
        for i in range(6):
            path = os.path.join(GEN, f'recomp_{i:04d}.c')
            if not os.path.exists(path): continue
            src = open(path, encoding='latin-1', newline='').read()
            m = re.search(r'^void ' + re.escape(name) + r'\(void\) \{', src, re.M)
            if not m: continue
            if '}' in src[m.end():src.find('\n', m.end())]:
                print(f'0x{addr:08X}: one-line stub (merged by a func-split fix) -- not relifting'); patched = True; break
            # find matching closing brace at column 0
            end = src.find('\n}\n', m.start())
            if end < 0: end = src.find('\n}', m.start())
            end = src.find('}', end) + 1
            old = src[m.start():end]
            src2 = src[:m.start()] + new_code + src[end:]
            open(path, 'w', encoding='latin-1', newline='').write(src2)
            print(f'0x{addr:08X} ({name}) patched in recomp_{i:04d}.c  switches_reconstructed={nsw}')
            patched = True
            break
        if not patched and add_new:
            add_function(name, addr, new_code)
            print(f'0x{addr:08X} ({name}) ADDED to {os.path.basename(ADDED)}  switches_reconstructed={nsw}')
        elif not patched:
            print(f'0x{addr:08X}: function not found in any gen file')


ADDED = os.path.join(GEN, 'recomp_added.c')   # functions functions.json never had (handler-table targets)


def add_function(name, addr, code):
    """Append a function functions.json missed: its body to recomp_added.c, a prototype to
    recomp_funcs.h, and a dispatch entry (sorted -- recomp_lookup is a binary search)."""
    if not os.path.exists(ADDED):
        open(ADDED, 'w', encoding='latin-1', newline='').write(
            '/* Functions functions.json missed, lifted by tools/relift_func.py --new */\n\n'
            '#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "recomp_funcs.h"\n'
            'extern void xwa_batch_check(const char*);\n#include <math.h>\n#include <string.h>\n\n')
    open(ADDED, 'a', encoding='latin-1', newline='').write(code + '\n\n')
    hdr = os.path.join(GEN, 'recomp_funcs.h')
    h = open(hdr, encoding='latin-1', newline='').read()
    proto = f'void {name}(void);  /* 0x{addr:08X} */\n'
    if proto not in h:
        i = h.rfind('void sub_')
        i = h.find('\n', i) + 1
        open(hdr, 'w', encoding='latin-1', newline='').write(h[:i] + proto + h[i:])
    dp = os.path.join(GEN, 'recomp_dispatch.c')
    d = open(dp, encoding='latin-1', newline='').read()
    if f'{{ 0x{addr:08X}u, {name} }}' in d:
        return
    rows = list(re.finditer(r'^    \{ 0x([0-9A-F]{8})u, sub_[0-9A-F]{8} \},\n', d, re.M))
    after = [r for r in rows if int(r[1], 16) > addr]
    at = after[0].start() if after else rows[-1].end()
    d = d[:at] + f'    {{ 0x{addr:08X}u, {name} }},\n' + d[at:]
    d = re.sub(r'recomp_dispatch_count = (\d+);', lambda m: f'recomp_dispatch_count = {int(m[1]) + 1};', d)
    open(dp, 'w', encoding='latin-1', newline='').write(d)


if __name__ == '__main__':
    add_new = '--new' in sys.argv
    sys.argv = [a for a in sys.argv if a != '--new']
    main()
