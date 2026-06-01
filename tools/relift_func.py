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
    targets = [int(a, 16) for a in sys.argv[1:]]
    if not targets:
        print('usage: relift_func.py 0xADDR ...'); return
    funcs = json.load(open('config/functions.json'))
    all_addrs = sorted(f['address_int'] for f in funcs)
    info = analyze_pe(EXE); iat = build_iat_map(info)
    pe = open(EXE, 'rb').read()
    text = [s for s in info.sections if s.name == '.text'][0]
    code = pe[text.raw_offset: text.raw_offset + min(text.virtual_size, text.raw_size)]
    cs = code_start = info.code_start
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    lifter = Lifter(iat_map=iat, code_start=info.code_start, code_end=info.code_end)

    for addr in targets:
        nxt = [a for a in all_addrs if a > addr]
        func_end = min(nxt[0], addr + 65536) if nxt else min(info.code_end, addr + 65536)
        instrs, leaders, switches = linear_disassemble_function(md, code, code_start, addr, func_end)
        if not instrs:
            print(f'0x{addr:08X}: no instructions'); continue
        trimmed = []; seen_ret = False
        for ins in instrs:
            if ins.mnemonic == 'int3': break
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
            src = open(path, encoding='utf-8', errors='replace').read()
            m = re.search(r'^void ' + re.escape(name) + r'\(void\) \{', src, re.M)
            if not m: continue
            # find matching closing brace at column 0
            end = src.find('\n}\n', m.start())
            if end < 0: end = src.find('\n}', m.start())
            end = src.find('}', end) + 1
            old = src[m.start():end]
            src2 = src[:m.start()] + new_code + src[end:]
            open(path, 'w', encoding='utf-8').write(src2)
            print(f'0x{addr:08X} ({name}) patched in recomp_{i:04d}.c  switches_reconstructed={nsw}')
            patched = True
            break
        if not patched:
            print(f'0x{addr:08X}: function not found in any gen file')

if __name__ == '__main__':
    main()
