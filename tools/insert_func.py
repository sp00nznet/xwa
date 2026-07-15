"""Lift a single MISSING function (not yet in any gen file) and insert it:
   - function body into the gen file that holds the preceding function
   - prototype into recomp_funcs.h
   - dispatch entry into recomp_dispatch.c
Usage: py tools/insert_func.py 0x004D3130:0x004D33D0
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
    a = sys.argv[1]
    if ':' in a:
        s, e = a.split(':'); addr, func_end = int(s, 16), int(e, 16)
    else:
        addr, func_end = int(a, 16), None
    funcs = json.load(open('config/functions.json'))
    all_addrs = sorted(f['address_int'] for f in funcs)
    if func_end is None:
        nxt = [x for x in all_addrs if x > addr]
        func_end = nxt[0] if nxt else addr + 65536
    info = analyze_pe(EXE); iat = build_iat_map(info)
    pe = open(EXE, 'rb').read()
    text = [s for s in info.sections if s.name == '.text'][0]
    code = pe[text.raw_offset: text.raw_offset + min(text.virtual_size, text.raw_size)]
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    lifter = Lifter(iat_map=iat, code_start=info.code_start, code_end=info.code_end)

    instrs, leaders, switches = linear_disassemble_function(md, code, info.code_start, addr, func_end)
    trimmed = []; seen_ret = False
    for ins in instrs:
        if ins.mnemonic == 'int3':
            seen_ret = True; continue
        if seen_ret:
            if ins.address not in leaders: continue
            seen_ret = False
        trimmed.append(ins)
        if ins.is_ret: seen_ret = True
    name = f'sub_{addr:08X}'
    lifter._flag_state = None
    new_code = lift_function_linear(lifter, name, trimmed, leaders, addr, switches)

    # insert body: place right before the next function def in whichever gen file has it
    nxt_name = None
    for x in all_addrs:
        if x > addr:
            nxt_name = f'sub_{x:08X}'; break
    inserted = False
    for i in range(6):
        path = os.path.join(GEN, f'recomp_{i:04d}.c')
        if not os.path.exists(path): continue
        src = open(path, encoding='utf-8', errors='replace').read()
        m = re.search(r'^void ' + re.escape(nxt_name) + r'\(void\) \{', src, re.M)
        if not m: continue
        src2 = src[:m.start()] + new_code + '\n' + src[m.start():]
        open(path, 'w', encoding='utf-8').write(src2)
        print(f'{name}: body inserted before {nxt_name} in recomp_{i:04d}.c')
        inserted = True
        break
    if not inserted:
        print(f'{name}: could not find {nxt_name} in any gen file'); return

    # prototype
    hp = os.path.join(GEN, 'recomp_funcs.h')
    h = open(hp, encoding='utf-8', errors='replace').read()
    proto = f'void {name}(void);'
    if proto not in h:
        anchor = f'void {nxt_name}(void);'
        if anchor in h:
            h = h.replace(anchor, proto + '\n' + anchor, 1)
        else:
            h = re.sub(r'(#endif\s*)$', proto + '\n' + r'\1', h, 1)
        open(hp, 'w', encoding='utf-8').write(h)
        print(f'{name}: prototype added')

    # dispatch entry
    dp = os.path.join(GEN, 'recomp_dispatch.c')
    d = open(dp, encoding='utf-8', errors='replace').read()
    entry = f'    {{ 0x{addr:08X}u, {name} }},'
    if entry.strip() not in d:
        anchor = f'{{ 0x{ (all_addrs[all_addrs.index(min(x for x in all_addrs if x>addr))]) :08X}u,'
        # insert before the next-address entry to keep sorted
        m = re.search(r'^\s*\{ 0x' + f'{min(x for x in all_addrs if x>addr):08X}' + r'u,', d, re.M)
        if m:
            d = d[:m.start()] + entry + '\n' + d[m.start():]
        else:
            d = d.replace('};', entry + '\n};', 1)
        open(dp, 'w', encoding='utf-8').write(d)
        print(f'{name}: dispatch entry added')

    # register in functions.json so future tooling knows about it
    funcs.append({'address': f'0x{addr:08X}', 'address_int': addr,
                  'name': name, 'num_instructions': len(trimmed)})
    json.dump(funcs, open('config/functions.json', 'w'), indent=1)
    print(f'{name}: added to functions.json ({len(trimmed)} instrs, switches={new_code.count("reconstructed jump table")})')

if __name__ == '__main__':
    main()
