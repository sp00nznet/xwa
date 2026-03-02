"""
Regenerate ONLY recomp_0000.c + rebuild dispatch table and function header.
Does NOT touch files 0001-0005 (which have manual fixes applied).
"""

import sys
import os
import re
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.pe_analyze import analyze_pe, build_iat_map
from tools.lifter import Lifter
from tools.generate import (
    LinearInstruction, find_entries, linear_disassemble_function,
    lift_function_linear, COND_JUMPS
)
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def main():
    exe_path = 'config/xwingalliance_decrypted.exe'
    output_dir = 'src/game/recomp/gen'
    functions_json = 'config/functions.json'

    # Load known functions
    with open(functions_json, 'r') as f:
        known_funcs = json.load(f)
    known_addrs = set(func['address_int'] for func in known_funcs)
    print(f'[*] {len(known_funcs)} functions in functions.json', flush=True)

    # Find which functions are in files 0001-0005 (scan existing files)
    existing_funcs = set()
    for i in range(1, 6):
        filepath = os.path.join(output_dir, f'recomp_{i:04d}.c')
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                for line in f:
                    m = re.match(r'^void (sub_([0-9A-Fa-f]{8}))\(void\)', line)
                    if m:
                        addr = int(m.group(2), 16)
                        existing_funcs.add(addr)
    print(f'[*] {len(existing_funcs)} functions in files 0001-0005', flush=True)

    # Functions needed for file 0000
    needed = sorted(addr for addr in known_addrs if addr not in existing_funcs)
    print(f'[*] {len(needed)} functions needed for recomp_0000.c', flush=True)

    if not needed:
        print('[!] No functions needed - nothing to do')
        return

    # Load PE
    print(f'[*] Loading PE: {exe_path}', flush=True)
    info = analyze_pe(exe_path)
    iat_map = build_iat_map(info)

    with open(exe_path, 'rb') as f:
        pe_data = f.read()

    code_start = info.code_start
    code_end = info.code_end
    text_sect = [s for s in info.sections if s.name == '.text'][0]
    offset = text_sect.raw_offset
    size = min(text_sect.virtual_size, text_sect.raw_size)
    code_data = pe_data[offset:offset + size]
    print(f'[*] Code: 0x{code_start:08X}-0x{code_end:08X} ({len(code_data):,} bytes)', flush=True)

    # Build complete entry list for boundary detection
    all_known = sorted(known_addrs)

    # Disassemble + lift
    print('[*] Disassembling and lifting...', flush=True)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lifter = Lifter(iat_map=iat_map, code_start=code_start, code_end=code_end)

    chunk_funcs = []
    error_count = 0
    start = time.time()

    for idx_in_needed, addr in enumerate(needed):
        # Find function end = next known function address or code end
        next_addrs = [a for a in all_known if a > addr]
        if next_addrs:
            func_end = min(next_addrs[0], addr + 65536)
        else:
            func_end = min(code_end, addr + 65536)

        if func_end - addr < 2:
            continue

        name = f'sub_{addr:08X}'

        try:
            instructions, leaders = linear_disassemble_function(
                md, code_data, code_start, addr, func_end)

            if not instructions:
                # Stub it
                stub = f'void {name}(void) {{ /* empty function */ }}\n'
                chunk_funcs.append((stub, addr, name))
                continue

            # Trim: stop at first int3, and skip garbage after ret
            trimmed = []
            seen_ret = False
            for insn in instructions:
                if insn.mnemonic == 'int3':
                    break
                if seen_ret:
                    if insn.address not in leaders:
                        continue
                    seen_ret = False
                trimmed.append(insn)
                if insn.is_ret:
                    seen_ret = True

            if not trimmed:
                stub = f'void {name}(void) {{ /* no valid instructions */ }}\n'
                chunk_funcs.append((stub, addr, name))
                continue

            code = lift_function_linear(lifter, name, trimmed, leaders, addr)
            chunk_funcs.append((code, addr, name))

        except Exception as e:
            stub = f'/* ERROR: {name} at 0x{addr:08X}: {e} */\nvoid {name}(void) {{ /* error */ }}\n'
            chunk_funcs.append((stub, addr, name))
            error_count += 1

        if (idx_in_needed + 1) % 50 == 0:
            elapsed = time.time() - start
            rate = (idx_in_needed + 1) / elapsed if elapsed > 0 else 0
            print(f'[*] {idx_in_needed + 1}/{len(needed)} functions ({rate:.0f}/s, {error_count} err)',
                  flush=True)

    # Write recomp_0000.c
    filepath = os.path.join(output_dir, 'recomp_0000.c')
    addr_min = needed[0] if needed else 0
    addr_max = needed[-1] if needed else 0
    with open(filepath, 'w') as f:
        f.write('/* Auto-generated by XWA recompiler - DO NOT EDIT */\n')
        f.write(f'/* Functions 0 to {len(chunk_funcs) - 1} */\n')
        f.write(f'/* Address range: 0x{addr_min:08X} - 0x{addr_max:08X} */\n\n')
        f.write('#define RECOMP_GENERATED_CODE\n')
        f.write('#include "recomp_types.h"\n')
        f.write('#include "recomp_funcs.h"\n')
        f.write('#include <math.h>\n')
        f.write('#include <string.h>\n\n')
        for code, addr, name in chunk_funcs:
            f.write(code)
            f.write('\n\n')

    print(f'[*] Wrote {filepath}: {len(chunk_funcs)} functions', flush=True)

    # Now rebuild dispatch table and header from ALL functions
    print('[*] Rebuilding dispatch table and function header...', flush=True)

    all_entries = []
    for func in known_funcs:
        addr = func['address_int']
        name = func['name']
        all_entries.append((addr, name))

    # Sort by address
    all_entries.sort(key=lambda x: x[0])

    # Write header
    header_path = os.path.join(output_dir, 'recomp_funcs.h')
    with open(header_path, 'w') as f:
        f.write('/* Auto-generated function declarations - DO NOT EDIT */\n')
        f.write('#pragma once\n\n')
        f.write('#include <stdint.h>\n\n')
        f.write(f'/* {len(all_entries)} recompiled functions */\n\n')
        for addr, name in all_entries:
            f.write(f'void {name}(void);  /* 0x{addr:08X} */\n')

    # Write dispatch table
    dispatch_path = os.path.join(output_dir, 'recomp_dispatch.c')
    with open(dispatch_path, 'w') as f:
        f.write('/* Auto-generated dispatch table - DO NOT EDIT */\n\n')
        f.write('#include "recomp_types.h"\n')
        f.write('#include "recomp_funcs.h"\n\n')
        f.write('const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n')
        for addr, name in all_entries:
            f.write(f'    {{ 0x{addr:08X}u, {name} }},\n')
        f.write('};\n\n')
        f.write(f'const uint32_t recomp_dispatch_count = {len(all_entries)};\n')

    elapsed = time.time() - start
    file_size = os.path.getsize(filepath)
    print(f'\n[*] === COMPLETE ===', flush=True)
    print(f'[*] {len(chunk_funcs)} functions in recomp_0000.c ({file_size / 1048576:.1f} MB)', flush=True)
    print(f'[*] {len(all_entries)} functions in dispatch table', flush=True)
    print(f'[*] {error_count} errors', flush=True)
    print(f'[*] Time: {elapsed:.1f}s', flush=True)


if __name__ == '__main__':
    main()
