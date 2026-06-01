import re, glob

REGS = r'(eax|ebx|ecx|edx|esi|edi|ebp)'
asm_re = re.compile(r'/\*\s*0x([0-9A-Fa-f]+):\s*([a-z]+)\s*(.*?)\s*\*/\s*$')
cond_re = re.compile(r'if\s*\(((?:TEST|CMP)_\w+)\(([^)]*)\)\)')
label_re = re.compile(r'^\s*L_[0-9A-Fa-f]+:')
NEUTRAL = {'mov','lea','movzx','movsx','push','pop','nop'}

def reg_written(mnem, ops):
    if mnem in ('mov','lea','movzx','movsx','pop'):
        m = re.match(r'\s*'+REGS+r'\b', ops)
        return m.group(1) if m else None
    return None

total = 0
for path in sorted(glob.glob('src/game/recomp/gen/recomp_000[1-5].c')):
    lines = open(path, encoding='utf-8', errors='replace').split('\n') if False else open(path, encoding='utf-8', errors='replace').read().split('\n')
    edits = []  # (test_line_idx, cond_line_idx, reg, addr)
    for i, ln in enumerate(lines):
        a = asm_re.search(ln)
        if not a or a.group(2) != 'test': continue
        mt = re.match(REGS+r',\s*'+REGS+r'$', a.group(3).strip())
        if not mt or mt.group(1) != mt.group(2): continue
        reg = mt.group(1); taddr = a.group(1)
        reloaded = False
        for j in range(i+1, min(i+20, len(lines))):
            l2 = lines[j]
            if label_re.match(l2): break
            c = cond_re.search(l2)
            if c:
                ops = c.group(2)
                if reloaded and re.search(r'\b'+reg+r'\b', ops) and ('_old' not in ops):
                    edits.append((i, j, reg, taddr))
                break
            a2 = asm_re.search(l2)
            if a2:
                mn = a2.group(2)
                if mn not in NEUTRAL and not mn.startswith('j'): break
                if reg_written(mn, a2.group(3)) == reg: reloaded = True
    if not edits: continue
    # apply from bottom to top so indices stay valid; insert save after test line, edit cond
    for (ti, ci, reg, taddr) in sorted(edits, reverse=True):
        var = f"_oldf_{taddr}"
        cond = lines[ci]
        m = cond_re.search(cond)
        new_ops = re.sub(r'\b'+reg+r'\b', var, m.group(2))
        lines[ci] = cond[:m.start()] + f"if ({m.group(1)}({new_ops}))" + cond[m.end():]
        indent = re.match(r'^(\s*)', lines[ti]).group(1)
        lines.insert(ti+1, f"{indent}uint32_t {var} = {reg}; /* fix: save flag operand before reload (test-after-reload) */")
        total += 1
    open(path, 'w', encoding='utf-8').write('\n'.join(lines))
    print(f"patched {len(edits)} in {path.split('/')[-1]}")
print(f"TOTAL patched: {total}")
