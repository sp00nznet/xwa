import re, glob

# Sweeps the generated C for "test-after-reload" codegen bugs: a flag-setting
# instruction (test/cmp) whose operand register is RELOADED by a neutral op
# (mov/lea/movzx/movsx/pop) before the dependent jcc, so the emitted condition
# reads the WRONG (reloaded) value instead of the value at the cmp/test.
# Handles both `test REG,REG` and `cmp REGA,REGB` / `cmp REG,imm`.

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

def operand_regs(mnem, operand):
    """Return the set of register operands that feed the flags."""
    operand = operand.strip()
    mt = re.match(REGS+r',\s*'+REGS+r'$', operand)
    if mt:
        if mnem == 'test' and mt.group(1) != mt.group(2):
            return None  # only test REG,REG (self) is the simple case
        return {mt.group(1), mt.group(2)}
    if mnem == 'cmp':
        mi = re.match(REGS+r',', operand)
        if mi:
            return {mi.group(1)}
    return None

total = 0
for path in sorted(glob.glob('src/game/recomp/gen/recomp_000[1-5].c')):
    lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    edits = []  # (cmp_line_idx, cond_line_idx, [regs_to_save], addr)
    for i, ln in enumerate(lines):
        a = asm_re.search(ln)
        if not a or a.group(2) not in ('test', 'cmp'): continue
        opregs = operand_regs(a.group(2), a.group(3))
        if not opregs: continue
        reloaded = set()
        for j in range(i+1, min(i+20, len(lines))):
            l2 = lines[j]
            if label_re.match(l2): break
            c = cond_re.search(l2)
            if c:
                ops = c.group(2)
                hit = [r for r in reloaded if re.search(r'\b'+r+r'\b', ops)]
                if hit and ('_oldf' not in ops):
                    edits.append((i, j, hit, a.group(1)))
                break
            a2 = asm_re.search(l2)
            if a2:
                mn = a2.group(2)
                if mn not in NEUTRAL and not mn.startswith('j'): break
                w = reg_written(mn, a2.group(3))
                if w in opregs: reloaded.add(w)
    if not edits: continue
    # apply bottom-to-top so earlier indices stay valid
    for (ti, ci, regs, taddr) in sorted(edits, reverse=True):
        cond = lines[ci]
        m = cond_re.search(cond)
        new_ops = m.group(2)
        for reg in regs:
            new_ops = re.sub(r'\b'+reg+r'\b', f"_oldf_{taddr}_{reg}", new_ops)
        lines[ci] = cond[:m.start()] + f"if ({m.group(1)}({new_ops}))" + cond[m.end():]
        indent = re.match(r'^(\s*)', lines[ti]).group(1)
        for reg in regs:
            lines.insert(ti+1, f"{indent}uint32_t _oldf_{taddr}_{reg} = {reg}; /* fix: save flag operand before reload (test-after-reload) */")
        total += 1
    open(path, 'w', encoding='utf-8').write('\n'.join(lines))
    print(f"patched {len(edits)} in {path.split('/')[-1]}")
print(f"TOTAL patched: {total}")
