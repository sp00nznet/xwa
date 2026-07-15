"""Fix TEST+JBE/JA code generation bug in recomp output files.

After a TEST instruction, CF is always 0. So:
  TEST + JBE (CF=1 or ZF=1) => only ZF matters => TEST_Z
  TEST + JA  (CF=0 and ZF=0) => only ZF matters => TEST_NZ
  
Bug: generator emits CMP_BE (unsigned <=) and CMP_A (unsigned >) which
compare the register to itself, always returning true/false respectively.
"""
import re, os, sys

GEN_DIR = os.path.join(os.path.dirname(__file__), "src", "game", "recomp", "gen")

fixes = 0
files_fixed = 0

for fname in sorted(os.listdir(GEN_DIR)):
    if not fname.endswith(".c"):
        continue
    fpath = os.path.join(GEN_DIR, fname)
    with open(fpath, "r") as f:
        lines = f.readlines()
    
    changed = False
    i = 0
    while i < len(lines) - 1:
        line = lines[i]
        next_line = lines[i + 1]
        
        # Check if current line is a TEST comment
        if "/* test " in line.lower() or "/* test\t" in line.lower():
            # Check next line for CMP_BE(X, X) pattern
            m = re.search(r'CMP_BE\(([^,]+),\s*\1\)', next_line)
            if m:
                arg = m.group(1)
                old = f'CMP_BE({arg}, {arg})'
                new = f'TEST_Z({arg}, {arg})'
                lines[i + 1] = next_line.replace(old, new)
                changed = True
                fixes += 1
                i += 2
                continue
            
            # Check next line for CMP_A(X, X) pattern  
            m = re.search(r'CMP_A\(([^,]+),\s*\1\)', next_line)
            if m:
                arg = m.group(1)
                old = f'CMP_A({arg}, {arg})'
                new = f'TEST_NZ({arg}, {arg})'
                lines[i + 1] = next_line.replace(old, new)
                changed = True
                fixes += 1
                i += 2
                continue
        i += 1
    
    if changed:
        with open(fpath, "w") as f:
            f.writelines(lines)
        files_fixed += 1
        print(f"  Fixed {fname}")

print(f"\nTotal: {fixes} fixes across {files_fixed} files")
