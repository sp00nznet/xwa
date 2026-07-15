"""Fix repne scasb and repe cmpsb code generation bug.

On x86, string scan/compare operations ALWAYS advance pointers and decrement ECX,
even on the iteration where the condition terminates. The old code had the advance
inside the while-condition loop body, causing it to skip the final advance.
"""
import os, sys

GEN_DIR = os.path.join(os.path.dirname(__file__), "src", "game", "recomp", "gen")

# Old patterns -> new patterns
REPLACEMENTS = [
    # repne scasb: old while loop -> new do-style loop
    (
        "{ while (ecx && LO8(eax) != MEM8(edi)) { edi += _df; ecx--; } }",
        "{ while (ecx) { int _m = (LO8(eax) == MEM8(edi)); edi += _df; ecx--; if (_m) break; } }"
    ),
    # repe cmpsb: old while loop -> new do-style loop 
    (
        "{ while (ecx && MEM8(esi) == MEM8(edi)) { esi += _df; edi += _df; ecx--; } }",
        "{ while (ecx) { int _m = (MEM8(esi) != MEM8(edi)); esi += _df; edi += _df; ecx--; if (_m) break; } }"
    ),
]

total_fixes = 0
for fname in sorted(os.listdir(GEN_DIR)):
    if not fname.endswith(".c"):
        continue
    fpath = os.path.join(GEN_DIR, fname)
    with open(fpath, "r") as f:
        content = f.read()
    
    file_fixes = 0
    for old, new in REPLACEMENTS:
        count = content.count(old)
        if count > 0:
            content = content.replace(old, new)
            file_fixes += count
    
    if file_fixes:
        with open(fpath, "w") as f:
            f.write(content)
        print(f"  {fname}: {file_fixes} fixes")
        total_fixes += file_fixes

print(f"\nTotal: {total_fixes} string operation fixes")
