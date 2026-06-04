"""
Fix the function-split codegen bug class.

functions.json sometimes splits ONE real function into several entries. Internal
jumps across the bogus boundary become unresolved RECOMP_ITAIL -> broken control
flow. This sweeps the gen for RECOMP_ITAIL(0xFIXED) whose target lands mid-another
function (= a split), then MERGES the caller-free split-off pieces back into the
owner: re-lifts the owner over the full range (ITAILs -> gotos), removes the dead
pieces (adding no-op ICALL-table stubs), and drops them from functions.json.

Safety: a piece G is merged ONLY if it has no real callers -- no RECOMP_CALL(sub_G)
and its address never appears as a pointer/callback (push/registration) in the gen.
Pieces with callers are left alone (their ITAIL may be a legit tail-call).

Usage: py -3.11 tools/fix_func_splits.py [--apply] [--lo 0xADDR --hi 0xADDR]
"""
import sys, os, re, json, glob, bisect
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.pe_analyze import analyze_pe, build_iat_map
from tools.lifter import Lifter
from tools.generate import linear_disassemble_function, lift_function_linear
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = 'config/xwingalliance_decrypted.exe'
GEN = 'src/game/recomp/gen'
ITAIL = re.compile(r'RECOMP_ITAIL\(0x([0-9A-Fa-f]{8})u\)')
FDEF = re.compile(r'^void (sub_[0-9A-Fa-f]{8})\(void\) \{', re.M)

def main():
    apply = '--apply' in sys.argv
    lo, hi = 0x401000, 0x5b0000
    if '--lo' in sys.argv: lo = int(sys.argv[sys.argv.index('--lo')+1], 16)
    if '--hi' in sys.argv: hi = int(sys.argv[sys.argv.index('--hi')+1], 16)

    funcs = json.load(open('config/functions.json'))
    faddr = sorted(int(f['address'], 16) for f in funcs)
    fset = set(faddr)

    # parse gen: function bodies + their ITAIL targets; also collect all caller/pointer refs
    bodies = {}      # addr -> (path, body text)
    files = {p: open(p, encoding='utf-8', errors='replace').read() for p in sorted(glob.glob(f'{GEN}/recomp_000[0-5].c'))}
    refs = ''.join(files.values())  # for caller/pointer scan
    for path, src in files.items():
        ms = list(FDEF.finditer(src))
        for i, m in enumerate(ms):
            a = int(m.group(1)[4:], 16)
            end = ms[i+1].start() if i+1 < len(ms) else len(src)
            bodies[a] = (path, src[m.start():end])

    # owner -> mid-function ITAIL targets
    owner_targets = {}
    for a, (path, body) in bodies.items():
        if not (lo <= a < hi): continue
        midf = set()
        for t in ITAIL.findall(body):
            t = int(t, 16)
            if t not in fset and 0x401000 <= t < 0x5b0000:
                midf.add(t)
        if midf: owner_targets[a] = midf

    def has_caller(g):
        nm = f'sub_{g:08X}'
        # real call, or address used as a pointer (push/registration/table)
        if f'RECOMP_CALL({nm})' in refs: return True
        if f'0x{g:08X}u' in refs.replace(f'RECOMP_ITAIL(0x{g:08X}u)', ''): return True
        return False

    # union-find: connect each owner with the functions its mid-func jumps land in (transitive chains)
    parent = {}
    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb: parent[max(ra, rb)] = min(ra, rb)   # root = lowest address
    for owner, targets in owner_targets.items():
        for t in targets:
            g = faddr[bisect.bisect_right(faddr, t) - 1]
            union(owner, g)
    comps = {}
    for a in list(parent):
        comps.setdefault(find(a), set()).add(a)

    plans = []   # (root, new_end, [pieces_to_remove])
    skipped = []
    for root, members in comps.items():
        if len(members) < 2: continue
        mx = max(members)
        i0 = bisect.bisect_right(faddr, root); i1 = bisect.bisect_right(faddr, mx)
        span = set(faddr[i0:i1])
        if span != (members - {root}):          # a non-member (real) function sits inside the range
            skipped.append(root); continue
        if any(has_caller(g) for g in members if g != root):
            skipped.append(root); continue
        new_end = faddr[i1] if i1 < len(faddr) else (mx + 16)
        plans.append((root, new_end, sorted(members - {root})))

    print(f'split owners found: {len(owner_targets)}; clean-mergeable: {len(plans)}; skipped(real-caller): {len(skipped)}')
    total_pieces = sum(len(p[2]) for p in plans)
    print(f'pieces to merge: {total_pieces}')
    for owner, new_end, pieces in plans[:12]:
        print(f'  sub_{owner:08X} -> 0x{new_end:08X}  merge {[f"{g:X}" for g in pieces]}')
    if not apply:
        print('\n(dry run; pass --apply to merge)'); return

    # --- apply ---
    info = analyze_pe(EXE); iat = build_iat_map(info)
    pe = open(EXE, 'rb').read()
    text = [s for s in info.sections if s.name == '.text'][0]
    code = pe[text.raw_offset: text.raw_offset + min(text.virtual_size, text.raw_size)]
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    lifter = Lifter(iat_map=iat, code_start=info.code_start, code_end=info.code_end)
    remove_from_json = set()
    patched = 0
    # process high->low addresses so in-file edits don't disturb earlier offsets
    for owner, new_end, pieces in sorted(plans, key=lambda p: -p[0]):
        instrs, leaders, switches = linear_disassemble_function(md, code, info.code_start, owner, new_end)
        if not instrs: continue
        trimmed = []; seen_ret = False
        for ins in instrs:
            if ins.mnemonic == 'int3': break
            if seen_ret:
                if ins.address not in leaders: continue
                seen_ret = False
            trimmed.append(ins)
            if ins.is_ret: seen_ret = True
        name = f'sub_{owner:08X}'
        lifter._flag_state = None
        new_code = lift_function_linear(lifter, name, trimmed, leaders, owner, switches)
        # find owner's file, replace its body, then remove each piece body + add stub
        for path, src in list(files.items()):
            m = re.search(r'^void ' + re.escape(name) + r'\(void\) \{', src, re.M)
            if not m: continue
            end = src.find('\n}\n', m.start()); end = (src.find('}', end) + 1) if end >= 0 else src.find('}', m.start()) + 1
            src = src[:m.start()] + new_code + src[end:]
            # remove each piece body, append a stub
            for g in pieces:
                gnm = f'sub_{g:08X}'
                gm = re.search(r'^void ' + re.escape(gnm) + r'\(void\) \{', src, re.M)
                if gm:
                    ge = src.find('\n}\n', gm.start()); ge = (src.find('}', ge) + 1) if ge >= 0 else src.find('}', gm.start()) + 1
                    stub = f'void {gnm}(void) {{ esp += 4; return; }} /* merged into {name} (func-split fix) */\n'
                    src = src[:gm.start()] + stub + src[ge+1:]
                remove_from_json.add(g)
            files[path] = src
            patched += 1
            break
    for path, src in files.items():
        open(path, 'w', encoding='utf-8').write(src)
    # update functions.json: drop merged pieces
    funcs2 = [f for f in funcs if int(f['address'], 16) not in remove_from_json]
    json.dump(funcs2, open('config/functions.json', 'w'), indent=1)
    print(f'patched {patched} owners, merged {len(remove_from_json)} pieces, functions.json {len(funcs)}->{len(funcs2)}')

if __name__ == '__main__':
    main()
