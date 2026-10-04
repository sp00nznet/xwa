"""Re-lift every gen function with XWA's CURRENT lifter (in memory, nothing
written to the repo) and diff against the checked-out gen, to size the hand
edits a wholesale regen would have to carry. Run from the repo root."""
import sys, os, re, json, difflib, collections, glob
sys.path.insert(0, os.getcwd())
from tools.pe_analyze import analyze_pe, build_iat_map
from tools.lifter import Lifter
from tools.generate import linear_disassemble_function, lift_function_linear
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

OUT = sys.argv[1]
EXE = 'config/xwingalliance_decrypted.exe'
GEN = 'src/game/recomp/gen'
FN = re.compile(r'^void (sub_([0-9A-F]{8}))\(void\) \{', re.M)

bodies = {}
for p in sorted(glob.glob(GEN + '/recomp_000*.c')):
    src = open(p, encoding='utf-8', errors='replace').read()
    ms = list(FN.finditer(src))
    for i, m in enumerate(ms):
        end = src.find('\n}\n', m.start())
        bodies[int(m.group(2), 16)] = (os.path.basename(p), src[m.start():end + 2])

funcs = json.load(open('config/functions.json'))
all_addrs = sorted(set(f['address_int'] for f in funcs) | set(bodies))
info = analyze_pe(EXE); iat = build_iat_map(info)
pe = open(EXE, 'rb').read()
text = [s for s in info.sections if s.name == '.text'][0]
code = pe[text.raw_offset: text.raw_offset + min(text.virtual_size, text.raw_size)]
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
lifter = Lifter(iat_map=iat, code_start=info.code_start, code_end=info.code_end)

norm = lambda s: re.sub(r'\s+', ' ', s).strip()
stats = collections.Counter()
per_file = collections.Counter()
rows = []
DUMP = open(OUT + '.lines', 'w', encoding='utf-8')
for addr, (fname, old) in sorted(bodies.items()):
    nxt = [a for a in all_addrs if a > addr]
    func_end = min(nxt[0], addr + 65536) if nxt else min(info.code_end, addr + 65536)
    try:
        instrs, leaders, switches = linear_disassemble_function(md, code, info.code_start, addr, func_end)
    except Exception as e:
        stats['relift_error'] += 1; continue
    trimmed = []; seen_ret = False
    for ins in instrs:
        if ins.mnemonic == 'int3':
            seen_ret = True; continue
        if seen_ret:
            if ins.address not in leaders: continue
            seen_ret = False
        trimmed.append(ins)
        if ins.is_ret: seen_ret = True
    lifter._flag_state = None
    new = lift_function_linear(lifter, f'sub_{addr:08X}', trimmed, leaders, addr, switches)
    skip = lambda l: (not l) or l == 'uint32_t ebp = 0;' or l.startswith('/* nop */') or l == 'return; /* end of function */'
    a = [x for x in (norm(l) for l in old.split('\n')) if not skip(x)]
    b = [x for x in (norm(l) for l in new.split('\n')) if not skip(x)]
    if a == b:
        stats['identical'] += 1; continue
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    ins_ = rep = dele = 0
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == 'insert': dele += j2 - j1           # relift has, gen lacks
        elif op == 'delete':
            ins_ += i2 - i1         # gen has, relift lacks (hand-added)
            for x in a[i1:i2]: DUMP.write(f'G sub_{addr:08X} {x}' + chr(10))
        elif op == 'replace':
            rep += max(i2 - i1, j2 - j1)
            for x in a[i1:i2]: DUMP.write(f'R sub_{addr:08X} {x}' + chr(10))
    stats['different'] += 1
    stats['gen_only_lines'] += ins_
    stats['replaced_lines'] += rep
    stats['relift_only_lines'] += dele
    per_file[fname] += 1
    rows.append((ins_ + rep + dele, f'sub_{addr:08X}', fname, ins_, rep, dele))

with open(OUT, 'w') as f:
    for k, v in sorted(stats.items()):
        f.write(f'{k:20s} {v}\n')
    f.write(f'functions in gen: {len(bodies)}\n')
    f.write('different per file: ' + json.dumps(per_file) + '\n')
    buckets = collections.Counter('<=5' if r[0] <= 5 else '<=50' if r[0] <= 50 else '>50' for r in rows)
    f.write('diff size buckets (lines): ' + json.dumps(buckets) + '\n')
    for r in sorted(rows, reverse=True)[:40]:
        f.write(f'{r[1]} {r[2]} total={r[0]} gen_only={r[3]} replaced={r[4]} relift_only={r[5]}\n')
print(open(OUT).read())
