#!/usr/bin/env python3
"""X-Wing Alliance lift driver: xwa.exe -> src/recomp/gen/.

xwa.exe is X-Wing Alliance (XWINGALLIANCE.EXE, Steam; base 0x00400000), unwrapped from
its SteamStub by Steamless and catalogued by disasm32 into work/functions.json.
The driver is X-Wing vs TIE Fighter's (xvt-recomp).

    py -3 run_lift.py --all
    py -3 run_lift.py --roots 0x004A39FE
"""
import argparse
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
# PCRECOMP picks the toolkit checkout, the same knob CMakeLists.txt has: the
# lifter and the runtime header must come from the same tree.
_TOOLS = os.path.join(os.environ.get('PCRECOMP', os.path.join(_HERE, '..', 'pcrecomp')), 'tools')
sys.path.insert(0, os.path.join(_TOOLS, 'lift'))
sys.path.insert(0, os.path.join(_TOOLS, 'pe'))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32          # noqa: E402
from capstone.x86 import X86_OP_MEM                        # noqa: E402
from generate import (EXTENT_REACH, closure, find_splits, true_extent,  # noqa: E402
                      linear_disassemble_function, lift_function_linear, write_chunk)
from lift32 import Lifter                                  # noqa: E402
from pe_analyze import analyze_pe, build_iat_map           # noqa: E402

OUT = os.path.join(_HERE, 'src', 'recomp', 'gen')
STATS = os.path.join(_HERE, 'work', 'lift_stats.json')

# (file, catalog, PE timestamp of the one build supported, what it is).
# A different build lifts, but the patches and seeds are at this build's
# addresses: it would crash in the game, so it is refused (README).
MODULES = [
    (os.path.join(_HERE, 'work', 'xwa.exe'), os.path.join(_HERE, 'work', 'functions.json'),
     0x3765a9b7, 'XWINGALLIANCE.EXE from Steam, unwrapped by Steamless'),
]

# Entries the catalog does not find (seed_from_log.py from runs).
RUN_SEEDS = []

DATA_IN_CODE = []


def is_data(va):
    return any(lo <= va < hi for lo, hi in DATA_IN_CODE)

# Fixes to the game itself: C run after the instruction at the address.
PATCHES = {
}
PATCH_DECLS = ''

# MSVC's setjmp (_setjmp3). Each call to it gets a landing pad: a label just
# after the call, which ct_longjmp resumes at (tf_setjmp_resume[]).
SETJMP = 0  # none found yet

def apply_patches(body, patches):
    """Add each patch's C after the lines that lift its instruction.

    Some instructions lift to a block over several lines (idiv's `{ ... }`):
    the patch goes after the block closes, not inside it. From the Tiberium
    Wars driver (tiberiumwars-recomp run_lift.py)."""
    for va, c in patches.items():
        tag = '/* 0x%08X:' % va
        k = body.find(tag)
        if k != -1:
            s = body.rfind('\n', 0, k) + 1
            e = body.index('\n', k)
            depth = body[s:e].count('{') - body[s:e].count('}')
            while depth > 0:
                s, e = e + 1, body.index('\n', e + 1)
                depth += body[s:e].count('{') - body[s:e].count('}')
            body = body[:e + 1] + '    ' + c + '\n' + body[e + 1:]
    return body


def code_patches(md, code, cs, ce):
    """Addresses inside .text that the module's own code stores to.

    The 3D texture mapper patches its inner loops (from Gunman's driver):
    `mov al, [eax+0x12345678]` ships with a placeholder that a setup routine
    overwrites with the live colormap address (Gunman's sw.dll). Only
    absolute stores are looked for -- that is the only form the patchers use.
    """
    from capstone import CS_AC_WRITE
    md.skipdata = True
    out = set()
    for ins in md.disasm(code, cs):
        if ins.id == 0 or not ins.operands:
            continue
        op = ins.operands[0]
        if (op.type == X86_OP_MEM and op.access & CS_AC_WRITE
                and op.mem.base == 0 and op.mem.index == 0
                and cs <= (op.mem.disp & 0xFFFFFFFF) < ce):
            out.add(op.mem.disp & 0xFFFFFFFF)
    md.skipdata = False
    return out


def load_seeds(path):
    """Addresses from a seed file: a list of {'address': va} or of plain VAs."""
    if not path or not os.path.exists(path):
        return set()
    return {e['address'] if isinstance(e, dict) else e for e in json.load(open(path))}


def exe_stamp(path):
    """The PE header's TimeDateStamp: which build of a module this is."""
    with open(path, 'rb') as f:
        head = f.read(4096)
    nt = int.from_bytes(head[0x3C:0x40], 'little')
    return int.from_bytes(head[nt + 8:nt + 12], 'little')


class Out:
    """The generated tree: chunks numbered across both modules."""

    def __init__(self, path, split):
        self.path, self.split = path, split
        self.chunk, self.idx, self.entries, self.setjmp = [], 0, [], []

    def add(self, body, addr, name):
        self.chunk.append((body, addr, name))
        self.entries.append((addr, name))
        if len(self.chunk) >= self.split:
            self.flush()

    def flush(self):
        if self.chunk:
            write_chunk(self.path, self.idx, self.chunk)
            self.idx += 1
            self.chunk = []


def lift_module(path, catalog, args, out, extra_roots):
    """Lift one module into `out`. Returns (entry VA, stats)."""
    info = analyze_pe(path)
    iat = build_iat_map(info)
    cs, ce = info.code_start, info.code_end
    print('[*] %s: base=0x%08X code=0x%08X-0x%08X IAT=%d'
          % (os.path.basename(path), info.image_base, cs, ce, len(iat)))

    # The code section, by address.
    cat = json.load(open(catalog))
    byaddr = {f['address']: f for f in cat['functions'] if cs <= f['address'] < ce and not is_data(f['address'])}
    print('[*]   catalog: %d functions inside the code section' % len(byaddr))

    text = next(s for s in info.sections
                if s.virtual_address <= cs - info.image_base < s.virtual_address + s.raw_size)
    code = open(path, 'rb').read()[text.raw_offset:text.raw_offset + text.raw_size]

    # Bound each injected entry by the next known one: an entry landing
    # mid-code handed `ce` makes the extent walk descend the whole section.
    want = {a for a in set(RUN_SEEDS) | load_seeds(args.seeds) if cs <= a < ce and a not in byaddr}
    known = sorted(set(byaddr) | want)
    nxt = {a: (known[i + 1] if i + 1 < len(known) else ce) for i, a in enumerate(known)}
    for a in want:
        byaddr[a] = {'address': a, 'end': min(nxt[a], a + 0x100), 'calls_to': [], 'entry_kind': 'start'}

    entry = info.image_base + info.entry_point_rva
    roots = [entry] + [info.image_base + e.rva for e in getattr(info, 'exports', [])
                       if getattr(e, 'rva', 0)] + [r for r in extra_roots if cs <= r < ce]
    chosen = set(byaddr) if args.all else set(closure(byaddr, roots, args.max))
    print('[*]   lifting %d of %d functions (%s)'
          % (len(chosen), len(byaddr), 'all' if args.all else 'closure, cap %d' % args.max))

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # precise carry: adc/sbb take their carry from the flag state that set it.
    # The default reads a `_cf` that add/sub/cmp never write, which breaks every
    # 64-bit add and subtract (The Movies lost its menu video to it).
    patches = code_patches(md, code, cs, ce)
    print('[*]   %d self-modified code fields' % len(patches))
    lifter = Lifter(iat_map=iat, lifted=set(byaddr), precise_carry=True, precise_sbb=True,
                    patch_sites=patches)
    ordered = sorted(byaddr)
    starts = {a for a in ordered if byaddr[a].get('entry_kind') != 'alias'}
    splits = find_splits(md, code, cs, ce, starts)
    starts -= splits          # still dispatchable; just not a wall inside its parent
    errors = dirty = 0

    def lift_one(addr, name, end, reached):
        nonlocal errors
        try:
            lo = min(reached) if reached else addr   # a chunk can sit below the entry
            insns, leaders = (linear_disassemble_function(md, code, cs, lo, end, reached=reached)
                              if end > addr else ([], None))
            if leaders is not None:
                leaders.add(addr)
            resume = {i.end_address for i in insns if i.is_call and i.get_branch_target() == SETJMP}
            out.setjmp += [(addr, r) for r in sorted(resume)]
            body = (lift_function_linear(lifter, name, insns, leaders, addr, eh_resume=resume) if insns
                    else 'void %s(void) { }\n' % name)
            body = apply_patches(body, {va: c for va, c in PATCHES.items() if reached and va in reached})
        except Exception as e:                      # noqa: BLE001 -- counted, not hidden
            body = '/* ERROR %s: %s */\nvoid %s(void) { }\n' % (name, e, name)
            errors += 1
        out.add(body, addr, name)

    # A direct branch or call to an address nothing catalogued is a tail call
    # or a jump into shared code the catalog missed. The target has to be
    # dispatchable or the RECOMP_ITAIL cannot resolve, so each round's outside
    # targets are lifted in the next round, until none are new.
    todo, added = sorted(chosen), 0
    while todo:
        outside = set()
        for addr in todo:
            reached, behind, called = set(), set(), set()
            end, clean = true_extent(md, code, cs, addr, min(addr + EXTENT_REACH, ce), starts,
                                     reached=reached, behind=behind, called=called)
            outside |= {t for t in behind if t not in reached} | called
            dirty += not clean
            lift_one(addr, 'sub_%08X' % addr, end, reached)
        todo = sorted(t for t in outside if cs <= t < ce and t not in byaddr and not is_data(t))
        for t in todo:
            byaddr[t] = {'address': t, 'end': ce, 'calls_to': [], 'entry_kind': 'start'}
            chosen.add(t)
        added += len(todo)

    stubs = [a for a in ordered if a not in chosen]
    for a in stubs:
        name = 'sub_%08X' % a
        out.add('void %s(void) { RECOMP_NOT_LIFTED(0x%08Xu); }\n' % (name, a), a, name)
    print('[*]   lifted %d, %d outside targets added, %d stubs, %d errors, %d with no terminator'
          % (len(chosen), added, len(stubs), errors, dirty))
    return entry, {'lifted': len(chosen), 'stubs': len(stubs), 'errors': errors, 'no_terminator': dirty}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=OUT)
    ap.add_argument('--roots', default='', help='comma-separated extra root VAs')
    ap.add_argument('--max', type=int, default=3000, help='closure size cap')
    ap.add_argument('--all', action='store_true', help='lift every function')
    ap.add_argument('--split', type=int, default=400, help='functions per .c file')
    ap.add_argument('--seeds', default=os.path.join(_HERE, 'work', 'run_seeds.json'),
                    help='seed_from_log.py JSON of unresolved targets from runs')
    args = ap.parse_args()
    for path, catalog, stamp, what in MODULES:
        if not os.path.exists(path):
            sys.exit('no %s -- README, Step by step' % path)
        if not os.path.exists(catalog):
            sys.exit('no catalog at %s -- run disasm32.py first (README, Step by step)' % catalog)
        if exe_stamp(path) != stamp:
            sys.exit('%s is not the build this project supports: its PE timestamp is 0x%08X, '
                     'expected 0x%08X: %s (README).' % (path, exe_stamp(path), stamp, what))

    os.makedirs(args.out, exist_ok=True)
    for fn in os.listdir(args.out):                 # a smaller lift must not leave stale chunks
        if fn.startswith('recomp_') and fn.endswith('.c'):
            os.remove(os.path.join(args.out, fn))
    t0 = time.time()
    out = Out(args.out, args.split)
    roots = [int(x, 0) for x in args.roots.split(',') if x.strip()]
    entries_va, stats = [], {'lifted': 0, 'stubs': 0, 'errors': 0, 'no_terminator': 0}
    for path, catalog, _, _ in MODULES:
        entry, s = lift_module(path, catalog, args, out, roots)
        entries_va.append(entry)
        for k in stats:
            stats[k] += s[k]
    out.flush()

    with open(os.path.join(args.out, 'recomp_funcs.h'), 'w', newline='\n') as f:
        f.write('/* xwa.exe - AUTO-GENERATED by run_lift.py */\n#pragma once\n'
                '#include <stdint.h>\n\n'
                'void recomp_not_lifted(uint32_t va);\n'
                '#define RECOMP_NOT_LIFTED(va) recomp_not_lifted(va)\n\n' + PATCH_DECLS + '\n')
        for a, n in out.entries:
            f.write('void %s(void);\n' % n)
    with open(os.path.join(args.out, 'recomp_dispatch.c'), 'w', newline='\n') as f:
        f.write('/* xwa.exe - AUTO-GENERATED by run_lift.py */\n'
                '#include "recomp_types.h"\n#include "recomp_funcs.h"\n\n'
                'const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n')
        for a, n in sorted(out.entries):
            f.write('    { 0x%08Xu, %s },\n' % (a, n))
        f.write('};\nconst uint32_t recomp_dispatch_count = %d;\n'
                'const uint32_t tf_entry_va = 0x%08Xu;\n'
                % (len(out.entries), entries_va[0]))
        f.write('const uint32_t tf_setjmp_resume[][2] = {\n%s    { 0, 0 }\n};\n'
                % ''.join('    { 0x%08Xu, 0x%08Xu },\n' % e for e in out.setjmp))

    # A patch that found no instruction to follow is a fix that silently isn't there.
    gen = ''.join(open(os.path.join(args.out, fn), encoding='utf-8', errors='replace').read()
                  for fn in os.listdir(args.out) if fn.endswith('.c'))
    for va, c in PATCHES.items():
        if c not in gen:
            sys.exit('patch at 0x%08X (%s) was not applied: is 0x%08X lifted?' % (va, c, va))
    print('[*] patches applied: %d' % len(PATCHES))

    lines = sum(sum(1 for _ in open(os.path.join(args.out, fn), encoding='utf-8', errors='replace'))
                for fn in os.listdir(args.out))
    stats.update({'files': out.idx, 'lines': lines})
    json.dump(stats, open(STATS, 'w'), indent=1)
    print('=' * 60)
    print('  lifted %(lifted)d   not-lifted stubs %(stubs)d   errors %(errors)d   '
          'no terminator %(no_terminator)d' % stats)
    print('  %s lines of C in %d files, %.1fs' % (format(lines, ','), out.idx, time.time() - t0))
    print('=' * 60)


if __name__ == '__main__':
    main()
