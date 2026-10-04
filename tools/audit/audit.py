"""Count XWA gen sites affected by upstream lift32 fixes.

Parses the instruction comments (`/* 0xADDR: mnem ops */`) and labels in
src/game/recomp/gen/recomp_000*.c -- i.e. what is actually compiled, hand
edits included -- and replays XWA's lifter flag model (textual, reset only at
function entry) against real x86 flag semantics.
"""
import os, re, glob, json, bisect, collections, sys

GEN = os.path.join(os.path.dirname(__file__), '..', '..') + '/' + 'src/game/recomp/gen'
FUNCS = os.path.join(os.path.dirname(__file__), '..', '..') + '/' + 'config/functions.json'

CMT = re.compile(r'/\* 0x([0-9A-F]{8}): ([a-z][a-z0-9 ]*?)(?: (.*?))? \*/')
LBL = re.compile(r'^\s*L_([0-9A-F]{8}):')
FN = re.compile(r'^void (sub_[0-9A-F]{8})\(void\)')
GOTO = re.compile(r'goto L_([0-9A-F]{8});')

JCC = {'je','jz','jne','jnz','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns','jo','jno','jp','jnp',
       'jnb','jnae','jc','jnc','jna','jnbe','jpe','jpo'}
CC_OF = lambda m: m[1:] if m.startswith('j') else (m[3:] if m.startswith('set') else m[4:])
SETCC = {'set' + j[1:] for j in JCC}
CMOV = {'cmov' + j[1:] for j in JCC}
CF_CC = {'b','ae','a','be','nb','nae','c','nc','na','nbe'}
SIGNED_CC = {'l','ge','g','le','s','ns'}
CF_READERS = {'adc','sbb','rcl','rcr'}
SHIFTS = {'shl','sal','shr','sar','shld','shrd'}
ROTS = {'rol','ror','rcl','rcr'}
# instructions that write (some) arithmetic flags on x86
WRITERS = ({'add','sub','adc','sbb','inc','dec','neg','cmp','test','and','or','xor','bt','bts','btr','btc',
            'bsf','bsr','mul','imul','clc','stc','cmc','sahf','popfd','cmpxchg','xadd','daa','das','aaa','aas',
            'scasb','scasw','scasd','cmpsb','cmpsw','cmpsd','repne scasb','repnz scasb','repe cmpsb','repz cmpsb',
            'repe cmpsd','fcomi','fcomip','fucomi','fucomip','call'} | SHIFTS | ROTS)
R8 = {'al','cl','dl','bl','ah','ch','dh','bh'}
R16 = {'ax','cx','dx','bx','sp','bp','si','di'}
SEG = {'es','cs','ss','ds','fs','gs'}


def width(opstr):
    if not opstr:
        return 32
    first = opstr.split(',')[0].strip()
    if first.startswith('byte'): return 8
    if first.startswith('word'): return 16
    if first.startswith('qword'): return 64
    if first.startswith('xword') or first.startswith('tbyte'): return 80
    if first in R8: return 8
    if first in R16: return 16
    return 32


def parse():
    funcs = []  # (name, [items])
    cur = None
    for path in sorted(glob.glob(GEN + '/recomp_000*.c')):
        for line in open(path, encoding='utf-8', errors='replace'):
            m = FN.match(line)
            if m:
                cur = {'name': m.group(1), 'items': [], 'gotos': collections.Counter(), 'file': path[-15:]}
                funcs.append(cur)
                continue
            if cur is None:
                continue
            for g in GOTO.findall(line):
                cur['gotos'][int(g, 16)] += 1
            lm = LBL.match(line)
            if lm:
                cur['items'].append(('L', int(lm.group(1), 16)))
            for c in CMT.finditer(line):
                mn, op = c.group(2).strip(), (c.group(3) or '').strip()
                if mn in ('rep', 'repe', 'repne', 'repz', 'repnz', 'lock') and op:
                    w, _, rest = op.partition(' ')
                    mn, op = mn + ' ' + w, rest.strip()
                cur['items'].append(('I', int(c.group(1), 16), mn, op, line.rstrip()))
    return funcs


def kind(m):
    if m in JCC: return 'jcc'
    if m in SETCC: return 'setcc'
    if m in CMOV: return 'cmov'
    return None


def main():
    funcs = parse()
    starts = sorted(f['address_int'] for f in json.load(open(FUNCS)))
    C = collections.Counter()
    ex = collections.defaultdict(list)

    def hit(key, f, it, n=1):
        C[key] += n
        if len(ex[key]) < 4:
            ex[key].append(f"{f['name']} 0x{it[1]:08X} {it[2]} {it[3]}")

    for f in funcs:
        items = f['items']
        insns = [it for it in items if it[0] == 'I']
        targets = set(f['gotos'])
        # writer lookup for jump sources (for the join-point check)
        idx_of = {}
        for k, it in enumerate(items):
            if it[0] == 'I':
                idx_of.setdefault(it[1], k)

        srcs = collections.defaultdict(list)
        for s_ in insns:
            if s_[2] in JCC or s_[2] == 'jmp':
                try:
                    srcs[int(s_[3], 16)].append(idx_of[s_[1]])
                except (ValueError, KeyError):
                    pass

        def real_writers(k, seen=None):
            seen = set() if seen is None else seen
            if k in seen:
                return set()
            seen.add(k)
            out = set()
            j = k - 1
            while j >= 0:
                it = items[j]
                if it[0] == 'L':
                    if it[1] in targets:
                        for sk in srcs.get(it[1], []):
                            out |= real_writers(sk, seen)
                        # does control fall into this label textually?
                        p = j - 1
                        while p >= 0 and items[p][0] == 'L':
                            p -= 1
                        if p >= 0 and items[p][0] == 'I' and (items[p][2] in ('jmp', 'ret', 'retn') or 'RECOMP_ITAIL' in items[p][4] or 'return;' in items[p][4]):
                            return out
                elif it[2] in WRITERS:
                    out.add(it)
                    return out
                j -= 1
            out.add(None)
            return out

        def writer_before(k):
            """(writer item or None, crossed_target_label, between items) walking back textually."""
            crossed = False
            between = []
            j = k - 1
            while j >= 0:
                it = items[j]
                if it[0] == 'L':
                    if it[1] in targets:
                        crossed = True
                elif it[2] in WRITERS:
                    return it, crossed, between
                else:
                    between.append(it)
                j -= 1
            return None, crossed, between

        # ---- per-instruction static counts ----
        for k, it in enumerate(items):
            if it[0] != 'I':
                continue
            _, va, m, ops, line = it
            w = width(ops)
            if m in ROTS:
                hit('rot_total', f, it)
                if w < 32: hit('rot_narrow', f, it)
                if m in ('rcl', 'rcr'): hit('rot_rcx', f, it)
                if ',' in ops and ops.split(',')[1].strip() == 'cl': hit('rot_by_cl_ub0', f, it)
            if m in ('push', 'pop') and w == 16 and ops.split(',')[0].strip() not in SEG:
                hit('pushpop16', f, it)
            if m in ('push', 'pop') and ops in SEG:
                hit('pushpop_seg', f, it)
            if m in SHIFTS:
                hit('shift_total', f, it)
                parts = [p.strip() for p in ops.split(',')]
                cnt = parts[-1]
                if re.fullmatch(r'0x[0-9a-f]+|\d+', cnt):
                    n = int(cnt, 0)
                    if m in ('shld', 'shrd'):
                        if n & 31 >= w or n == 0: hit('shift_imm_ub', f, it)
                    elif n >= 32 or n >= w:
                        hit('shift_imm_ge_width', f, it)
            if m in ('mul', 'imul', 'div', 'idiv') and ',' not in ops:
                hit(f'{m}_1op_total', f, it)
                if w < 32: hit('muldiv_narrow', f, it); C['zz_muldiv:' + m + str(w)] += 1
            if m in ('stosw', 'lodsw', 'rep stosw', 'rep lodsw'): hit('stosw_lodsw', f, it)
            if m in ('clc', 'stc', 'cmc'): hit('clc_stc_cmc', f, it)
            if m in ('fnstsw', 'fstsw'): hit('fnstsw_total', f, it)
            if m == 'sahf': hit('sahf_total', f, it)
            if m == 'frndint': hit('frndint', f, it)
            if m in ('fistp', 'fist'):
                hit('fist_total', f, it)
                if w == 64: hit('fistp_qword', f, it)
            if m == 'fild' and w == 64: hit('fild_qword', f, it)
            if m in ('fld', 'fstp') and w == 80: hit('fld_fstp_80', f, it)
            if m in ('fxam', 'xlatb', 'xlat', 'fprem', 'fprem1', 'fptan', 'fsin', 'fcos', 'fsincos'):
                hit(f'x87_{m}', f, it)
            if m in ('fucompp', 'cmpxchg8b'): hit(m, f, it)
            if m.startswith('lock'): hit('lock', f, it)
            if m in ('bts', 'btr', 'btc', 'bt'): hit(f'{m}_total', f, it)
            if m == 'bt' and ops.split(',')[0].strip().startswith('dword ptr') and not re.search(r',\s*(0x[0-9a-f]+|\d+)$', ops):
                hit('bt_mem_regoff', f, it)
            if m == 'std': hit('std', f, it)
            if 'cmps' in m or 'scas' in m: hit('str_cmp_scan', f, it)
            if m in ('rep movsb', 'rep movsd', 'rep movsw', 'rep stosb', 'rep stosd', 'rep stosw'): hit('rep_string', f, it)
            if m in ('div', 'idiv'): pass

            # ---- flag consumers ----
            kd = kind(m)
            cfr = m in CF_READERS
            if not kd and not cfr:
                continue
            xw, crossed, between = writer_before(k)
            rws = real_writers(k)
            cc = CC_OF(m) if kd else None
            tag = kd or 'cfread'
            C[f'consumer_{tag}'] += 1
            hits = set()
            H = lambda key, *a: hits.add(key)
            if crossed:
                H('cons_crossed_target')
            sig = lambda w: (w[2], w[3]) if w else None
            if xw is not None and {sig(w) for w in rws} != {sig(xw)}:
                H('cons_real_writer_differs_from_xwa_textual')
                H('cons_real_writer_differs_' + tag)
            for wr in rws:
              if wr is None:
                H('cons_no_writer'); continue
              wm = wr[2]
              wops = wr[3]
              ww = width(wops)
              if kd:
                  if wm in ROTS: H('cc_after_rotate')
                  if wm in SHIFTS: H('cc_after_shift'); H('zz_shift:' + cc)
                  if wm in ('clc', 'stc', 'cmc'): H('cc_after_clc_stc_cmc')
                  if wm == 'add': H('cc_after_add'); H('zz_add:' + cc)
                  if wm in ('inc', 'dec'):
                      if cc in CF_CC: H('cfcc_after_incdec')
                      if wm == 'inc': H('cc_after_inc')
                  if wm == 'sub': H('cc_after_sub_postwrite'); H('zz_sub:' + cc)
                  if wm in ('or', 'xor'):
                      p = [x.strip() for x in wops.split(',')]
                      if len(p) == 2 and p[0] != p[1]: H('cc_after_or_xor_nonself_postwrite')
                  if wm in ('test', 'and') and kd in ('setcc', 'cmov') and cc in ('le', 'g', 'l', 'ge', 'ng', 'nle', 'nl', 'nge'):
                      H('ordered_setcc_after_test')
                  if wm == 'bt' and cc in ('ae', 'nb', 'nc'): H('bt_jae_inverted')
                  if wm == 'call': H('cc_after_call')
                  if wm in ('repe cmpsb', 'repz cmpsb', 'repne scasb', 'repnz scasb', 'repe cmpsd', 'cmpsb', 'cmpsd', 'scasd'):
                      H('cc_after_rep_cmps_scas')
                  if wm in ('mul', 'imul'): H('cc_after_mul')
                  if wm == 'sahf' and cc in ('p', 'np', 'pe', 'po'): H('jp_after_sahf')
                  if wm == 'sahf': H('cc_after_sahf')
                  if cc in ('p', 'np', 'pe', 'po') and wm != 'sahf': H('jp_after_int_setter')
                  if wm in ('cmp', 'sub', 'test', 'and', 'or', 'xor', 'add') and ww < 32 and cc in SIGNED_CC:
                      H('narrow_signed_cc'); H('zz_nsigned:' + wm + ':' + cc)
                      # fnstsw ah tests are narrow but use je/jne -> not here
                  if wm in ('cmp', 'add', 'sub') and ww < 32 and cc in CF_CC:
                      H('narrow_unsigned_cc_cmp')
                  # fnstsw-fed: writer reads ah and an fnstsw precedes it closely
                  if wm in ('test', 'and', 'cmp') and wops.split(',')[0].strip() == 'ah':
                      H('cc_on_ah')
                  # live-operand clobber between writer and consumer (XWA-only):
                  # memory written / register written by non-mov ops after the setter
                  regs = set(re.findall(r'\b(e?[abcd]x|[abcd][lh]|e?[sd]i|e?bp|e?sp)\b', wops))
                  for b in (between if wr is xw else []):
                      bm, bops = b[2], b[3]
                      dst = bops.split(',')[0].strip() if bops else ''
                      if bm in ('mov', 'movzx', 'movsx', 'lea', 'pop'):
                          if 'ptr [' in dst and 'ptr [' in wops:
                              H('cc_mem_operand_stored_between'); break
                          continue
                      if bm.startswith('j') or bm.startswith('set') or bm.startswith('cmov') or bm.startswith('f') or bm in ('push', 'nop'):
                          continue
                      if dst and (dst in regs or ('ptr [' in dst and 'ptr [' in wops)):
                          H('cc_operand_clobbered_untracked'); break
              else:  # adc/sbb/rcl/rcr read _cf directly
                  if wm in ('cmp', 'sub'): H('cfread_after_cmp_sub')
                  if wm == 'neg': H('cfread_after_neg')
                  if wm == 'add': H('cfread_after_add')
                  if wm == 'bt': H('cfread_after_bt')
                  if wm in SHIFTS:
                      if not (wm == 'shr' and wops.endswith(', 1')): H('cfread_after_shift_nocf')
                  if wm in ('test', 'and', 'or', 'xor'): H('cfread_after_logic_cf_not_cleared')
                  if wm in ROTS: H('cfread_after_rotate')
                  if wm in ('repe cmpsb', 'repz cmpsb'): H('cfread_after_repe_cmps')
                  if wm == 'cmc': H('cfread_after_cmc')
                  if wm in ('adc', 'sbb'): H('cfread_after_adc_sbb')
            for h in hits:
                hit(h, f, it)

        # ---- fnstsw consumers: what reads ah next ----
        for k, it in enumerate(items):
            if it[0] == 'I' and it[2] in ('fnstsw', 'fstsw'):
                nxt = None
                for j in range(k + 1, min(k + 12, len(items))):
                    jt = items[j]
                    if jt[0] == 'I' and jt[2] in WRITERS | {'mov'} and ('ah' in jt[3] or jt[2] == 'sahf' or 'ax' in jt[3]):
                        nxt = jt; break
                key = 'fnstsw_then_' + (('sahf' if nxt[2] == 'sahf' else nxt[2] + '_' + nxt[3].split(',')[0].strip()) if nxt else 'none')
                hit(key, f, it)

        # ---- join points: does every incoming edge carry the textual setter? ----
        for k, it in enumerate(items):
            if it[0] != 'L' or it[1] not in targets:
                continue
            # find first consumer after the label before any writer
            j = k + 1
            cons = None
            while j < len(items):
                jt = items[j]
                if jt[0] == 'I':
                    if jt[2] in WRITERS: break
                    if kind(jt[2]) or jt[2] in CF_READERS:
                        cons = j; break
                j += 1
            if cons is None:
                continue
            wtext, _, _ = writer_before(k)
            wtext_va = (wtext[2], wtext[3]) if wtext else None
            # sources: jumps whose target is this label
            mism = False
            for s in insns:
                if s[2] in JCC or s[2] == 'jmp':
                    try:
                        t = int(s[3], 16)
                    except ValueError:
                        continue
                    if t != it[1]:
                        continue
                    ws, _, _ = writer_before(idx_of[s[1]])
                    if ((ws[2], ws[3]) if ws else None) != wtext_va:
                        mism = True; break
            hit('join_consumer_total', f, items[cons])
            if mism:
                hit('join_consumer_mismatched_setter', f, items[cons])

        # ---- int3/split symptom: constant ITAIL into own range ----
    for f in funcs:
        a = int(f['name'][4:], 16)
        i = bisect.bisect_right(starts, a)
        end = starts[i] if i < len(starts) else a + 0x10000
        # read ITAILs from source lines
    itail = collections.Counter()
    for path in sorted(glob.glob(GEN + '/recomp_000*.c')):
        cur = None
        for line in open(path, encoding='utf-8', errors='replace'):
            m = FN.match(line)
            if m:
                cur = int(m.group(1)[4:], 16)
                i = bisect.bisect_right(starts, cur)
                end = starts[i] if i < len(starts) else cur + 0x10000
                continue
            for t in re.findall(r'RECOMP_ITAIL\(0x([0-9A-Fa-f]{8})u\)', line):
                t = int(t, 16)
                itail['const_itail'] += 1
                if cur and cur < t < end:
                    itail['itail_into_own_range'] += 1
                    if len(ex['itail_into_own_range']) < 6:
                        ex['itail_into_own_range'].append(f"sub_{cur:08X} -> 0x{t:08X}")
    C.update(itail)

    C['functions_parsed'] = len(funcs)
    C['insns_parsed'] = sum(1 for f in funcs for it in f['items'] if it[0] == 'I')
    for k in sorted(C):
        print(f"{k:45s} {C[k]}")
    print()
    for k in sorted(ex):
        print(k)
        for e in ex[k]:
            print('   ', e)


if __name__ == '__main__':
    main()
