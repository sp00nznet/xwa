# Lifter audit: XWA's fork vs pcrecomp lift32

`tools/lifter.py` is an older fork of pcrecomp's `tools/lift/lift32.py`. This audit (2026-10-03)
measured which upstream correctness fixes since 2026-09-12 are missing here, and how many sites in
the compiled `gen/` each one affects. Scripts: `tools/audit/audit.py`, `tools/audit/relift_diff.py`.

**Status (2026-10-04):** fixed in the lifter or patched into gen, all replayed by
`tools/repair_gen.py`:
- #14 fnstsw (595 sites, `tools/fix_fnstsw.py`);
- post-write sub/add/and/or/xor conditions, including narrow signed ones (911 sites,
  `tools/fix_postwrite.py`, self-tested against reference x86 flags);
- cmp/test operands clobbered before the consumer -- `test esi,esi; pop esi; sete al` (26 sites,
  `tools/fix_clobbered_flags.py`). This one made the CRT report a masked acos() domain error as
  unhandled and raise 0xC0000090;
- local jump tables lifted as indirect tail calls (`tools/fix_jmptbl.py`, the generator's switch
  detector, and re-lifts), which left callers' esp off by the callee's pushes;
- 37 functions whose func-split "merge" dropped code (sub_0040F230, the hangar-launch transfer,
  was 7 instructions), re-lifted with explicit ends.
Still open: CF publishing (neg/cmp/add/sub feeding sbb/adc), shifts, narrow cmp/test conditions
outside the post-write class, join points (only 0x0044309B fixed by hand), the CRT routines.

## How the counts were made

- **Source of truth is the compiled gen**, not a fresh lift. `audit.py` parses every
  `/* 0xVA: mnem ops */` comment and `L_xxx:` label in `src/game/recomp/gen/recomp_000*.c`
  (2,878 functions, 510,214 lifted instructions, hand edits included). It then replays XWA's flag
  model against real x86 semantics. XWA's flag model is textual: `_flag_state` is reset only at
  function entry (`tools/generate.py:294`) and holds *live* operand expressions.
- For each flag consumer (jcc/setcc/cmovcc, or adc/sbb/rcl/rcr reading `_cf`), the script finds
  the **real** x86 writer(s). It walks back through the stream and follows every jump into a
  branch-target label, and compares that with the writer XWA actually pairs it with.
- Spot checks: about 20 sites were opened in gen and confirmed by hand. The examples below are quoted
  verbatim from gen.
- `relift_diff.py` re-lifts every gen function in memory with XWA's *current* `tools/lifter.py`
  and diffs it against gen. That sizes the hand edits.
- Scripts: `tools/audit/`. Their output is derived from gen and stays local.

**Structural finding first.** XWA's fork predates upstream's lazy-flag runtime: `_flag_k/_flag_a/_flag_b`,
`FK_*`, `recomp_cond()`, `recomp_eflags*()` and the operand snapshot `_flag_capture`. Most upstream
fixes in this window are written *in terms of* that machinery: they freeze the flags into
`FK_EFLAGS`, or fall back to `recomp_cond` at join points. Porting them one by one therefore means
porting that runtime first.

## Per-fix results

Line refs: XWA = `G:/recomp/pc/xwa/recomp/tools/lifter.py` unless noted.

| # | Upstream fix (commit) | Present in XWA? (where) | XWA sites (gen) | Severity for XWA |
|---|---|---|---|---|
| 1 | Rotates at operand width (142d4e0) | YES. `ROL32/ROR32` regardless of width, lifter.py:612-622 | 17 narrow (`ror ax,8` x17 in sub_00592292, 1 caller). Emits `SET_LO16(eax, ROR32(LO16(eax),8))`, which returns 0x00HH, not LLHH | likely-visible inside that routine (byte swap is broken) |
| 1b | Rotates publish CF (142d4e0) | YES (rotates don't touch flag state) | 0 consumers after a rotate | theoretical |
| 1c | rcl/rcr implemented | Worse: not implemented at all (UNIMPLEMENTED) | 4 (`rcr ebx,1`/`rcr eax,1` in sub_005A5B00/5A5B70, CRT `_aulldiv`-style 64-bit divide; 1 caller each) | rare: only divisors >= 2^32 |
| 2 | 16-bit push/pop (142d4e0) | YES, lifter.py:456-472 (always PUSH32/POP32) | 3 (`push cx` x3 in sub_005152F0) | possible stack skew of 2 bytes on that path |
| 2b | Segment push/pop are 4 bytes (f9b4b14) | not present (XWA always 4) | n/a | none |
| 3 | Capstone operands freed (142d4e0) | N/A. XWA uses its own `LinearInstruction` with `detail=True` | 0 | none |
| 4 | Narrow-operand flags (0e57ed4) | YES, different form. Flag operands are zero-extended `LO8/LO16/MEM16`. Eq/unsigned conditions come out right (capstone gives `0xFFFFu`, not sign-extended, so verified). **Signed conditions are wrong** whenever the narrow sign bit is set | **745** signed conditions on 8/16-bit setters (cmp 481, test 208, add 43, sub 12, and 1). E.g. `test cx,cx; setge` -> `TEST_NS(LO16(ecx),..)` is always 1; `cmp word [0x7b4c00],bp; jle` | likely-visible |
| 5 | Shifts publish CF/flags (0e57ed4) | YES. shl/sar set nothing; shr sets `_cf` only for count 1; no shift updates `_flag_state` (lifter.py:590-610) | **38** jcc after a shift read the *previous* setter (jne 24, je 7, jns 6, js 1). E.g. 0x00406C63 `sar esi,9; jns` -> `CMP_NS(esp, 0x2Cu)` from an old `add esp`. 0 CF-readers after a shift | likely-visible at those 38 |
| 6 | stosw/lodsw missing (0e57ed4) | not present (lifter.py:696-718). lodsw is missing but has 0 sites | 29 stosw, all handled | none |
| 7 | clc/stc/cmc publish CF (96f3747) | YES in code, lifter.py:1034-1041 | 1 clc, 0 dependent consumers | theoretical |
| 8 | add/inc paired with jcc (d00e752) | **add: YES and worse.** The condition is the subtracting `CMP_*` macro *and* it is evaluated on the post-write register (`CMP_EQ(eax_new, b)`). **inc: not present.** XWA emits `CMP_xx(new, 0)`, which is right for ZF/SF | add: **163** (s 76, ge 29, ne 15, ns 14, l 9, e 8, jno 6, b 4, ae 1). b/ae are right by accident (`new < b` == carry), so about 150 are wrong. inc: 18, all fine | likely-visible |
| 9 | Shift count masked to 5 bits / UB (d00e752) | YES in code (raw immediate) | 0 sites with imm count >= width | theoretical |
| 10 | setcc after test used CMP_* (3eb57f4) | **not present.** XWA's `SETCC_MAP`/`CMOVCC_MAP` carry the jcc tuple (lifter.py:81-84), so setle -> TEST_LE | 16 ordered setcc/cmov after test, all emitted as TEST_* (the narrow ones still hit #4) | none |
| 11 | cmp/sub publish `_cf` for sbb/adc (3eb57f4) | YES. cmp/sub never write `_cf`; sbb/adc read `_cf` (lifter.py:625-630, 663-677) | **494** CF-readers whose real writer is cmp/sub: 429 are the `sbb r,r; sbb r,-1` strcmp/memcmp sign tail (equality survives, ordering is random); 33 `cmp; sbb r,r` bool idiom (+22 with a mov between); 12 `sub; sbb` 64-bit | likely-visible (bool idiom, 64-bit subtract, sorted/bsearch string compares) |
| 12 | rep movs/stos honour DF (3eb57f4) | YES. rep forms always copy forward (lifter.py:680-697) | 4 `std; rep movs*` sites, in CRT memmove/memcpy **sub_0059D7F0 (66 direct callers)** and its siblings | likely-visible when any overlapping dst>src copy happens |
| 13 | cmps/scas all widths + flags (3eb57f4, 5124e56) | YES. `repe cmpsb` sets no flag state and no `_cf` (lifter.py:728-730); cmpsd/scasd missing | **7** `repe cmpsb; jne` -> `TEST_NZ(eax=0,..)`: never taken, so memcmp always reports "equal" (sub_00531430, sub_005306C0). `repe cmpsd` and `scasd` are UNIMPLEMENTED (1 + 1). 1007 `repne scasb` (strlen) need no flags | likely-visible where used |
| 14 | **fnstsw was a comment (6263fdb)** | **YES**, lifter.py:965-967 | **595 fnstsw. 586 are followed by `test ah,N; jcc`** on a stale AH (`test ah,1` 313, `0x41` 178, `0x40` 46, ...). That is every MSVC float compare in the game. It includes the render-path site the flight work studied (#573): 0x004842F6 `fcomp [0x5A99E8]; fnstsw; test ah,0x40; jne L_0048441B` | **likely-visible, highest impact** |
| 15 | int3 inside a body / sweep resume (967f895) | PARTLY. `linear_disassemble_function` stops at int3 only past forward targets (generate.py:248), but `main()` trims at the *first* int3 (generate.py:439). `relift_func.py` resumes at the next leader. No resume at a jmp target; int3 emits no `return` | 38 constant `RECOMP_ITAIL` into the function's own range (of 211 constant ITAILs). These are the symptom; `fix_func_splits.py` covers some | per-site; visible if hit |
| 16a | sahf real (5124e56) | YES (comment, lifter.py:969) | 5. `fnstsw;sahf;jcc` still works through the fcom path. 2 `jp` after sahf (CRT fmod/fprem1 loop, sub_0059DDBD, 1 caller) are emitted as `_fpu_cmp==0` | low |
| 16b | fprem/fxam/xlatb/frndint (5124e56) | fprem1 UNIMPLEMENTED; frndint truncates | fprem1 1; fxam/xlatb/frndint 0 | low |
| 16c | 80-bit fld/fstp (5124e56) | YES: pushes 0.0 / drops the value | 9 `fld xword` (CRT math constants, sub_0059C3DD/0059C54D/0059DDBD, 1 caller each) | moderate in those CRT math helpers |
| 16d | trig ops clear C2 (5124e56) | n/a until fnstsw is real | fsin 37 / fcos 33 | theoretical now; matters after #14 |
| 16e | flags across ret (5124e56) | YES (call doesn't reset or reload flag state) | 3 jcc directly after a call (sub_0055B630, sub_00595FA4) | low |
| 16f | inc/dec preserve CF (5124e56) | YES for dec (`dec; jae` -> `CMP_AE(new,1)`) | 1 (0x004EA631) | low |
| 16g | bt;jae inverted, memory bit-string bt, bts/btr/btc (5124e56) | YES. lifter.py:302-306 returns BT_CF for both jb and jae; `bt [mem],reg` reads one dword; bts is UNIMPLEMENTED | 2 bt (both `bt [esp],eax; jae`, inverted) + 2 bts, in **strpbrk/strcspn sub_005A1670/005A16B0** (5 callers). The bit map is never built and the test is inverted | visible wherever those are called |
| 16h | lock-prefixed forms (5124e56) | YES (UNIMPLEMENTED) | 6 `lock inc/dec [0xB0F970]` (CRT refcount) | low |
| 16i | fist/fistp round by control word (5124e56) | YES (C truncation) | 2 (one is inside FTOL, which is inlined anyway) | theoretical |
| 16j | unordered x87 compares, narrow PF (5124e56) | YES (CMP_P stub) | jp after an integer setter: 2 | theoretical |
| 17 | mul/imul/div/idiv sized by operand (dd6eebb) | YES, lifter.py:530-561 (always 32-bit) | **42** (all `imul r8`): writes the whole EAX *and EDX* instead of AX. Total 1-operand: imul 956, idiv 475, div 173, mul 112 | likely-visible (EDX clobber) |
| 18a | flag state leaks across branch targets (f9b4b14) | YES. Reset only at function entry (generate.py:294); no runtime fallback exists | **59** jcc/setcc whose real setter(s) differ from the textual one. E.g. 0x004176D9 reached by `cmp al,0x14; jae` emits `CMP_NE(_old_eax, esi)` from an earlier `add` (+440 CF-readers, which are counted in #11) | likely-visible |
| 18b | ICALL-unresolved popped an unpushed slot (f9b4b14) | not present (recomp_types.h:416 undoes its own push) | n/a | none |
| 18c | add publishes CF (f9b4b14) | YES | **92** `add; adc` (+2 more): 64-bit adds, e.g. sub_00405FE0 0x00406C88 `adc edx,0` | likely-visible (64-bit / fixed-point math) |
| 18d | fild/fistp qword exact (f9b4b14) | YES (through a double) | 123 fild qword, 1 fistp qword | theoretical (needs > 2^53) |
| 19 | cmpxchg8b, fucompp, CPUID mask (2688140) | missing, but unused | 0 / 0 / 0 cpuid | none |
| 20 | bt publishes `_cf` (506396b) | YES | 0 `bt; adc/sbb` | theoretical |

### Older bugs that are NOT in this commit window but bite hardest

XWA's fork lacks fixes that upstream made *before* 2026-09-12. They share the shape of the bugs above and
should be fixed alongside them:

| Bug | XWA location | Sites | Severity |
|---|---|---|---|
| **Setter evaluated after its own write-back** (sub/add/or/xor). Upstream snapshots operands in `_flag_capture` | lifter.py:487-499, 571-587 | **sub 398** (je 215, jns 121, jne 56, js 5), add 163 (#8), or/xor 24 | **likely-visible.** `sub eax,0x15; je` (0x0040D61C, 0x0048212F) emits `CMP_EQ(eax, 0x15u)` on the *result*, so it fires for mode 0x2A, not 0x15. This is the MODE chain that memory note #573 decoded as "0x2A/0x16/0x1A" from the lifted C |
| `neg` doesn't publish CF | lifter.py:519-523 | **207** `neg; sbb r,r` bool idiom | likely-visible |
| No divide-by-zero guard | lifter.py:551-561 | 648 div/idiv | host #DE crash if hit |
| Memory operand stored between cmp and jcc | flag state holds live expressions | 259 (nearly all to different addresses) | theoretical |

## Wholesale migration vs one-by-one: cost

### What wholesale actually means for the *tool*

- Upstream `lift32.py` is 2,153 lines against XWA's 1,251. Its interface is compatible: XWA's
  `LinearInstruction` already exposes `bytes/operands/size/mnemonic/op_str`.
- What has to be carried over:
  - **FS_MEM.** Upstream already routes `fs:` through `FS_BASE + (addr)` (lift32.py:377-379), so
    one `#define FS_BASE` in XWA's runtime covers it. XWA's `FS_ADDR` in fstp/fst needs the same mapping.
  - **FTOL / FPEPI inlining.** About 10 lines in the call/jmp handlers.
  - **XWA's `detect_switches`.** Keep XWA's `generate.py` as the driver; upstream's
    `_itail_tgt` local dispatch is an alternative.
  - **The local `ebp` question.** It is already settled: gen has no local `ebp` (the runtime treats it
    as global), which matches upstream.
- Runtime header: port roughly 300-400 lines from `runtime/recomp32/recomp_types.h`: `FK_*`,
  `recomp_cond/_cf`, `recomp_eflags(_setcf)`, `recomp_flags_pack/_adc`, `recomp_carry`, `RECOMP_PF`,
  `RECOMP_FLAGS_IN/OUT` (weak), `FPU_CMP`, `fp_ld80/st80`, `fp_round_cw`, `fp_to_int`,
  `g_st_i64/fp_push_i64/fp_st0_to_i64`, `fp_xch`, `MEMSET16`, `PUSH16/POP16_VAL`, plus the four new
  `FUNCTION_LOCALS`.
- Estimate: **1-2 days** to get a clean build of freshly lifted code. That is about what porting the
  fixes one by one would cost anyway, because #5, #7, #18a and #1 need the same `FK_EFLAGS`/`recomp_cond`
  runtime.

### What wholesale means for *gen*: the real cost

- `relift_diff`: re-lifting every gen function with **XWA's own current lifter**, normalised for the
  `ebp` local, padding nops and the trailing return:
  - only **1,001 / 2,878 functions are identical**;
  - 1,877 differ: 643 by 5 lines or fewer, 920 by 6-50, 314 by more than 50.
  - In other words, the current XWA toolchain cannot reproduce gen either.
- Gen-side lines with no counterpart in a fresh lift:
  - about **4,100 diagnostic/env-gated lines** (fprintf/getenv/`g_lastblk`/`[G_DC]`/`XWA_*`/`[FGDBG]`) in
    **186 functions**. For example, `recomp_0000.c` has 271 `[G_DC]` probes and 441 `g_lastblk` writes.
  - about **6,500 other hand-written C lines** in **380 functions**: native rewrites, `_old_` saves,
    hand-patched conditions.
  - about 74k lifted-instruction lines that differ, in 650 functions. These come from bounds,
    split and over-extension fixes (`fix_overextended.py`, `fix_func_splits.py`), int3 trimming
    differences, and in-place patchers (`fix_dec_cond`, `fix_test_cond`, `fix_clobber`, `fix_fpu_pop`).
- `tools/hooks/*.hook` covers **13 hooks / 511 lines**. `XWA_ALLOBJ` (5 hits in recomp_0000.c),
  `[FGDBG]` (2) and all of the `[G_DC]`/`g_lastblk` instrumentation are **not** hooks.
- `regen_0000.py`'s own docstring already says files 0001-0005 "have manual fixes applied".
- So a wholesale regen would silently drop about 10k hand lines across 400+ functions, plus the
  bounds/split repairs. That is weeks of re-deriving, and it would knock the flight investigation
  back to an unknown baseline.

## Recommendation

**Don't migrate gen wholesale. Swap the tool, roll out gen incrementally, and patch the big
bugs in place first.**

1. **This week: in-place gen patchers**, in the style of `fix_fpu_pop.py` / `fix_dec_cond.py`. Each one
   is keyed on the instruction comment, touches only lines that still carry the exact buggy emission,
   and reports anything hand-edited. In priority order:
   - **fnstsw (586):** replace the comment with
     `eax = (eax & 0xFFFF0000u) | (_fpu_cmp < 0 ? 0x0100u : _fpu_cmp == 0 ? 0x4000u : 0u);`.
     `_fpu_cmp` is already set by the preceding fcom*/ficom*.
   - **sub/add/or/xor post-write (about 560):** for e/ne/s/ns, rewrite `/* sub result */ CMP_xx(X, Y)`
     to `CMP_xx(X, 0)`, which is exactly what `fix_dec_cond.py` did for dec. Narrow X needs an
     `(int16_t)`/`(int8_t)` cast.
   - **Narrow signed conditions (745):** sign-extend the operands with casts.
   - **CF publishing:** `neg; sbb` (207), `cmp; sbb` (about 55), `add; adc` (92), `sub; sbb` (12).
     Insert `_cf = ...` before the write-back.
   - **The 38 jcc after shifts and the 59 join-point jcc:** few enough to fix by hand.
   - **The CRT routines** memmove DF (sub_0059D7F0), strpbrk/strcspn (bt/bts), memcmp `repe cmpsb`
     (7), `imul r8` (42) and `ror ax,8` (17): native overrides or hand fixes are cheapest.
2. **Then: switch `tools/lifter.py` to upstream lift32**, with the FS_BASE / FTOL / FPEPI shims and the
   header port. Use it for every *new* lift (`relift_func.py`, `insert_func.py`, `fix_*`). Auto-replace
   only the 1,001 functions that are byte-identical to a fresh old-lifter relift, since those carry no
   hand edits. Review the 643 small-diff functions semi-automatically.
3. **Over time: convert the hand edits into hooks**, so a future full regen is possible. Until that
   is done, a wholesale regen is not an option, whichever lifter is used.
