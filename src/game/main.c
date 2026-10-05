/*
 * X-Wing Alliance Static Recompilation - Entry Point
 *
 * Sets up the memory layout, initializes the register model,
 * installs the VEH crash handler, and launches the recompiled game.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <mmsystem.h>   /* timeBeginPeriod */
#include <winternl.h>  /* NtCurrentTeb() */
#include <stdio.h>
#include <float.h>
#include <stdint.h>
#include <stdarg.h>
#include <dbghelp.h>
#include <psapi.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include "recomp/recomp_types.h"
#include "../hal/d3d11_renderer.h"

/* Real-CRT sprintf bridge. The June relift left the guest _vsnprintf/_output
 * (sub_0059A680 -> sub_0059E580) broken: they crash walking the format/arg
 * stream even for a trivial "times%u.abp" format (see sub_00556B20). Rather
 * than debug 894 lines of relifted printf, delegate to the host CRT. cdecl
 * layout at entry (RECOMP_CALL already pushed the return address):
 *   [esp+4]=buffer, [esp+8]=format, [esp+0xC..]=varargs.
 * Guest memory is identity-mapped (g_mem_base=0), so guest pointers are host
 * pointers and the guest vararg block is a valid x86 va_list. Caller (cdecl)
 * cleans the args, so we only pop the return address. */
void xwa_sprintf_bridge(void) {
    char* buf = (char*)ADDR(MEM32(g_esp + 4));
    const char* fmt = (const char*)ADDR(MEM32(g_esp + 8));
    va_list ap = (va_list)(uintptr_t)ADDR(g_esp + 0xC);
    int n = vsprintf(buf, fmt, ap);
    g_eax = (uint32_t)n;
    g_esp += 4;
}

/* Real-CRT fprintf bridge for the guest fprintf (sub_0059BEE0). Same relift
 * breakage as sprintf, but it targets a GUEST FILE* (arg0) — the game's Deus
 * debug logger — whose guest FILE/_output machinery derefs NULL and crashes
 * during flight init. The guest FILE* can't be handed to the host CRT, and the
 * game never reads its own debug log, so format the args (for a correct return
 * count) and drop the output. cdecl: [esp+4]=FILE*, [esp+8]=format, [esp+0xC..]=varargs. */
void xwa_fprintf_bridge(void) {
    const char* fmt = (const char*)ADDR(MEM32(g_esp + 8));
    va_list ap = (va_list)(uintptr_t)ADDR(g_esp + 0xC);
    char tmp[1024];
    int n = _vsnprintf(tmp, sizeof(tmp) - 1, fmt, ap);
    if (n < 0) n = (int)sizeof(tmp) - 1;
    g_eax = (uint32_t)n;
    g_esp += 4;
}

/* ============================================================
 * Global Register Definitions
 * ============================================================ */

uint32_t g_eax = 0, g_ecx = 0, g_edx = 0, g_esp = 0;
uint32_t g_ebp = 0;
int g_ret_probe = 0;
volatile unsigned g_lastblk = 0;
volatile unsigned g_fgbase = 0, g_fgtblptr = 0, g_fgrec = 0, g_fgro = 0;
volatile unsigned g_obj = 0, g_objro = 0, g_objtag = 0;
volatile unsigned g_cw[3] = {0,0,0};
volatile unsigned g_edxcap = 0xDEADBEEF, g_edxval = 0;
volatile unsigned g_s1 = 0, g_s2 = 0, g_s3 = 0, g_smark = 0;
volatile unsigned g_w1 = 0, g_w2 = 0;
volatile unsigned g_ldrblk = 0;
volatile unsigned g_after1=0, g_after2=0, g_aftermark=0;
volatile unsigned g_strblk=0;
volatile unsigned g_al1=0,g_al2=0,g_al3=0,g_almark=0;
volatile unsigned g_g1=0,g_g2=0,g_g3=0,g_g4=0,g_gmark=0;
volatile unsigned g_scmark=0;
volatile unsigned g_p1=0,g_p2=0,g_p3=0,g_pmark=0;
volatile unsigned g_r1=0,g_r2=0,g_rmark=0;
volatile unsigned g_rw[4]={0,0,0,0}, g_rwidx[4]={0,0,0,0};
volatile unsigned g_setup[4]={0,0,0,0};
volatile unsigned g_dd[2]={0,0};
volatile unsigned g_ctxblk=0;
volatile unsigned g_t1=0,g_t2=0,g_t3=0,g_t4=0,g_tmark=0;
volatile unsigned g_dv1=0,g_dv2=0,g_dv3=0,g_dvmark=0;
volatile unsigned g_sd[4]={0,0,0,0};
volatile unsigned g_scn=0; volatile int g_scn_n=0;
volatile unsigned g_dr=0; volatile int g_dr_n=0;
volatile unsigned g_em=0; volatile int g_em_n=0;
volatile unsigned g_ebf[4]={0,0,0,0};
volatile unsigned g_up[4]={0,0,0,0};
volatile uint32_t g_ebp_pass = 0;
volatile uint32_t g_std3d_a1 = 0, g_std3d_a2 = 0;
volatile uint32_t g_open_a1 = 0, g_open_a2 = 0;
volatile unsigned g_ty[10];
volatile unsigned g_hw[4]={0,0,0,0};
volatile unsigned g_dev[8];
volatile unsigned g_ld[4];
volatile uint32_t g_lastidx = 0;
volatile unsigned g_t7[2];
volatile unsigned g_up2[2];
volatile unsigned g_fr=0; volatile int g_fr_n=0;
volatile unsigned g_b80=0; volatile int g_b80n=0;
volatile unsigned g_wi=0; volatile int g_wi_n=0;
volatile unsigned g_st=0; volatile int g_st_n=0;
volatile unsigned g_dc=0; volatile int g_dc_n=0;
volatile unsigned g_ab=0; volatile int g_ab_n=0;
volatile unsigned g_ol=0; volatile int g_ol_n=0;
volatile unsigned g_fl[2]={0,0}, g_flmark=0;
volatile unsigned g_sc[2]={0,0};
volatile unsigned g_scblk=0;
volatile unsigned g_csblk=0;
volatile unsigned g_fltblk=0;
volatile unsigned g_wb1=0,g_wb2=0,g_wbmark=0;
volatile unsigned g_wbblk=0;
volatile unsigned g_sel=0,g_selmark=0;
volatile unsigned g_af1=0;
volatile unsigned g_afblk=0;
volatile unsigned g_witlast=0; volatile int g_witn=0; int g_wit_on=-1;
/* Set only while xwa_drive_render is inside sub_004340D0, so render-path probes are not
 * drowned out by the concourse/2D traffic that also runs sub_00433850. */
int g_drv_active = 0;
double _st[8] = {0};   /* shared x87 stack -- see recomp_types.h */
int    _fp_top = 0;
uint32_t g_ebx = 0, g_esi = 0, g_edi = 0;
uint16_t g_seg_cs = 0, g_seg_ds = 0, g_seg_es = 0;
uint16_t g_seg_fs = 0, g_seg_gs = 0, g_seg_ss = 0;

/* Memory base offset (0 for fixed-base mapping) */
ptrdiff_t g_mem_base = 0;

/* XWA_RENDCOUNT: per-stage hit counters for the flight render pipeline, printed from the
 * flight-view blit in com_mocks. Tells us at a glance WHICH stage stops feeding the next. */
/* A zeroed scratch "scene object" for render objects whose ro+0xDD is missing. Guest pointers
 * are host pointers here (g_mem_base == 0), so a normal heap block is directly usable as a
 * guest address -- and unlike a hard-coded guest address it cannot collide with real game data
 * (0x00B0FA00 did, and corrupted the heap). */
/* Per-object stand-in scene records. One shared scratch was wrong: every render object we
 * fixed up pointed at the SAME block, so they scribbled over each other (its position came
 * back as 2.59e36 garbage) and the transform read a nonsense object. Give each index its own
 * record, seeded with a position in front of the camera so the perspective divide gets a
 * non-zero depth instead of 640/0. */
#define XWA_SCENE_STRIDE 0x100u
#define XWA_SCENE_COUNT  1200u
/* XWA_FGFILL's render objects for slots past the real pool: pool + i*0xE5 runs into the object
 * table itself beyond entry ~1010 (pool 0x0F045E98, table 0x0F07E708 in a measured run), and the
 * game writes ro fields -- corrupting the table and the heap behind it. One zeroed record each. */
uint32_t xwa_ro_slot(uint32_t idx) {
    static uint8_t* base = NULL;
    if (!base) base = (uint8_t*)calloc(XWA_SCENE_COUNT, XWA_SCENE_STRIDE);
    if (!base || idx >= XWA_SCENE_COUNT) return 0;
    return (uint32_t)(uintptr_t)(base + (size_t)idx * XWA_SCENE_STRIDE);
}

uint32_t xwa_scene_slot(uint32_t idx) {
    static uint8_t* base = NULL;
    if (!base) {
        base = (uint8_t*)calloc(XWA_SCENE_COUNT, XWA_SCENE_STRIDE);
        if (base) {
            for (uint32_t i = 0; i < XWA_SCENE_COUNT; i++) {
                float* f = (float*)(base + (size_t)i * XWA_SCENE_STRIDE);
                f[2] = (float)(((int)(i % 5) - 2) * 700);
                f[3] = (float)(((int)((i / 5) % 5) - 2) * 700);
                f[4] = 3000.0f + (float)(i % 9) * 400.0f;
            }
        }
    }
    if (!base || idx >= XWA_SCENE_COUNT) idx = 0;
    return base ? (uint32_t)(uintptr_t)(base + (size_t)idx * XWA_SCENE_STRIDE) : 0;
}

/* Is this pointer one of OUR fabricated stand-in scene records (rather than a real one the
 * engine built)? Objects backed by a stand-in have no genuine position, so they transform to
 * depth 0 and rasterise as screen-filling inf/NaN garbage -- they should not be drawn at all. */
int xwa_is_stand_in(uint32_t addr) {
    extern uint32_t xwa_scene_slot(uint32_t);
    uint32_t base = xwa_scene_slot(0);
    if (!base || !addr) return 0;
    return addr >= base && addr < base + XWA_SCENE_COUNT * XWA_SCENE_STRIDE;
}

uint32_t xwa_scene_scratch(void) {
    /* Hand out a DISTINCT record per call, rotating through the per-object array. A single
     * shared block meant every guard that fell back here aliased the same memory: consumers
     * scribbled over each other (its position field read back as 2.59e36) and the vertex
     * transform then read an object sitting at the camera, giving depth 0 and 640/0.
     * Each slot is pre-seeded with a position in front of the camera. */
    if (!getenv("XWA_SHAREDSCRATCH")) {
        static uint32_t next = 1;
        uint32_t slot = xwa_scene_slot(next);
        next = (next + 1) % XWA_SCENE_COUNT;
        if (!next) next = 1;
        if (slot) return slot;
    }
    static void* p = NULL;
    if (!p) {
        p = calloc(1, 0x400);
        if (p) {
            /* This block also ends up standing in for a real scene object in the vertex
             * transform (sub_00442820 reads a position at +0x8/+0xC/+0x10 as floats, and the
             * perspective divide is 640 / view-depth). All-zero meant depth 0 -> 640/0 -> inf
             * vertices, so place it well in front of the camera instead of at it. */
            float* f = (float*)p;
            f[2] = 0.0f;      /* +0x8  x */
            f[3] = 0.0f;      /* +0xC  y */
            f[4] = 4096.0f;   /* +0x10 z */
        }
    }
    return (uint32_t)(uintptr_t)p;
}

/* XWA_FPTRAP: unmask FP divide-by-zero/invalid so the very first degenerate divide raises
 * an exception the VEH can locate. The engine transforms vertices itself and is emitting
 * inf/NaN screen coordinates; a float divide does not trap by default, so the damage only
 * surfaces much later as garbage geometry. This turns it into a precise source line. */
void xwa_fptrap_enable(void) {
    static int done = 0;
    if (done || !getenv("XWA_FPTRAP")) return;
    done = 1;
    unsigned cur = 0;
    _controlfp_s(&cur, 0, _EM_ZERODIVIDE | _EM_INVALID);
    fprintf(stderr, "[FPTRAP] float divide-by-zero / invalid now raise\n");
    fflush(stderr);
}

unsigned g_ccount[4];   /* camera chain: sub_00478490 build, sub_004949B0 copy, sub_004EE820 per-craft */
uint32_t g_hostmod_lo = 0, g_hostmod_hi = 0;
unsigned g_texpath[3];
unsigned g_bindfn[8];
unsigned g_objtype[40];
unsigned g_node1;
unsigned g_anyct;
unsigned g_walk[4];
unsigned g_exits[4];
unsigned g_link_n;
unsigned g_subload_n;
unsigned g_bld[4];
unsigned g_cal[8];
unsigned g_bpath;
int g_np[8];
unsigned g_spawnfn[8];
unsigned g_frameblk;
void xwa_dump_surface(unsigned idx, const char* name);   /* defined below, used by the UI driver */
int g_ui_mx = -1, g_ui_my = -1;
int g_ui_click = 0;
int g_ui_down = 0;     /* button held, for drag-and-drop menus */   /* UI driver cursor override, applied inside the game's own mouse update */
int g_in_flight;
/* XWA_BLOCKTRACE: the [G_AB]/[G_DC]/[G_ST]/... block tracers in gen print up to 200000 lines each;
 * off unless asked for (set in main). */
int g_blocktrace;
unsigned g_simcalls;   /* sub_004F6510 (sim update) entries, for XWA_STATUS */

/* XWA_AUTOPLAY=1: a TEST HARNESS that plays 1b0m1fw headlessly, the way XWA_AUTOPILOT types the
 * pilot name. Nobody is at the controls on a test machine, so it drives the game's OWN mechanics and
 * follows the game's OWN feedback (in-flight message ids, via the msg-tap hook):
 *
 *   PICKUP   target C/C Xi 1 (mission FG 1), park 1500 units off it (automatic pickup range is
 *            0x2000 = 0.2 km, checked at 0x00507742) and issue sub_00507510(slot)  -> 0x156 secured
 *   HYPER    target the hyper buoy whose flight group is named for the next stop, park 4000 units
 *            off it (jump range 0.5 km) and press Space                           -> region changes
 *   DELIVER  target the delivery object, park 20000 units off it (docking range 1 km) and issue
 *            sub_00506CB0(slot) ("Shift-D")                                        -> 0x162 delivered
 *   then pick up whatever this region offers (each object is tried until one says 0x14E
 *   "initiating pickup"), hyper home, deliver to the Azzameen base, and return to the hangar.
 *
 * Player record = 0x8B94E0 + slot*0xBCF (slot = MEM32(0x8C1CC8)); target at rec+0x8B9505; region at
 * rec+0x8B94F0. Objects = MEM32(0x7B33C4), stride 0x27: +2 engine type, +5 mission FG index,
 * +7/+0xB/+0xF position; the current region's objects are [MEM32(0x8BF378), MEM32(0x7CA3B8)).
 * Mission FGs at 0x80DC80 + fg*0xE42, name at +0. Runs once a second from d3d11_present; each guest
 * call saves and restores the registers. Every step logs [AUTOPLAY]. */
static uint32_t g_msg_ring[16]; static unsigned g_msg_n;
void xwa_msg_tap(uint32_t id) {
    g_msg_ring[g_msg_n++ & 15] = id;
    if (getenv("XWA_AUTOPLAY")) { fprintf(stderr, "[AUTOPLAY] msg 0x%X\n", id); fflush(stderr); }
}
static int msg_seen_since(unsigned mark, uint32_t id) {
    unsigned i;
    for (i = mark; i != g_msg_n; i++) if (g_msg_ring[i & 15] == id) return 1;
    return 0;
}
static void guest_call1(void (*fn)(void), uint32_t arg) {
    uint32_t s_eax = g_eax, s_ecx = g_ecx, s_edx = g_edx, s_ebx = g_ebx, s_esi = g_esi, s_edi = g_edi, s_ebp = g_ebp;
    g_esp -= 4; MEM32(g_esp) = arg;
    g_esp -= 4; MEM32(g_esp) = 0xDEAD0000u;
    fn();                               /* its `esp += 4; return` pops the dummy return address */
    g_esp += 4;                         /* cdecl: caller pops the argument */
    g_eax = s_eax; g_ecx = s_ecx; g_edx = s_edx; g_ebx = s_ebx; g_esi = s_esi; g_edi = s_edi; g_ebp = s_ebp;
}
static const char *fg_name(uint32_t fg) {
    return (fg < 0x100u) ? (const char *)(uintptr_t)ADDR(0x80DC80u + fg * 0xE42u) : "";
}
/* the mission FG whose cargo (FG+0x28) is `cargo`, or -1 */
static int fg_by_cargo(const char *cargo) {
    for (uint32_t fg = 0; fg < 64; fg++)
        if (!strcmp((const char *)(uintptr_t)ADDR(0x80DC80u + fg * 0xE42u + 0x28), cargo)) return (int)fg;
    return -1;
}
/* first object in the current region matching a mission FG index (or any FG if fg < 0) and engine
 * type (any if type < 0), whose FG name contains `name` (any if NULL); skips `skip` matches */
static uint32_t find_obj(int fg, int type, const char *name, int skip) {
    uint32_t tbl = MEM32(0x7B33C4), i, n = MEM32(0x7CA3B8);
    if (n > 0x3000u) n = 0x3000u;
    for (i = MEM32(0x8BF378); i < n; i++) {
        uint32_t o = tbl + i * 0x27u;
        if (!MEM16(o + 2)) continue;
        if (fg >= 0 && MEM8(o + 5) != (uint32_t)fg) continue;
        if (type >= 0 && MEM16(o + 2) != (uint32_t)type) continue;
        if (name && !strstr(fg_name(MEM8(o + 5)), name)) continue;
        if (skip-- > 0) continue;
        return i;
    }
    return 0xFFFFu;
}
static void dump_region(void) {
    uint32_t tbl = MEM32(0x7B33C4), i, n = MEM32(0x7CA3B8);
    if (n > 0x3000u) n = 0x3000u;
    fprintf(stderr, "[AUTOPLAY] region objects [%u,%u):", MEM32(0x8BF378), n);
    for (i = MEM32(0x8BF378); i < n; i++) {
        uint32_t o = tbl + i * 0x27u;
        if (MEM16(o + 2)) fprintf(stderr, " %u:fg%u/t%u/%.12s", i, MEM8(o + 5), MEM16(o + 2), fg_name(MEM8(o + 5)));
    }
    fprintf(stderr, "\n"); fflush(stderr);
}
static void park_at(uint32_t pidx, uint32_t obj, int off) {
    uint32_t tbl = MEM32(0x7B33C4), po = tbl + pidx * 0x27u, co = tbl + obj * 0x27u;
    MEM32(po + 7) = MEM32(co + 7); MEM32(po + 0xB) = MEM32(co + 0xB) - off; MEM32(po + 0xF) = MEM32(co + 0xF);
}
/* park `off` units from obj along axis dir (0..5 = -Y,+Y,-X,+X,-Z,+Z) */
static void park_dir(uint32_t pidx, uint32_t obj, int off, int dir) {
    uint32_t tbl = MEM32(0x7B33C4), po = tbl + pidx * 0x27u, co = tbl + obj * 0x27u;
    static const signed char ax[6][3] = { {0,-1,0}, {0,1,0}, {-1,0,0}, {1,0,0}, {0,0,-1}, {0,0,1} };
    MEM32(po + 7) = MEM32(co + 7) + ax[dir][0] * off; MEM32(po + 0xB) = MEM32(co + 0xB) + ax[dir][1] * off;
    MEM32(po + 0xF) = MEM32(co + 0xF) + ax[dir][2] * off;
}
void xwa_autoplay_tick(void) {
    extern void sub_00507510(void), sub_00506CB0(void), sub_005079F0(void), xwa_queue_key(uint32_t);
    enum { WAIT, PICK1, SWAP, HYPER1, DELIVER1, PICK2, HYPER2, DELIVER2, LAND, DONE };
    static const char *const sname[] = { "WAIT", "PICK1", "SWAP", "HYPER1", "DELIVER1", "PICK2", "HYPER2", "DELIVER2", "LAND", "DONE" };
    static int on = -1, st = WAIT, tries, skip, trip, hangar, entered; static DWORD last; static unsigned mark; static uint32_t region0;
    uint32_t slot, rec, pidx, obj, region;
    DWORD now = GetTickCount();
    if (on < 0) on = getenv("XWA_AUTOPLAY") ? 1 : 0;
    if (!on || now - last < 1500) return;
    last = now;
    if (!g_in_flight || !MEM32(0x7B33C4)) return;
    slot = MEM32(0x8C1CC8); rec = slot * 0xBCFu;
    pidx = MEM32(rec + 0x8B94E0); region = MEM8(rec + 0x8B94F0);
    if (pidx == 0xFFFFu || pidx > 0x3000u) return;
    {   /* XWA_WATCHOBJ=n: hardware write-watch on object n's X, to name the code that moves it */
        static int armed; extern void xwa_watch_set(uint32_t);
        if (!armed && getenv("XWA_WATCHGATE")) {   /* Selu's AI countdown, order block +0x32 */
            uint32_t ro3 = MEM32(MEM32(0x7B33C4) + 3 * 0x27u + 0x23);
            if (ro3 && MEM32(ro3 + 0xDD)) { armed = 1; xwa_watch_set(MEM32(ro3 + 0xDD) + (getenv("XWA_WATCHOFF") ? (uint32_t)strtoul(getenv("XWA_WATCHOFF"), NULL, 0) : 0x5Au)); } }   /* craft offset: 0x84 order cmd, 0x60 order target */
        if (!armed && getenv("XWA_WATCHOBJ")) {   /* n or n:off (field offset, default 7 = X) */
            const char *w = getenv("XWA_WATCHOBJ"), *c = strchr(w, ':');
            armed = 1; xwa_watch_set(MEM32(0x7B33C4) + (uint32_t)atoi(w) * 0x27u + (c ? (uint32_t)strtoul(c + 1, NULL, 0) : 7u)); } }
    {   static int k; uint32_t t = MEM32(0x7B33C4);
        if ((k++ % 8) == 0) { fprintf(stderr, "[AUTOPLAY] pos: clock=%02u:%02u:%02u pidx=%u alt(96CC)=%u f5=%u f3=%u player(%d,%d,%d) obj3(%d,%d,%d) obj2(%d,%d,%d) docked=%u\n",
            MEM8(0x8053F7), MEM8(0x8053F8), MEM8(0x8053F9), pidx, MEM32(rec + 0x8B96CC), MEM8(rec + 0x8B94F5), MEM8(rec + 0x8B94F3), (int32_t)MEM32(t + pidx*0x27u + 7), (int32_t)MEM32(t + pidx*0x27u + 0xB), (int32_t)MEM32(t + pidx*0x27u + 0xF),
            (int32_t)MEM32(t + 3*0x27u + 7), (int32_t)MEM32(t + 3*0x27u + 0xB), (int32_t)MEM32(t + 3*0x27u + 0xF),
            (int32_t)MEM32(t + 2*0x27u + 7), (int32_t)MEM32(t + 2*0x27u + 0xB), (int32_t)MEM32(t + 2*0x27u + 0xF), MEM32(0x9C6750));
            {   /* Selu's AI: script id (order+0x2A, names at 0x7FFDA0 stride 0x55), runtime cmd, region */
                uint32_t ro3 = MEM32(t + 3 * 0x27u + 0x23), cr3 = ro3 ? MEM32(ro3 + 0xDD) : 0;
                uint32_t rop = MEM32(t + pidx * 0x27u + 0x23), crp = rop ? MEM32(rop + 0xDD) : 0;
                fprintf(stderr, "[AUTOPLAY] fg pickup counters (0x7B703E+fg*0x172): fg1=%u fg2=%u | flag(0x7B7076) fg1=%u fg2=%u\n",
                    MEM16(0x7B703Eu + 1 * 0x172u), MEM16(0x7B703Eu + 2 * 0x172u), MEM8(0x7B7076u + 1 * 0x172u), MEM8(0x7B7076u + 2 * 0x172u));
                if (cr3) fprintf(stderr, "[AUTOPLAY] selu ai: script %u '%s' cmd 0x%02X tgt %u region %u | player order cmd 0x%02X tgt %u phase %u\n", MEM8(cr3 + 0x52),
                    (const char*)ADDR(0x7FFDA0u + MEM8(cr3 + 0x52) * 0x55u), MEM8(cr3 + 0x84), MEM16(cr3 + 0x60), MEM8(t + 3 * 0x27u + 6),
                    crp ? MEM8(crp + 0x84) : 0, crp ? MEM16(crp + 0x60) : 0, crp ? MEM8(crp + 0x85) : 0); }
            fflush(stderr); } }
    if (getenv("XWA_AIOP")) {   /* Selu's AI gate: order block (craft+0x28) +0x32 countdown, +0x2E interval */
        uint32_t ro3 = MEM32(MEM32(0x7B33C4) + 3 * 0x27u + 0x23), cr3 = ro3 ? MEM32(ro3 + 0xDD) : 0;
        uint32_t ps3 = MEM32(MEM32(0x7B33C4) + 3 * 0x27u + 0x1F);
        if (cr3) { fprintf(stderr, "[AUTOPLAY] selu gate: +32=%d +2E=%d cmd=0x%02X slot=%d F6=%u 96F9=%u 96FB=%u | myslot=%u myF6=%u | obj3+4=%u obj%u+4=%u obj2+4=%u\n",(int32_t)MEM32(cr3 + 0x5A), (int32_t)MEM32(cr3 + 0x56), MEM8(cr3 + 0x84),
            (int32_t)ps3, ps3 < 16 ? MEM8(ps3 * 0xBCFu + 0x8B94F6) : 0, ps3 < 16 ? MEM16(ps3 * 0xBCFu + 0x8B96F9) : 0, ps3 < 16 ? MEM16(ps3 * 0xBCFu + 0x8B96FB) : 0, slot, MEM8(rec + 0x8B94F6), MEM8(MEM32(0x7B33C4) + 3 * 0x27u + 4), pidx, MEM8(MEM32(0x7B33C4) + pidx * 0x27u + 4), MEM8(MEM32(0x7B33C4) + 2 * 0x27u + 4)); fflush(stderr); } }
    {   /* Selu's craft struct (obj 3: [[obj+0x23]+0xDD]), first 0x180 bytes, printed when it changes */
        static uint8_t prevc[0x180]; static int have; uint32_t t3 = MEM32(0x7B33C4) + (getenv("XWA_DIFFOBJ") ? (uint32_t)atoi(getenv("XWA_DIFFOBJ")) : 3u) * 0x27u, ro = MEM32(t3 + 0x23), cr;
        extern int xwa_readable(uint32_t, uint32_t);
        if (ro && xwa_readable(ro + 0xDD, 4) && (cr = MEM32(ro + 0xDD)) && xwa_readable(cr, 0x180)) {
            int j; if (have && getenv("XWA_SELUDIFF")) { fprintf(stderr, "[AUTOPLAY] selu craft 0x%08X diff:", cr);
                for (j = 0; j < 0x180; j++) if (MEM8(cr + j) != prevc[j]) fprintf(stderr, " +%X:%02X>%02X", j, prevc[j], MEM8(cr + j));
                fprintf(stderr, "\n"); }
            for (j = 0; j < 0x180; j++) prevc[j] = MEM8(cr + j); have = 1;
            { static int kk; if ((kk++ % 8) == 0) { fprintf(stderr, "[AUTOPLAY] selu cmd=0x%02X tgt=%u CC=%04X D4=%04X DB=%04X 8E=%04X F0=%04X\n",
                MEM8(cr + 0x84), MEM16(cr + 0x60), MEM16(cr + 0xCC), MEM16(cr + 0xD4), MEM16(cr + 0xDB), MEM16(cr + 0x8E), MEM16(cr + 0xF0)); fflush(stderr); } }
            if (getenv("XWA_SELUSPEED") && MEM8(cr + 0x84) == 0x12 && !MEM16(cr + 0xD4)) {
                MEM16(cr + 0xCC) = 0x4000; MEM16(cr + 0xD4) = 0x4000; MEM16(cr + 0xDB) = 0x4000;
                fprintf(stderr, "[AUTOPLAY] SELUSPEED applied\n"); fflush(stderr); } } }
    if (getenv("XWA_OBJDIFF")) {   /* object records 0 (player) and 3 (Selu): 0x27 bytes each */
        static uint8_t pv[2][0x27]; static int hv; int a, j; uint32_t t = MEM32(0x7B33C4);
        for (a = 0; a < 2; a++) { uint32_t o = t + (a ? 3u : pidx) * 0x27u;
            if (hv) { fprintf(stderr, "[AUTOPLAY] obj%d diff:", a ? 3 : (int)pidx);
                for (j = 0; j < 0x27; j++) if (MEM8(o + j) != pv[a][j]) fprintf(stderr, " +%X:%02X>%02X", j, pv[a][j], MEM8(o + j));
                fprintf(stderr, "\n"); }
            for (j = 0; j < 0x27; j++) pv[a][j] = MEM8(o + j); }
        hv = 1; fflush(stderr); }

    if (MEM8(rec + 0x8B94F3)) return;                 /* a pickup / docking manoeuvre is flying */
#define NEXT(s) do { fprintf(stderr, "[AUTOPLAY] %s -> %s (region %u)\n", sname[st], sname[s], region); fflush(stderr); \
                     st = (s); tries = 0; skip = 0; mark = g_msg_n; region0 = region; } while (0)
#define GIVEUP(why) do { fprintf(stderr, "[AUTOPLAY] %s: giving up (%s)\n", sname[st], why); fflush(stderr); st = DONE; } while (0)
    switch (st) {
    case WAIT:
        if (MEM32(0x68BBA0) >= 4) {   /* the hangar launch has finished ... */
            /* ... and the player has been moved into the space region: its object is inside the
             * region range, is the YT-1300, and has been placed (the exit leaves it in the hangar
             * partition, or at 0,0,0, for a while) */
            static int settle; uint32_t po = MEM32(0x7B33C4) + pidx * 0x27u;
            if (pidx >= MEM32(0x8BF378) && pidx < MEM32(0x7CA3B8) && MEM16(po + 2) == 58 &&
                (MEM32(po + 7) | MEM32(po + 0xB) | MEM32(po + 0xF)) && ++settle > 3) NEXT(PICK1);
            break; }
        /* "> Launch <" is the hangar menu's default item: ENTER until the launch starts
         * (9C6954 = launch requested). No keys after that -- nothing else should be pressed. */
        if (MEM32(0x9C6750) && !MEM32(0x9C6954)) xwa_queue_key(0x1C);
        break;
    case PICK1: case PICK2:
        if (st == PICK2 && trip) {   /* second trip: the coolant again, kept this time, for delivery home */
            int fgc = fg_by_cargo("Realgar"); uint32_t i, sp, tb = MEM32(0x7B33C4);
            if (msg_seen_since(mark, 0x156)) { NEXT(HYPER2); break; }
            if (fgc < 0) { GIVEUP("no coolant flight group"); break; }
            sp = MEM8(0x80DC80u + (uint32_t)fgc * 0xE42u + 0x69);
            for (obj = 0xFFFFu, i = MEM32(0x8BF378); i < MEM32(0x7CA3B8) && i < 0x3000u; i++) {
                uint32_t o = tb + i * 0x27u, ro = MEM32(o + 0x23);
                if (MEM16(o + 2) && MEM8(o + 5) == (uint32_t)fgc && ro && MEM32(ro + 0xDD) && MEM8(MEM32(ro + 0xDD) + 0xE2) == sp) { obj = i; break; }
            }
            if (obj == 0xFFFFu) { GIVEUP("coolant container gone"); break; }
            MEM16(rec + 0x8B9505) = (uint16_t)obj; park_dir(pidx, obj, 1500, 5);
            fprintf(stderr, "[AUTOPLAY] PICK2 (trip 2): coolant obj %u\n", obj); fflush(stderr);
            mark = g_msg_n; guest_call1(sub_00507510, slot);
            if (++tries > 20) GIVEUP("coolant pickup failed");
            break;
        }
        if (st == PICK2) {
            /* FG24 "Return Home" arrives on fuel cells (FG15) AND the coolant -- FG17's special craft,
             * Aeron's job -- picked up. Selu never gets here, so take the coolant first, release it
             * (the trigger counts the pickup), then the fuel cells. Special craft: craft+0xE2 ==
             * FG+0x69, the test sub_004B65E0 makes before setting the flag at 0x7B7076+fg*0x172. */
            static int cool;   /* 0 pick coolant, 1 release it, 2 done */
            int fgc = fg_by_cargo("Realgar");
            if (cool == 0 && fgc >= 0 && !MEM8(0x7B7076u + (uint32_t)fgc * 0x172u)) {
                uint32_t i, sp = MEM8(0x80DC80u + (uint32_t)fgc * 0xE42u + 0x69), tb = MEM32(0x7B33C4);
                for (obj = 0xFFFFu, i = MEM32(0x8BF378); i < MEM32(0x7CA3B8) && i < 0x3000u; i++) {
                    uint32_t o = tb + i * 0x27u, ro = MEM32(o + 0x23);
                    if (MEM16(o + 2) && MEM8(o + 5) == (uint32_t)fgc && ro && MEM32(ro + 0xDD) && MEM8(MEM32(ro + 0xDD) + 0xE2) == sp) { obj = i; break; }
                }
                if (obj != 0xFFFFu) {
                    MEM16(rec + 0x8B9505) = (uint16_t)obj; park_dir(pidx, obj, 1500, 5);   /* from above: the containers stand in a row along Y */
                    fprintf(stderr, "[AUTOPLAY] PICK2: coolant (fg %d special craft %u) obj %u\n", fgc, sp, obj); fflush(stderr);
                    mark = g_msg_n; guest_call1(sub_00507510, slot);
                    if (++tries > 20) cool = 2;
                    break;
                }
            }
            if (cool == 0 && fgc >= 0 && MEM8(0x7B7076u + (uint32_t)fgc * 0x172u)) {
                fprintf(stderr, "[AUTOPLAY] PICK2: coolant picked up, releasing it\n"); fflush(stderr);
                guest_call1(sub_005079F0, slot); cool = 1; tries = 0; mark = g_msg_n; break;
            }
            if (cool == 1) { cool = 2; break; }   /* one tick for the release to land */
        }
        if (msg_seen_since(mark, 0x156)) { NEXT(st == PICK1 ? (getenv("XWA_SWAP") ? SWAP : HYPER1) : HYPER2); break; }
        if (msg_seen_since(mark, 0x151)) { NEXT(st == PICK1 ? HYPER1 : HYPER2); break; }   /* already carrying */
        obj = (st == PICK1) ? find_obj(1, -1, NULL, 0) : find_obj(fg_by_cargo("Fuel Cells"), -1, NULL, skip);   /* FG15 "Pi": the Return Home buoy waits on it */
        if (obj == 0xFFFFu) { GIVEUP("nothing left to try"); break; }
        if (obj == pidx) { skip++; break; }
        if (tries && st == PICK2 && !msg_seen_since(mark, 0x14E)) skip++;              /* not pickable */
        MEM16(rec + 0x8B9505) = (uint16_t)obj; if (st == PICK2) park_dir(pidx, obj, 1500, 5); else park_at(pidx, obj, 1500);
        fprintf(stderr, "[AUTOPLAY] %s: target obj %u (fg %u '%s' type %u) at (%d,%d,%d)\n", sname[st], obj,
                MEM8(MEM32(0x7B33C4) + obj * 0x27u + 5), fg_name(MEM8(MEM32(0x7B33C4) + obj * 0x27u + 5)),
                MEM16(MEM32(0x7B33C4) + obj * 0x27u + 2), (int32_t)MEM32(MEM32(0x7B33C4) + obj * 0x27u + 7),
                (int32_t)MEM32(MEM32(0x7B33C4) + obj * 0x27u + 0xB), (int32_t)MEM32(MEM32(0x7B33C4) + obj * 0x27u + 0xF)); fflush(stderr);
        mark = g_msg_n; guest_call1(sub_00507510, slot);
        {   static int wp; extern void xwa_watch_set(uint32_t);   /* XWA_WATCHPICK: who moves the player next */
            if (!wp && getenv("XWA_WATCHPICK")) { wp = 1; xwa_watch_set(MEM32(0x7B33C4) + pidx * 0x27u + 0xB); }
            if (!wp && getenv("XWA_WATCHPCMD")) {   /* the player's order cmd: who drops the pickup claim */
                uint32_t rop = MEM32(MEM32(0x7B33C4) + pidx * 0x27u + 0x23);
                if (rop && MEM32(rop + 0xDD)) { wp = 1; xwa_watch_set(MEM32(rop + 0xDD) + 0x84); } } }
        if (++tries > 40) GIVEUP("too many tries");
        break;
    case SWAP:
        /* Experiment: the jump buoy may only arrive once BOTH canisters have been picked up (the
         * wingman is meant to take Xi 2). Release Xi 1 (sub_005079F0, "Object released" 0x161),
         * pick up Xi 2, then come back for Xi 1. */
        if (tries == 0) { mark = g_msg_n; guest_call1(sub_005079F0, slot); tries = 1; break; }
        if (tries == 1) { obj = find_obj(2, -1, NULL, 0); if (obj == 0xFFFFu) { GIVEUP("no Xi 2"); break; }
            /* the wingman holds Xi 2 "targeted for pickup" (object +0x1F, -1 = free) but never flies
             * to it; take the claim back so the player can do its job */
            {   uint32_t so = find_obj(3, -1, NULL, 0), ro, cr;   /* Selu: its order targets Xi 2 */
                if (so != 0xFFFFu && (ro = MEM32(MEM32(0x7B33C4) + so * 0x27u + 0x23)) && (cr = MEM32(ro + 0xDD)))
                    MEM16(cr + 0x28 + 0x38) = 0xFFFF; }
            MEM16(rec + 0x8B9505) = (uint16_t)obj; park_at(pidx, obj, 1500); mark = g_msg_n; guest_call1(sub_00507510, slot); tries = 2; break; }
        if (tries == 2) { if (msg_seen_since(mark, 0x156)) { dump_region(); guest_call1(sub_005079F0, slot); tries = 3; } break; }
        if (tries == 3) { obj = find_obj(1, -1, NULL, 0); MEM16(rec + 0x8B9505) = (uint16_t)obj; park_at(pidx, obj, 1500);
            mark = g_msg_n; guest_call1(sub_00507510, slot); tries = 4; break; }
        if (msg_seen_since(mark, 0x156)) { dump_region(); NEXT(HYPER1); }
        break;
    case HYPER1: case HYPER2:
        if (getenv("XWA_THROTTLETEST") && tries < 6) xwa_queue_key(0x0E);   /* Backspace = full throttle */
        if (region != region0) { NEXT(st == HYPER1 ? (trip ? PICK2 : DELIVER1) : DELIVER2); break; }
        obj = find_obj(-1, 218, st == HYPER1 ? "Harlequin" : "Home", 0);   /* FG24 "Return Home" arrives once the fuel cells (FG15) are picked up */
        if (tries % 20 == 0) {   /* every hyper buoy (type 218) in every region, to see what the mission spawned */
            uint32_t i, tb = MEM32(0x7B33C4); fprintf(stderr, "[AUTOPLAY] buoys:");
            for (i = 0; i < 2000; i++) { uint32_t o = tb + i * 0x27u; if (MEM16(o + 2) == 218)
                fprintf(stderr, " %u:fg%u '%s' r%u", i, MEM8(o + 5), fg_name(MEM8(o + 5)), MEM8(o + 6)); }
            fprintf(stderr, "\n"); fflush(stderr); }
        if (obj == 0xFFFFu) { if (tries % 10 == 0) dump_region(); if (++tries > 60) GIVEUP("no hyper buoy appeared"); break; }
        MEM16(rec + 0x8B9505) = (uint16_t)obj; park_at(pidx, obj, 4000);
        {   /* "follow Aeron": give Selu (obj 3, fg 3) time to jump first, as a flown approach would */
            uint32_t s3 = MEM32(0x7B33C4) + 3 * 0x27u;
            int selu_here = st == HYPER1 && !trip && getenv("XWA_WAITSELU") && MEM16(s3 + 2) && MEM8(s3 + 5) == 3 && MEM8(s3 + 6) == region0;
            if (selu_here && tries < 40) { if (tries++ % 8 == 0) { fprintf(stderr, "[AUTOPLAY] %s: at buoy, waiting for Selu (obj3 at %d,%d,%d cmd 0x%02X)\n", sname[st],
                (int32_t)MEM32(s3 + 7), (int32_t)MEM32(s3 + 0xB), (int32_t)MEM32(s3 + 0xF), MEM32(s3 + 0x23) ? MEM8(MEM32(MEM32(s3 + 0x23) + 0xDD) + 0x84) : 0); fflush(stderr); } break; } }
        fprintf(stderr, "[AUTOPLAY] %s: buoy obj %u '%s', pressing Space\n", sname[st], obj, fg_name(MEM8(MEM32(0x7B33C4) + obj * 0x27u + 5))); fflush(stderr);
        xwa_queue_key(0x39);
        if (++tries > 70) GIVEUP("no jump");
        break;
    case DELIVER1: case DELIVER2:
        if (msg_seen_since(mark, 0x162)) {
            /* mission complete = MEM8(0x807A60 + team*3) (team: player record +0x8B94EC); the hangar
             * offers "Go to Debriefing" only then. Still open after the fuel cells: the coolant
             * (Aeron's, she never comes) -- go back for it */
            uint32_t team = MEM16(rec + 0x8B94EC), done = MEM8(0x807A60u + team * 3u);
            fprintf(stderr, "[AUTOPLAY] %s: delivered; mission complete flag (team %u) = %u, failed = %u\n", sname[st], team, done, MEM8(0x807A61u + team * 3u)); fflush(stderr);
            if (st == DELIVER2 && !done && !trip) { trip = 1; NEXT(HYPER1); break; }
            NEXT(st == DELIVER1 ? PICK2 : LAND); break; }
        obj = (st == DELIVER1) ? find_obj(13, -1, NULL, 0) : find_obj(4, -1, NULL, 0);
        if (obj == 0xFFFFu) { dump_region(); GIVEUP("no delivery target in this region"); break; }
        if (!tries) { dump_region();
            if (getenv("XWA_FGDUMP")) {   /* Selu's flight group record (orders + triggers), for offline decoding */
                FILE *fd = fopen("fg3.bin", "wb"); if (fd) { fwrite((void*)ADDR(0x80DC80u + 3 * 0xE42u), 1, 0xE42, fd); fclose(fd); }
                fd = fopen("fg13.bin", "wb"); if (fd) { fwrite((void*)ADDR(0x80DC80u + 13 * 0xE42u), 1, 0xE42, fd); fclose(fd); }
                fd = fopen("fg0.bin", "wb"); if (fd) { fwrite((void*)ADDR(0x80DC80u), 1, 0xE42, fd); fclose(fd); }
                fd = fopen("fgall.bin", "wb"); if (fd) { fwrite((void*)ADDR(0x80DC80u), 1, 0xE42 * 32, fd); fclose(fd); }
                fd = fopen("aiscripts.bin", "wb"); if (fd) { fwrite((void*)ADDR(0x7FFDA0u), 1, 0x55 * 64, fd); fclose(fd); } } }   /* AI script names */
        MEM16(rec + 0x8B9505) = (uint16_t)obj; park_dir(pidx, obj, 20000, (tries / 2) % 6);   /* the dock ray test needs a docking point in view */
        {   uint32_t rop = MEM32(MEM32(0x7B33C4) + pidx * 0x27u + 0x23), crp = rop ? MEM32(rop + 0xDD) : 0;
            fprintf(stderr, "[AUTOPLAY] %s: dock with obj %u '%s' dir %d, carrying obj %u\n", sname[st], obj, fg_name(MEM8(MEM32(0x7B33C4) + obj * 0x27u + 5)),
                    (tries / 2) % 6, crp ? MEM16(crp + 0x185) : 0xFFFFu); fflush(stderr); }
        mark = g_msg_n; guest_call1(sub_00506CB0, slot);
        if (++tries > 200) GIVEUP("no delivery");   /* the platform takes ours only after Selu has delivered */
        break;
    case LAND:
        /* "Hit [Space] to activate tractor beam and enter hangar" (0x117) appears near the base */
        if (MEM32(0x68BBA0) == 6) {   /* in the hangar: hands off (re-parking breaks the tractor-in) */
            /* the hangar menu is now "= MISSION COMPLETED =", item 0 "Go to Debriefing" (STRINGS.TXT
             * MISSION_OVER_DEBRIEF); ENTER selects it, as it selected Launch on the way out */
            {   uint32_t team = MEM16(rec + 0x8B94EC);   /* the menu builder copies its title to 0x68BC40 */
                fprintf(stderr, "[AUTOPLAY] LAND: in the hangar (hstate=6), map=0x%X, menu '%.40s', complete=%u, item %u, 80B604=%u 80DB68=%u%s\n", MEM16(0x9C6754),
                        (const char *)ADDR(0x68BC40u), MEM8(0x807A60u + team * 3u), MEM32(0x68BC28), MEM32(0x80B604), MEM8(0x80DB68), tries > 4 ? ", ENTER" : ""); fflush(stderr);
                /* mission-over menu: item 0 "Go to Debriefing" sets 0x80B604 = 1, item 2 "Refly" = 2
                 * (sub_0045C680 @0x0045CF09); put the cursor on item 0 as a player would */
                if (MEM8(0x807A60u + team * 3u) == 1 && !entered) MEM32(0x68BC28) = 0; }
            hangar = 1;
            if (tries > 4 && entered < 3 && tries % 4 == 0) { xwa_queue_key(0x1C); entered++; }   /* a few presses, logged by the [ENTER] probe */
            if (++tries > 80) GIVEUP("no debriefing"); break; }
        if (hangar) {   /* left the hangar after ENTER: watch, never press Space (Space launches) */
            fprintf(stderr, "[AUTOPLAY] LAND: after the hangar: hstate=%u 80B604=%u 68BBB8=%u\n", MEM32(0x68BBA0), MEM32(0x80B604), MEM32(0x68BBB8)); fflush(stderr);
            if (++tries > 80) GIVEUP("stuck after the hangar"); break; }
        obj = find_obj(4, -1, NULL, 0);
        if (obj != 0xFFFFu && !msg_seen_since(mark, 0x117)) { MEM16(rec + 0x8B9505) = (uint16_t)obj; park_at(pidx, obj, 3000 + tries * 500); }
        if (msg_seen_since(mark, 0x117) || tries > 3) xwa_queue_key(0x39);
        fprintf(stderr, "[AUTOPLAY] LAND: try %d hstate=%u docked=%u\n", tries, MEM32(0x68BBA0), MEM32(0x9C6750)); fflush(stderr);
        if (++tries > 40) GIVEUP("could not land");
        break;
    default: break;
    }
#undef NEXT
#undef GIVEUP
}

/* XWA_STATUS=N: every N presented frames (called from d3d11_present), one line of campaign state:
 * the screen, the hangar/launch flags, the player's camera position and the mission clock. Unlike
 * the native-draw dumps it keeps running for the whole flight, so a long headless run shows where
 * the mission got to and whether the world is moving at all. */
void xwa_status_tick(unsigned frame) {
    /* XWA_STATUS=<ms>: rate-limited by wall clock, because the flight loop does not present
     * through d3d11_present every frame -- it is also called from the flight object walk. */
    static int every = -1; static DWORD last;
    uint32_t cam; DWORD now = GetTickCount();
    {   /* XWA_HEAPWATCH=1: validate the guest's heap and the process heap each tick; report the first
         * tick that fails with the call count, so XWA_HEAPCHECKFROM=<calls> can arm per-call checks */
        static int hw = -1, bad; static unsigned ok_calls; extern uint32_t g_last_heapalloc_heap;
        if (hw < 0) hw = getenv("XWA_HEAPWATCH") != NULL;
        if (hw) { extern void com_check_surface_guards(void); com_check_surface_guards(); }
        if (hw && !bad) {
            HANDLE gh = (HANDLE)(uintptr_t)g_last_heapalloc_heap;
            int g_ok = !gh || HeapValidate(gh, 0, NULL), p_ok = HeapValidate(GetProcessHeap(), 0, NULL);
            if (g_ok && p_ok) ok_calls = g_total_calls;
            else { bad = 1; fprintf(stderr, "[HEAPWATCH] corrupt: guest heap %s, process heap %s; last ok at call %u, now call %u frame %u\n",
                       g_ok ? "ok" : "BAD", p_ok ? "ok" : "BAD", ok_calls, g_total_calls, frame); fflush(stderr); } } }
    {   extern int g_heap_check_enabled; static int from = -1;
        if (from < 0) from = getenv("XWA_HEAPCHECKFROM") ? (int)strtoul(getenv("XWA_HEAPCHECKFROM"), NULL, 0) : 0;
        if (from > 0 && g_total_calls >= (unsigned)from && !g_heap_check_enabled) { g_heap_check_enabled = 1; from = 0;
            fprintf(stderr, "[HEAPWATCH] per-call heap checks on at call %u\n", g_total_calls); fflush(stderr); } }
    if (every < 0) every = getenv("XWA_STATUS") ? atoi(getenv("XWA_STATUS")) : 0;
    if (every <= 0 || now - last < (DWORD)every) return;
    last = now;
    cam = MEM32(0x8C1CC8) * 0xBCFu + 0x8BA028u;
    fprintf(stderr, "[STATUS] f=%u inflight=%d hstate(68BBA0)=%u docked(9C6750)=%u map(9C6754)=0x%X "
            "end(68BBB8)=%u 9C6954=%u 80B604=%u cam=(%d,%d,%d) calls=%u sim=%u ai[8D9628..8BF368)=[%u,%u) cmd(7CA1CC)=0x%X region[8BF378..7CA3B8)=[%u,%u)\n",
            frame, g_in_flight, MEM32(0x68BBA0), MEM32(0x9C6750), (unsigned)MEM16(0x9C6754),
            MEM32(0x68BBB8), MEM32(0x9C6954), MEM32(0x80B604),
            (int32_t)MEM32(cam), (int32_t)MEM32(cam + 4), (int32_t)MEM32(cam + 8), g_total_calls, g_simcalls, MEM16(0x8D9628), MEM32(0x8BF368), MEM32(0x7CA1CC), MEM32(0x8BF378), MEM32(0x7CA3B8));
    fflush(stderr);
}

/* XWA_BATCHCHK: validate the render-batch lists (heads 0x686B0C/10/14, free list 0x74C210) against
 * the node pool. Nodes are 0x4E0C bytes, three per chunk; chunks are listed at 0x74C248 as
 * {chunk, next}. The first caller that sees a bad pointer is printed once, with g_lastblk -- this
 * is how the batch-list corruption behind the old L_0048967D crash gets located. */
static int batch_node_ok(uint32_t p) {
    uint32_t c, n = 0;
    if (!p) return 1;
    for (c = MEM32(0x74C248); c && n < 4096; c = MEM32(c + 4), n++) {
        uint32_t base = MEM32(c);
        if (p >= base && p < base + 0xEA24u) return ((p - base) % 0x4E0Cu) == 0;
    }
    return 0;
}
void xwa_batch_check(const char *where) {
    static int on = -1, reported; static uint32_t last_bad;
    static const uint32_t heads[4] = { 0x686B0C, 0x686B10, 0x686B14, 0x74C210 };
    int h;
    if (on < 0) on = getenv("XWA_BATCHCHK") ? 1 : 0;
    if (!on || reported >= 40 || !MEM32(0x74C248)) return;
    for (h = 0; h < 4; h++) {
        uint32_t p = MEM32(heads[h]), prev = heads[h]; int n = 0;
        while (p && n < 4096) {
            if (!batch_node_ok(p)) {
                if (p == last_bad) return;
                last_bad = p; reported++;
                fprintf(stderr, "[BATCHCHK] BAD at %s: list 0x%X node#%d ptr=0x%08X (from 0x%08X) "
                        "lastblk=0x%08X\n", where, heads[h], n, p, prev, g_lastblk);
                fflush(stderr);
                return;
            }
            if (h < 3 && MEM32(p + 0x3000) > 384u) {
                reported++;
                fprintf(stderr, "[BATCHCHK] OVERFULL at %s: list 0x%X node 0x%08X vcount=%u icount=%u lastblk=0x%08X\n",
                        where, heads[h], p, MEM32(p + 0x3000), MEM32(p + 0x4E04), g_lastblk);
                fflush(stderr);
                return;
            }
            prev = p; p = MEM32(p + 0x4E08); n++;
        }
    }
}
int g_ui_snap_req;     /* set by the UI driver, serviced by the present path */       /* set once the flight object walk has run */
unsigned g_loaderblk;
unsigned g_simblk;
unsigned g_dpblk, g_dpblkprev;   /* last blocks inside the DirectPlay session create */
unsigned g_crloopblk;
unsigned g_crloopprev;
unsigned g_partsite;   /* call site that last asked for a partition */  /* block reached just before the create loop exits */  /* last block inside the craft-create loop */
unsigned g_createblk;  /* last block inside the per-craft create */     /* last block reached inside the sim update */  /* last block reached inside the player-craft loader */   /* last block reached inside the flight frame function */   /* candidate mission spawn/update entry points */


/* ============================================================================
 * xwa_native_mesh -- draw the game's own loaded OPT geometry (XWA_NATIVEDRAW).
 *
 * The lifted model renderer (sub_00442F70) is unreachable in this port (#574-#580), so the meshes
 * the engine has already loaded are drawn here instead. OPT runtime blocks are byte-packed and
 * self-describing (#552 + the MESHSCAN probe):
 *     +0x00 = 0    +0x04 = type    +0x10 = count    +0x14 = block+0x18 (inline data)
 *   type 3 = vertex list  (count xyz float triples)
 *   type 1 = face data    (data[0] = face count, then 4 int32 vertex indices per face, -1 = triangle)
 * A mesh's faces are the type-1 blocks between its vertex block and the next type-3 block (one per
 * LOD; the first is the most detailed).
 *
 * The recogniser hands over one mesh at a time and only on a few frames, so meshes are CACHED with
 * the object transform they arrived with and the whole scene is re-emitted on every update.
 * ============================================================================ */
int g_nrot[4];              /* object orientation: yaw, pitch, roll (XwaObject +0x13/+0x15/+0x17) */
int g_camrot[4];            /* player craft orientation = camera orientation (cockpit view) */

#define NMESH_MAX 512
static struct { uint32_t vnode; int obj; int p[3]; int rot[3]; } g_nmesh[NMESH_MAX];
static int g_nmesh_n;

static int xwa_blk(uint32_t a) {
    return xwa_readable(a, 0x20) && MEM32(a) == 0u && MEM32(a + 0x14) == a + 0x18u;
}

static float xwa_f32(uint32_t a) { uint32_t v = MEM32(a); float f; memcpy(&f, &v, 4); return f; }

/* Shared view basis (right / forward / up) -- one camera for the whole scene. */
static double vbx, vby, vbz, vfx, vfy, vfz, vux, vuy, vuz;
/* Eye position. Normally the player craft, but the spectator camera can pull in toward its target:
 * with the mission's real distances a craft a few km out is a handful of pixels, correctly. */
static double vex, vey, vez;

/* The engine's own camera record: playerslot*0xBCF + 0x8BA028 holds the camera POSITION (3 int32)
 * and its orientation as 16-bit angles -- +0x14 pitch, +0x16 yaw, +0x18 roll. Both track the player
 * craft as it flies. Reading them directly beats the old heuristic of borrowing the angles from
 * whichever object happened to sit nearest the camera. */
static void ncam_read(void)
{
    uint32_t base = MEM32(0x8C1CC8) * 0xBCFu + 0x8BA028u;
    if (getenv("XWA_CAMOBJ") || !xwa_readable(base, 0x20)) return;   /* XWA_CAMOBJ = old heuristic */
    g_np[3] = (int32_t)MEM32(base);
    g_np[4] = (int32_t)MEM32(base + 4);
    g_np[5] = (int32_t)MEM32(base + 8);
    g_np[6] = 1;
    g_camrot[1] = (int16_t)MEM16(base + 0x14);      /* pitch */
    g_camrot[0] = (int16_t)MEM16(base + 0x16);      /* yaw */
    g_camrot[2] = (int16_t)MEM16(base + 0x18);      /* roll */
}

static void nview_build(void)
{
    double fx, fy, fz, rxv, ryv, l;
    ncam_read();
    /* Frame the scene when the camera record is not usable. On the engine's own mission-load path
     * the record at playerslot*0xBCF+0x8BA028 is still fill garbage (values around 0x80808080)
     * until the player craft is created, and rendering from it puts every vertex off screen.
     * A camera position that is not a plausible world coordinate can never be right, so fall back
     * to the bounding sphere of the meshes that ARE sane and look at them from outside it.
     * XWA_NOCAMFIT keeps the raw record, for when the record itself is what is being debugged. */
    if (g_nmesh_n > 0 && !getenv("XWA_NOCAMFIT")) {
        const double SANE = 2.0e7;
        /* Also do this for the explicit spectator view: a valid camera record still points where
         * the (not yet created) player craft would be, which on this path is nowhere near the
         * mission's craft. XWA_NLOOKAT means "show me the ships", so stand next to them. */
        if (getenv("XWA_NLOOKAT")
            || fabs((double)g_np[3]) > SANE || fabs((double)g_np[4]) > SANE || fabs((double)g_np[5]) > SANE) {
            double cx = 0, cy = 0, cz = 0, r = 0;
            int q, n = 0;
            for (q = 0; q < g_nmesh_n; q++) {
                if (fabs((double)g_nmesh[q].p[0]) > SANE ||
                    fabs((double)g_nmesh[q].p[1]) > SANE ||
                    fabs((double)g_nmesh[q].p[2]) > SANE) continue;
                cx += g_nmesh[q].p[0]; cy += g_nmesh[q].p[1]; cz += g_nmesh[q].p[2]; n++;
            }
            if (n) {
                /* Stand next to one craft, not outside the whole formation. Backing off by the
                 * bounding radius put the eye 300k units away, where a 200-unit fighter is well
                 * under a pixel -- the frame came back as stars and nothing else. Pick the mesh
                 * nearest the centroid, which is a real cluster member rather than an outlier,
                 * and sit a fixed distance off it. XWA_NCAMDIST=<units> sets that distance. */
                int pick = -1; double bd = 1e30;
                cx /= n; cy /= n; cz /= n;
                for (q = 0; q < g_nmesh_n; q++) {
                    double dx = g_nmesh[q].p[0] - cx, dy = g_nmesh[q].p[1] - cy, dz = g_nmesh[q].p[2] - cz;
                    double d2 = dx*dx + dy*dy + dz*dz;
                    if (d2 > SANE * SANE) continue;
                    if (d2 < bd) { bd = d2; pick = q; }
                }
                if (pick >= 0) { cx = g_nmesh[pick].p[0]; cy = g_nmesh[pick].p[1]; cz = g_nmesh[pick].p[2]; }
                r = getenv("XWA_NCAMDIST") ? atof(getenv("XWA_NCAMDIST")) : 1200.0;
                if (r < 50.0) r = 1200.0;
                g_np[3] = (int)cx;
                g_np[4] = (int)(cy - r);
                g_np[5] = (int)(cz + r * 0.25);
                g_np[6] = 1;
                g_camrot[0] = g_camrot[1] = g_camrot[2] = 0;
                { static int lg; if (lg < 3) { lg++;
                    fprintf(stderr, "[NCAMFIT] standing off %d sane meshes at (%d,%d,%d), dist=%.0f\n",
                            n, (int)cx, (int)cy, (int)cz, r); fflush(stderr); } }
            }
        }
    }
    vex = g_np[3]; vey = g_np[4]; vez = g_np[5];
    if (getenv("XWA_NLOOKAT") && g_nmesh_n > 0) {
        /* Spectator view: aim at the centroid of everything cached, so the whole formation is in
         * one frame. The cockpit camera (below) is the game's real view; here the force-built
         * world puts the wingmen 40-80 degrees off it, which shows an empty sky. */
        int q, best = 0; double bd = 1e30;
        for (q = 0; q < g_nmesh_n; q++) {          /* nearest craft, not the centroid: one stray
                                                    * object drags a centroid off into empty sky */
            double dx = g_nmesh[q].p[0] - (double)g_np[3];
            double dy = g_nmesh[q].p[1] - (double)g_np[4];
            double dz = g_nmesh[q].p[2] - (double)g_np[5];
            double d2 = dx*dx + dy*dy + dz*dz;
            if (d2 > 100.0 && d2 < bd) { bd = d2; best = q; }
        }
        fx = g_nmesh[best].p[0] - (double)g_np[3];
        fy = g_nmesh[best].p[1] - (double)g_np[4];
        fz = g_nmesh[best].p[2] - (double)g_np[5];
        {   double zoom = getenv("XWA_NZOOM") ? atof(getenv("XWA_NZOOM")) : 1.0;
            if (zoom > 1.0) {                       /* move the eye along the sight line */
                double f2 = 1.0 - 1.0 / zoom;
                vex = g_np[3] + fx * f2; vey = g_np[4] + fy * f2; vez = g_np[5] + fz * f2;
            }
        }
    } else {
        double poff = getenv("XWA_NPITCHOFF") ? atof(getenv("XWA_NPITCHOFF")) : 16384.0;
        double cu = g_camrot[0] * 9.5873799e-5, cp = (g_camrot[1] - poff) * 9.5873799e-5;
        fx = -sin(cu) * cos(cp); fy = cos(cu) * cos(cp); fz = sin(cp);
    }
    l = sqrt(fx*fx + fy*fy + fz*fz); if (l < 1e-9) { fx = 0; fy = 1; fz = 0; l = 1; }
    fx /= l; fy /= l; fz /= l;
    rxv = fy; ryv = -fx;                                /* right = forward x world-up(0,0,1) */
    l = sqrt(rxv*rxv + ryv*ryv); if (l < 1e-9) { rxv = 1; ryv = 0; l = 1; }
    rxv /= l; ryv /= l;
    vbx = rxv; vby = ryv; vbz = 0.0;
    vfx = fx;  vfy = fy;  vfz = fz;
    vux = ryv*fz - 0.0*fy; vuy = 0.0*fx - rxv*fz; vuz = rxv*fy - ryv*fx;
    {   /* roll: spin right/up about the forward axis, so banking tilts the view as it should */
        double rl = g_camrot[2] * 9.5873799e-5, cr, sr, bx, by, bz;
        if (!getenv("XWA_NLOOKAT") && rl != 0.0) {
            cr = cos(rl); sr = sin(rl);
            bx = vbx*cr + vux*sr; by = vby*cr + vuy*sr; bz = vbz*cr + vuz*sr;
            vux = vux*cr - vbx*sr; vuy = vuy*cr - vby*sr; vuz = vuz*cr - vbz*sr;
            vbx = bx; vby = by; vbz = bz;
        }
    }
    if (getenv("XWA_CAMCHECK")) {   /* does the heading implied by yaw match how the ship moves? */
        static int cs; static double lx, ly, lz; static int have;
        if (cs < 8) {
            double dx = vex - lx, dy = vey - ly, dz = vez - lz;
            double dl = sqrt(dx*dx + dy*dy + dz*dz);
            if (have && dl > 1.0) { cs++;
                fprintf(stderr, "[CAMCHECK] yaw=%d pitch=%d roll=%d fwd=(%.2f,%.2f,%.2f) "
                                "moved=(%.2f,%.2f,%.2f) dot=%.3f\n",
                        g_camrot[0], g_camrot[1], g_camrot[2], vfx, vfy, vfz,
                        dx/dl, dy/dl, dz/dl, (vfx*dx + vfy*dy + vfz*dz) / dl);
                fflush(stderr); }
            lx = vex; ly = vey; lz = vez; have = 1;
        }
    }
}

/* Starfield: without it a correct scene still reads as an empty blue void. Fixed directions from
 * a deterministic LCG, so the sky is stable frame to frame and rotates with the camera. */
static int nstars_emit(D3DTLVERTEX* vb, int n, int cap)
{
    unsigned seed = 0x5EEDu, i, count = 320;
    int start = n;
    if (getenv("XWA_NOSTARS")) return n;
    for (i = 0; i < count && n + 6 <= cap; i++) {
        double dx, dy, dz, l, f, sxc, syc, sz; int q, sh;
        uint32_t col;
        seed = seed * 1103515245u + 12345u; dx = (double)(int)(seed >> 9) / 4194304.0 - 1.0;
        seed = seed * 1103515245u + 12345u; dy = (double)(int)(seed >> 9) / 4194304.0 - 1.0;
        seed = seed * 1103515245u + 12345u; dz = (double)(int)(seed >> 9) / 4194304.0 - 1.0;
        seed = seed * 1103515245u + 12345u; sh = 140 + (int)((seed >> 16) % 116u);
        l = sqrt(dx*dx + dy*dy + dz*dz); if (l < 0.2) continue;
        dx /= l; dy /= l; dz /= l;
        f = dx*vfx + dy*vfy + dz*vfz;
        if (f < 0.25) continue;                          /* behind or far off-axis */
        sxc = 400.0 + 640.0 * (dx*vbx + dy*vby + dz*vbz) / f;
        syc = 300.0 - 640.0 * (dx*vux + dy*vuy + dz*vuz) / f;
        if (sxc < 0.0 || sxc > 800.0 || syc < 0.0 || syc > 600.0) continue;
        sz = 0.99999;                                    /* behind everything else */
        col = 0xFF000000u | ((uint32_t)sh << 16) | ((uint32_t)sh << 8) | (uint32_t)sh;
        {   static const float ox[6] = { -1.0f, 1.0f, -1.0f,  1.0f, 1.0f, -1.0f };
            static const float oy[6] = { -1.0f, -1.0f, 1.0f, -1.0f, 1.0f,  1.0f };
            for (q = 0; q < 6; q++) {
                vb[n].sx = (float)sxc + ox[q]; vb[n].sy = (float)syc + oy[q];
                vb[n].sz = (float)sz; vb[n].rhw = 1.0f;
                vb[n].diffuse = col; vb[n].specular = 0; vb[n].tu = 0.0f; vb[n].tv = 0.0f;
                n++;
            }
        }
    }
    if (n > start) d3d11_draw_native(&vb[start], n - start, -1);
    return n;
}

/* Emit one cached mesh into vb; returns the new vertex count. */
/* Craft type -> model path. FLIGHTMODELS/SPACECRAFT0.LST is the game's own list, one OPT path per
 * line in craft-type order (0 = Xwing, 1 = Ywing, ...), which is exactly the index an object's +0x00
 * field holds. Used to load the models the force-launch path never preloaded. */
const char* xwa_craft_opt(unsigned type)
{
    static char* lines[600];
    static int n = -1;
    if (n < 0) {
        FILE* f = fopen("FLIGHTMODELS\\SPACECRAFT0.LST", "rb");
        n = 0;
        if (f) {
            char buf[260];
            while (n < 600 && fgets(buf, sizeof buf, f)) {
                size_t L = strlen(buf);
                while (L && (buf[L-1] == '\n' || buf[L-1] == '\r' || buf[L-1] == ' ')) buf[--L] = 0;
                if (!L) continue;
                lines[n] = (char*)malloc(L + 1);
                if (!lines[n]) break;
                memcpy(lines[n], buf, L + 1);
                n++;
            }
            fclose(f);
        }
        fprintf(stderr, "[CRAFTLIST] %d craft models listed\n", n);
        fflush(stderr);
    }
    return (type < (unsigned)n) ? lines[type] : NULL;
}

/* Textures. The OPT's own 8-bit pixels plus palette are a dead end here -- the palette pointer in
 * the loaded record does not survive the load. But the engine has ALREADY converted every texture
 * into a 16-bit DirectDraw surface through our own mock, so read it from there instead:
 *   texture node (type 27) +0x14 -> descriptor
 *   descriptor +0x23       -> { count, surfaceA, surfaceB }
 *   surface (tag 'DDSF')   +0x0C = pixels, +0x10 = w, +0x14 = h, +0x18 = bpp, +0x1C = pitch
 * The surface is in the pixel format our mock advertises (ARGB1555; XWA_TEX565 if that flips). */
#define MOCK_TAG_DDSF 0x44445346u

static uint32_t ntex_surface(uint32_t node)
{
    uint32_t dp, rec, k;
    if (!xwa_readable(node, 0x18)) return 0;
    dp = MEM32(node + 0x14);
    if (!dp || !xwa_readable(dp, 0x30)) return 0;
    rec = MEM32(dp + 0x23);
    if (rec && xwa_readable(rec, 16))
        for (k = 0; k < 3u; k++) {
            uint32_t cand = MEM32(rec + 4u + k * 4u);
            if (cand && xwa_readable(cand, 0x24) && MEM32(cand + 8) == MOCK_TAG_DDSF) return cand;
        }
    for (k = 0; k < 0x30u; k++) {          /* fall back to any surface pointer in the descriptor */
        uint32_t cand = MEM32(dp + k);
        if (cand && xwa_readable(cand, 0x24) && MEM32(cand + 8) == MOCK_TAG_DDSF) return cand;
    }
    return 0;
}

static int ntex_get(uint32_t node)
{
    static uint32_t px[512 * 512];
    uint32_t surf, pix, w, h, bpp, pitch, x, y;
    /* Our DirectDraw mock advertises ARGB1555 for texture surfaces (#176), but what the engine
     * actually writes into them decodes as 565 -- reading 1555 tints every hull purple. */
    int fmt565 = getenv("XWA_TEX555") ? 0 : 1;
    if (getenv("XWA_NOTEX")) return -1;
    surf = ntex_surface(node);
    if (!surf) return -1;
    pix   = MEM32(surf + 0x0C);
    w     = MEM32(surf + 0x10);
    h     = MEM32(surf + 0x14);
    bpp   = MEM32(surf + 0x18);
    pitch = MEM32(surf + 0x1C);
    if (w < 1u || h < 1u || w > 512u || h > 512u || bpp != 16u) return -1;
    if (!pitch) pitch = w * 2u;
    if (!pix || !xwa_readable(pix, pitch * h)) return -1;
    for (y = 0; y < h; y++)
        for (x = 0; x < w; x++) {
            uint32_t c = MEM16(pix + y * pitch + x * 2u), r, g, b;
            if (fmt565) { r = (c >> 11) & 0x1Fu; g = (c >> 5) & 0x3Fu; b = c & 0x1Fu;
                          r = (r * 255u) / 31u; g = (g * 255u) / 63u; b = (b * 255u) / 31u; }
            else        { r = (c >> 10) & 0x1Fu; g = (c >> 5) & 0x1Fu; b = c & 0x1Fu;
                          r = (r * 255u) / 31u; g = (g * 255u) / 31u; b = (b * 255u) / 31u; }
            px[y * w + x] = 0xFF000000u | (r << 16) | (g << 8) | b;
        }
    if (getenv("XWA_TEXDUMP")) {   /* write the decoded texture out so it can actually be looked at */
        static int dn;
        if (dn < 12) { char path[64]; FILE* f;
            sprintf(path, "tex_%02d_%ux%u.bmp", dn++, w, h);
            f = fopen(path, "wb");
            if (f) {
                uint32_t rowb = (w * 3u + 3u) & ~3u, isz = rowb * h, y2, x2;
                uint8_t hdr[54] = {0};
                hdr[0]='B'; hdr[1]='M'; *(uint32_t*)&hdr[2] = 54u + isz; *(uint32_t*)&hdr[10] = 54u;
                *(uint32_t*)&hdr[14] = 40u; *(int32_t*)&hdr[18] = (int32_t)w;
                *(int32_t*)&hdr[22] = -(int32_t)h; *(uint16_t*)&hdr[26] = 1; *(uint16_t*)&hdr[28] = 24;
                *(uint32_t*)&hdr[34] = isz;
                fwrite(hdr, 1, 54, f);
                for (y2 = 0; y2 < h; y2++) {
                    uint8_t row[512*3+4]; memset(row, 0, rowb);
                    for (x2 = 0; x2 < w; x2++) { uint32_t c = px[y2*w + x2];
                        row[x2*3+0] = (uint8_t)(c & 0xFF); row[x2*3+1] = (uint8_t)((c >> 8) & 0xFF);
                        row[x2*3+2] = (uint8_t)((c >> 16) & 0xFF); }
                    fwrite(row, 1, rowb, f);
                }
                fclose(f);
            }
        }
    }
    {   int id = d3d11_native_texture(node, px, (int)w, (int)h);
        static int lg;
        if (lg < 8 && getenv("XWA_NMESHLOG")) { lg++;
            fprintf(stderr, "[NTEX] node=0x%08X surf=0x%08X %ux%u bpp=%u pitch=%u -> id=%d px0=%08X\n",
                    node, surf, w, h, bpp, pitch, id, px[0]); fflush(stderr); }
        return id; }
}

/* Per-mesh context shared with nfaces_emit (rendering is single-threaded). */
static uint32_t nc_vdata, nc_vcnt, nc_tc, nc_tccnt;
static int nc_tex = -1;
static double nc_relx, nc_rely, nc_relz, nc_k, nc_m[9];

static int nfaces_emit(uint32_t a, D3DTLVERTEX* vb, int n, int cap);
void xwa_native_flush(void);

static int nmesh_emit(int mi, D3DTLVERTEX* vb, int n, int cap)
{
    uint32_t vnode = g_nmesh[mi].vnode, vcnt, vdata, a, fgrp = 0;
    double relx, rely, relz, k, ca, sa, cb, sb, cc, sc, m[9];

    if (!xwa_blk(vnode) || MEM32(vnode + 4) != 3u) return n;
    vcnt = MEM32(vnode + 0x10);
    if (vcnt < 3u || vcnt > 4096u || !xwa_readable(vnode + 0x18, vcnt * 12u)) return n;
    vdata = vnode + 0x18;

    {   /* XWA angles are 16-bit (65536 = 360 deg). Pitch is measured from a different zero than
         * yaw/roll: craft sitting level at mission start all read 16384, so that is the offset. */
        double poff = getenv("XWA_NPITCHOFF") ? atof(getenv("XWA_NPITCHOFF")) : 16384.0;
        double u = g_nmesh[mi].rot[0] * 9.5873799e-5;
        double v = (g_nmesh[mi].rot[1] - poff) * 9.5873799e-5;
        double w = g_nmesh[mi].rot[2] * 9.5873799e-5;
        if (getenv("XWA_NOROT")) { u = v = w = 0.0; }
        ca = cos(u); sa = sin(u); cb = cos(v); sb = sin(v); cc = cos(w); sc = sin(w);
    }
    /* yaw about Z, pitch about X, roll about Y */
    m[0] =  ca*cc + sa*sb*sc;  m[1] = -sa*cb;  m[2] =  ca*sc - sa*sb*cc;
    m[3] =  sa*cc - ca*sb*sc;  m[4] =  ca*cb;  m[5] =  sa*sc + ca*sb*cc;
    m[6] = -cb*sc;             m[7] = -sb;     m[8] =  cb*cc;

    relx = (double)g_nmesh[mi].p[0] - vex;
    rely = (double)g_nmesh[mi].p[1] - vey;
    relz = (double)g_nmesh[mi].p[2] - vez;

    /* OPT units -> world units. No measurement has pinned this constant, so it stays a knob:
     * raise it if ships are specks, lower it if one hull fills the screen. */
    k = getenv("XWA_NSCALE") ? atof(getenv("XWA_NSCALE")) : 0.12;

    nc_vdata = vdata; nc_vcnt = vcnt;
    nc_tc = 0; nc_tccnt = 0;
    for (a = vdata + vcnt * 12u; a < vdata + 0x8000u; a++) {   /* texture coords: type 13, (u,v) */
        if (!xwa_blk(a)) continue;
        if (MEM32(a + 4) == 3u) break;
        if (MEM32(a + 4) == 13u) { nc_tccnt = MEM32(a + 0x10); nc_tc = a + 0x18; break; }
    }
    nc_relx = relx; nc_rely = rely; nc_relz = relz; nc_k = k;
    for (a = 0; a < 9; a++) nc_m[a] = m[a];

    /* Find this mesh's FaceGrouping (type 21). Its children are LODs, and each LOD's children are
     * texture(20)/face(1) pairs. Drawing every type-1 block in the region -- what the flat scan
     * did -- stacks LOD1/LOD2 on top of LOD0 and buries the hull under coarse geometry. */
    for (a = vdata + vcnt * 12u; a < vdata + 0x8000u; a++) {
        if (!xwa_readable(a, 0x18) || MEM32(a) != 0u || MEM32(a + 4) != 21u) continue;
        {   uint32_t nch = MEM32(a + 8), arr = MEM32(a + 0xC);
            if (nch < 1u || nch > 32u || !xwa_readable(arr, nch * 4u)) continue;
            fgrp = a; break; }
    }
    if (getenv("XWA_NMESHLOG")) {
        static int ml;
        if (ml < 12) { uint32_t q; double x0=1e30,x1=-1e30,y0=1e30,y1=-1e30,z0=1e30,z1=-1e30; ml++;
            for (q = 0; q < vcnt; q++) {
                double X = xwa_f32(vdata+q*12), Y = xwa_f32(vdata+q*12+4), Z = xwa_f32(vdata+q*12+8);
                if (X<x0)x0=X; if (X>x1)x1=X; if (Y<y0)y0=Y; if (Y>y1)y1=Y; if (Z<z0)z0=Z; if (Z>z1)z1=Z;
            }
            fprintf(stderr, "[NMESH] vnode=0x%08X verts=%u %s lods=%u  extent x[%.0f,%.0f] y[%.0f,%.0f] z[%.0f,%.0f]\n",
                    vnode, vcnt, fgrp ? "HIER" : "flat-scan", fgrp ? MEM32(fgrp + 8) : 0u,
                    x0, x1, y0, y1, z0, z1);
            fflush(stderr);
        }
    }
    if (fgrp) {
        uint32_t arr  = MEM32(fgrp + 0xC);
        uint32_t nlod = MEM32(fgrp + 8);
        uint32_t want = getenv("XWA_NLOD") ? (uint32_t)atoi(getenv("XWA_NLOD")) : 0u;
        uint32_t lodn, nch, carr, c;
        if (want >= nlod) want = 0u;
        lodn = MEM32(arr + want * 4u);                 /* one LOD -- the most detailed by default */
        if (xwa_readable(lodn, 0x18)) {
            nch = MEM32(lodn + 8); carr = MEM32(lodn + 0xC);
            if (nch >= 1u && nch <= 128u && xwa_readable(carr, nch * 4u)) {
                nc_tex = -1;
                if (getenv("XWA_NMESHLOG")) { static int lg3; uint32_t q, t20 = 0, t1 = 0;
                    if (lg3 < 6) { lg3++;
                        for (q = 0; q < nch; q++) { uint32_t ch = MEM32(carr + q*4u);
                            if (!xwa_readable(ch, 0x18)) continue;
                            if (MEM32(ch + 4) == 20u) t20++;
                            if (MEM32(ch + 4) == 1u) t1++; }
                        fprintf(stderr, "[NLOD] children=%u textures=%u faceblocks=%u types:", nch, t20, t1);
                        for (q = 0; q < nch && q < 20u; q++) { uint32_t ch = MEM32(carr + q*4u);
                            fprintf(stderr, " %u", xwa_readable(ch, 0x18) ? MEM32(ch + 4) : 999u); }
                        fprintf(stderr, "\n");
                        for (q = 0; q < nch && q < 3u; q++) { uint32_t ch = MEM32(carr + q*4u), r;
                            if (!xwa_readable(ch, 0x40) || MEM32(ch + 4) != 27u) continue;
                            fprintf(stderr, "  [T27] node=0x%08X:", ch);
                            for (r = 0; r < 12u; r++) fprintf(stderr, " %08X", MEM32(ch + r*4));
                            { uint32_t dp = MEM32(ch + 0x14);
                              if (xwa_readable(dp, 0x40)) {
                                  fprintf(stderr, "  bytes@dp:");
                                  for (r = 0; r < 40u; r++) fprintf(stderr, " %02X", MEM8(dp + r));
                                  fprintf(stderr, "  fields: size=%u mip=%u w=%u h=%u palcand=%08X,%08X,%08X",
                                          MEM32(dp+0x0E), MEM32(dp+0x12), MEM32(dp+0x16), MEM32(dp+0x1A),
                                          MEM32(dp+0x02), MEM32(dp+0x06), MEM32(dp+0x0A));
                              } }
                            fprintf(stderr, "\n"); }
                        fflush(stderr); } }
                for (c = 0; c < nch; c++) {
                    uint32_t child = MEM32(carr + c * 4u);
                    if (!xwa_readable(child, 0x18)) continue;
                    /* Inside a LOD the children alternate texture(20) / faces(1): each face block
                     * is skinned with the texture node that precedes it. */
                    if (MEM32(child + 4) == 27u) { nc_tex = ntex_get(child); continue; }
                    if (MEM32(child + 4) == 24u) {   /* NodeReference: the texture lives behind it */
                        uint32_t rn = MEM32(child + 8), ra = MEM32(child + 0xC), rk;
                        if (rn >= 1u && rn <= 16u && xwa_readable(ra, rn * 4u))
                            for (rk = 0; rk < rn; rk++) {
                                uint32_t rc = MEM32(ra + rk * 4u);
                                if (xwa_readable(rc, 0x18) && MEM32(rc + 4) == 27u) {
                                    int id = ntex_get(rc); if (id >= 0) { nc_tex = id; break; }
                                }
                            }
                        continue;
                    }
                    if (MEM32(child) == 0u && MEM32(child + 4) == 1u)
                        n = nfaces_emit(child, vb, n, cap);
                }
                return n;
            }
        }
    }
    /* No usable FaceGrouping: fall back to the flat scan (every face block up to the next mesh). */
    for (a = vdata + vcnt * 12u; a < vdata + 0x8000u; a++) {
        if (!xwa_blk(a)) continue;
        if (MEM32(a + 4) == 3u) break;
        if (MEM32(a + 4) == 1u) n = nfaces_emit(a, vb, n, cap);
    }
    return n;
}

/* Emit one FaceData block. Layout, confirmed against the OPT file itself (FLIGHTMODELS/*.OPT):
 *   +0x10      = face count            +0x18 = edge count
 *   +0x1C      = 16 int32 PER FACE: vertex[4], edge[4], texcoord[4], normal[4]  (-1 = triangle)
 *   +0x1C+n*64 = 3 floats per face: the face normal
 *   +0x1C+n*76 = 6 more floats per face (100 bytes per face in total)
 * The index records are 64 bytes apart, not 16 -- reading them at 16 fed edge and texture indices
 * to the rasteriser as if they were vertices, which is what mangled the hulls. */
static int nfaces_emit(uint32_t a, D3DTLVERTEX* vb, int n, int cap)
{
    uint32_t fcnt = MEM32(a + 0x10), fp = a + 0x1C, fnorm, i;
    int start = n;
    if (fcnt < 1u || fcnt > 4096u || !xwa_readable(fp, fcnt * 100u)) return n;
    fnorm = fp + fcnt * 64u;
    if (getenv("XWA_UVLOG")) { static int uv;
        if (uv < 6 && fcnt > 0u) { uint32_t q; uv++;
            fprintf(stderr, "[UV] block=0x%08X faces=%u tex=%d tcblock=0x%08X tccnt=%u\n",
                    a, fcnt, nc_tex, nc_tc, nc_tccnt);
            for (q = 0; q < 2u && q < fcnt; q++) {
                int t0 = (int32_t)MEM32(fp + q*64 + 32), t1 = (int32_t)MEM32(fp + q*64 + 36);
                int t2 = (int32_t)MEM32(fp + q*64 + 40), t3 = (int32_t)MEM32(fp + q*64 + 44);
                fprintf(stderr, "   face%u tcidx=%d,%d,%d,%d", q, t0, t1, t2, t3);
                if (nc_tc && t0 >= 0 && (uint32_t)t0 < nc_tccnt)
                    fprintf(stderr, "  uv0=(%.3f,%.3f) uv1=(%.3f,%.3f)",
                            xwa_f32(nc_tc + (uint32_t)t0*8u), xwa_f32(nc_tc + (uint32_t)t0*8u + 4u),
                            (t1 >= 0 && (uint32_t)t1 < nc_tccnt) ? xwa_f32(nc_tc + (uint32_t)t1*8u) : -99.0,
                            (t1 >= 0 && (uint32_t)t1 < nc_tccnt) ? xwa_f32(nc_tc + (uint32_t)t1*8u + 4u) : -99.0);
                fprintf(stderr, "\n");
            }
            fflush(stderr); } }

    for (i = 0; i < fcnt && n + 6 <= cap; i++) {
        int idx[4], j, nv, bad = 0;
        double px[4], py[4], pz[4], sx[4], sy[4], sz[4];
        idx[0] = (int32_t)MEM32(fp + i*64 + 0);  idx[1] = (int32_t)MEM32(fp + i*64 + 4);
        idx[2] = (int32_t)MEM32(fp + i*64 + 8);  idx[3] = (int32_t)MEM32(fp + i*64 + 12);
        nv = (idx[3] >= 0) ? 4 : 3;
        for (j = 0; j < nv; j++) if (idx[j] < 0 || (uint32_t)idx[j] >= nc_vcnt) bad = 1;
        if (bad) continue;
        for (j = 0; j < nv; j++) {
            double vx = xwa_f32(nc_vdata + (uint32_t)idx[j]*12 + 0);
            double vy = xwa_f32(nc_vdata + (uint32_t)idx[j]*12 + 4);
            double vz = xwa_f32(nc_vdata + (uint32_t)idx[j]*12 + 8);
            double wx = nc_relx + nc_k * (nc_m[0]*vx + nc_m[1]*vy + nc_m[2]*vz);
            double wy = nc_rely + nc_k * (nc_m[3]*vx + nc_m[4]*vy + nc_m[5]*vz);
            double wz = nc_relz + nc_k * (nc_m[6]*vx + nc_m[7]*vy + nc_m[8]*vz);
            px[j] = wx*vbx + wy*vby + wz*vbz;       /* world -> view */
            py[j] = wx*vfx + wy*vfy + wz*vfz;
            pz[j] = wx*vux + wy*vuy + wz*vuz;
            if (py[j] < 0.05) { bad = 1; break; }   /* behind the camera */
            sx[j] = 400.0 + 640.0 * px[j] / py[j];
            sy[j] = 300.0 - 640.0 * pz[j] / py[j];
            sz[j] = 1.0 - 1.0 / (1.0 + py[j]);      /* 0..1 depth, nearer = smaller */
        }
        if (bad) continue;
        {   /* The model stores a real normal per face: use it to cull backfaces and to shade,
             * instead of guessing from the winding. */
            double nx = xwa_f32(fnorm + i*12 + 0), ny = xwa_f32(fnorm + i*12 + 4);
            double nz = xwa_f32(fnorm + i*12 + 8);
            double wnx = nc_m[0]*nx + nc_m[1]*ny + nc_m[2]*nz;    /* model -> world */
            double wny = nc_m[3]*nx + nc_m[4]*ny + nc_m[5]*nz;
            double wnz = nc_m[6]*nx + nc_m[7]*ny + nc_m[8]*nz;
            double len = sqrt(wnx*wnx + wny*wny + wnz*wnz), d;
            double ex, ey, ez;
            uint32_t col; int sh;
            if (len < 1e-12) continue;
            wnx /= len; wny /= len; wnz /= len;
            ex = px[0]*vbx + py[0]*vfx + pz[0]*vux;               /* view -> world eye vector */
            ey = px[0]*vby + py[0]*vfy + pz[0]*vuy;
            ez = px[0]*vbz + py[0]*vfz + pz[0]*vuz;
            if (!getenv("XWA_NOCULL") && (wnx*ex + wny*ey + wnz*ez) > 0.0) continue;
            d = 0.40*wnx - 0.80*wny + 0.45*wnz;
            if (d < 0.0) d = 0.0;
            sh = (nc_tex >= 0) ? (int)(150.0 + 105.0 * d)   /* modulated onto the texture */
                               : (int)(50.0 + 170.0 * d);
            if (sh > 255) sh = 255;
            col = 0xFF000000u | ((uint32_t)sh << 16) | ((uint32_t)sh << 8) | (uint32_t)(sh + 20);
            if (getenv("XWA_TEXONLY")) col = 0xFFFFFFFFu;   /* raw texture, no shading */
            for (j = 0; j < nv - 2; j++) {          /* fan: (0,1,2) then (0,2,3) */
                int t[3], q; t[0] = 0; t[1] = j + 1; t[2] = j + 2;
                for (q = 0; q < 3; q++) {
                    int sidx = t[q];
                    vb[n].sx = (float)sx[sidx]; vb[n].sy = (float)sy[sidx]; vb[n].sz = (float)sz[sidx];
                    vb[n].rhw = 1.0f; vb[n].diffuse = col; vb[n].specular = 0;
                    vb[n].tu = 0.0f; vb[n].tv = 0.0f;
                    if (nc_tc && nc_tex >= 0) {          /* face's texcoord indices, 3rd index group */
                        int ti = (int32_t)MEM32(fp + i*64 + 32 + sidx*4);
                        if (ti >= 0 && (uint32_t)ti < nc_tccnt) {
                            vb[n].tu = xwa_f32(nc_tc + (uint32_t)ti * 8u);
                            vb[n].tv = xwa_f32(nc_tc + (uint32_t)ti * 8u + 4u);
                        }
                    }
                    n++;
                }
            }
        }
    }
    if (n > start) d3d11_draw_native(&vb[start], n - start, nc_tex);
    return n;
}

/* Add one mesh (a type-3 vertex node) to the scene cache with the transform of the object it
 * belongs to. Returns 1 if it was new. */
/* One entry per (object, mesh). The transform is REFRESHED on every pass -- keying on position
 * instead meant a moving craft kept adding new entries, so the scene was a trail of stale copies
 * frozen where each object was first seen. */
static int nmesh_add(uint32_t vnode, const int* pos, const int* rot, int obj)
{
    int i;
    if (!xwa_blk(vnode) || MEM32(vnode + 4) != 3u) return 0;
    for (i = 0; i < g_nmesh_n; i++)
        if (g_nmesh[i].vnode == vnode && g_nmesh[i].obj == obj) {
            g_nmesh[i].p[0] = pos[0]; g_nmesh[i].p[1] = pos[1]; g_nmesh[i].p[2] = pos[2];
            g_nmesh[i].rot[0] = rot[0]; g_nmesh[i].rot[1] = rot[1]; g_nmesh[i].rot[2] = rot[2];
            return 0;                                  /* already known -- just moved */
        }
    if (g_nmesh_n >= NMESH_MAX) return 0;
    g_nmesh[g_nmesh_n].vnode  = vnode;
    g_nmesh[g_nmesh_n].obj    = obj;
    g_nmesh[g_nmesh_n].p[0]   = pos[0]; g_nmesh[g_nmesh_n].p[1] = pos[1]; g_nmesh[g_nmesh_n].p[2] = pos[2];
    g_nmesh[g_nmesh_n].rot[0] = rot[0]; g_nmesh[g_nmesh_n].rot[1] = rot[1]; g_nmesh[g_nmesh_n].rot[2] = rot[2];
    g_nmesh_n++;
    return 1;
}

/* Walk an OPT node tree and cache every mesh in it. Container nodes carry a child count at +8 and
 * an array of child pointers at +0xC; leaf data blocks have count/inline-data at +0x10/+0x14. */
static int nwalk(uint32_t node, const int* pos, const int* rot, int obj, int depth)
{
    uint32_t nch, arr, i;
    int added = 0;
    if (depth > 8 || !xwa_readable(node, 0x18) || MEM32(node) != 0u) return 0;
    if (MEM32(node + 4) == 3u) return nmesh_add(node, pos, rot, obj);
    nch = MEM32(node + 8);
    arr = MEM32(node + 0xC);
    if (nch < 1u || nch > 128u || !xwa_readable(arr, nch * 4u)) return 0;
    for (i = 0; i < nch; i++) added += nwalk(MEM32(arr + i * 4u), pos, rot, obj, depth + 1);
    return added;
}

/* Resolve a craft type to its loaded OPT image, the same way the engine does it:
 *   resource id  = WORD[0x7CA6E0 + type*2]
 *   image        = DWORD[((id & DWORD[0x5AA020]) & 0xFFFF) - 1)*4 + 0x77D030]      (sub_0050E2F0)
 * The engine's resolver is a plain table lookup, so there is no need to call into guest code. */
static uint32_t xwa_model_for_type(unsigned type)
{
    uint32_t rid, idx;
    if (type == 0u || type > 0x400u || !xwa_readable(0x7CA6E0u + type * 2u, 2)) return 0;
    rid = MEM16(0x7CA6E0u + type * 2u);
    if (!xwa_readable(0x5AA020u, 4)) return 0;
    idx = (rid & MEM32(0x5AA020u)) & 0xFFFFu;
    if (idx < 1u || idx > 5000u) return 0;
    if (!xwa_readable((idx - 1u) * 4u + 0x77D030u, 4)) return 0;
    return MEM32((idx - 1u) * 4u + 0x77D030u);
}

/* Find the root node inside a loaded OPT image. The image is the .OPT file with its offsets patched
 * to real addresses; the header is followed by the root NodeGroup. Earlier sessions read this image
 * as if it were a node and saw "type = 720915" -- that was the file SIZE field at +4. */
static uint32_t xwa_opt_root(uint32_t img)
{
    uint32_t p;
    /* The loaded image begins at FILE OFFSET 8 -- the loader overwrites the file's global-pointer
     * field with the load address, so the -5 magic is not present in memory. The root NodeGroup
     * follows a variable-length pointer array, and OPT structures are 2-byte packed, so scan. */
    if (!xwa_readable(img, 0x40)) return 0;
    for (p = img; p < img + 0x400u; p += 2u) {
        uint32_t ty, nch, arr, c0;
        if (!xwa_readable(p, 0x18) || MEM32(p) != 0u) continue;
        ty  = MEM32(p + 4);
        nch = MEM32(p + 8);
        arr = MEM32(p + 0xC);
        if (ty > 32u || nch < 1u || nch > 64u) continue;
        if (arr < img || arr > img + 0x2000000u || !xwa_readable(arr, nch * 4u)) continue;
        c0 = MEM32(arr);                       /* the first child must itself look like a node */
        if (!xwa_readable(c0, 0x18) || MEM32(c0) != 0u || MEM32(c0 + 4) > 32u) continue;
        return p;
    }
    return 0;
}

/* Called per object from the render walk. Draws THAT object's own model: the mesh recogniser only
 * ever hands over whichever model it happens to be resolving, so every craft came out with the
 * same hull. */
void xwa_native_object(unsigned type, int px, int py, int pz, int yaw, int pitch, int roll, int obj)
{
    int pos[3], rot[3], added;
    uint32_t img, root;
    if (!getenv("XWA_NATIVEDRAW")) return;
    {   /* The walk restarts at object 0 every pass; that boundary is the frame. Re-emit the scene
         * there, so what reaches the screen is this pass's positions rather than a snapshot. */
        static int last = -1;
        if (obj <= last) xwa_native_flush();
        last = obj;
    }
    img = xwa_model_for_type(type);
    root = img ? xwa_opt_root(img) : 0u;
    /* An OPT holds SEVERAL mesh roots (an X-wing is 5: fuselage plus wings). The count sits at
     * img+6 and the pointer array at img+0x0E -- file offsets 0x0E/0x16, less the 8 bytes the
     * loader strips. Walking only the first root drew one wedge instead of the whole craft. */
    if (img && xwa_readable(img, 0x40)) {
        uint32_t nroot = MEM16(img + 6), ri, hits = 0;
        if (nroot >= 1u && nroot <= 64u && xwa_readable(img + 0x0Eu, nroot * 4u)) {
            pos[0] = px; pos[1] = py; pos[2] = pz;
            rot[0] = yaw; rot[1] = pitch; rot[2] = roll;
            {   /* Cull by distance from the camera. The default 200k units only rejects outright
                 * junk coordinates; a real mission also carries craft tens of thousands of units
                 * away, and letting them into the scene drags the XWA_NLOOKAT centroid off the
                 * near action so nothing lands on screen. XWA_NMAXDIST=<units> tightens it. */
                static double maxd2 = -1.0;
                double dx = (double)(px - g_np[3]), dy = (double)(py - g_np[4]), dz = (double)(pz - g_np[5]);
                const double SANE = 2.0e7;
                if (maxd2 < 0.0) {
                    const char* e = getenv("XWA_NMAXDIST");
                    double d = e ? atof(e) : 200000.0;
                    if (d < 1.0) d = 200000.0;
                    maxd2 = d * d;
                }
                /* Culling against the camera is only meaningful when the camera is somewhere real.
                 * Before the player craft exists the camera record is fill garbage, and measuring
                 * from it threw away every genuine craft while keeping the junk slots nearest the
                 * garbage value -- the exact opposite of what the cull is for. With no usable
                 * camera, keep whatever has plausible coordinates and let nview_build frame it. */
                if (fabs((double)g_np[3]) > SANE || fabs((double)g_np[4]) > SANE
                                                 || fabs((double)g_np[5]) > SANE) {
                    if (fabs((double)px) > SANE || fabs((double)py) > SANE
                                                || fabs((double)pz) > SANE) return;
                } else if (dx*dx + dy*dy + dz*dz > maxd2) return;
            }
            for (ri = 0; ri < nroot; ri++) {
                uint32_t r = MEM32(img + 0x0Eu + ri * 4u);
                if (!xwa_readable(r, 0x18) || MEM32(r) != 0u || MEM32(r + 4) > 32u) continue;
                hits += (uint32_t)nwalk(r, pos, rot, obj, 0);
            }
            if (getenv("XWA_NMESHLOG")) { static int lg2;
                if (lg2 < 10) { lg2++;
                    fprintf(stderr, "[NOBJ] type=0x%X img=0x%08X roots=%u meshes+%u total=%d at (%d,%d,%d) ypr=(%d,%d,%d)\n",
                            type, img, nroot, hits, g_nmesh_n, px, py, pz, yaw, pitch, roll);
                    fflush(stderr); } }
            return;
        }
    }
    if (getenv("XWA_NMESHLOG")) { static int lg;
        if (lg < 10) { lg++;
            fprintf(stderr, "[NOBJ] type=0x%X img=0x%08X root=0x%08X rtype=%u kids=%u at (%d,%d,%d)\n",
                    type, img, root, root ? MEM32(root+4) : 0u, root ? MEM32(root+8) : 0u, px, py, pz);
            fflush(stderr); } }
    if (!root) return;
    pos[0] = px; pos[1] = py; pos[2] = pz;
    rot[0] = yaw; rot[1] = pitch; rot[2] = roll;
    {   /* Reject junk coordinates. Mission space runs to a few tens of thousands of units; the
         * fabricated flight groups carry float bit patterns in these int fields, which show up as
         * values in the hundreds of millions. */
        if (px < -200000 || px > 200000 || py < -200000 || py > 200000
            || pz < -200000 || pz > 200000) return;
    }
    added = nwalk(root, pos, rot, obj, 0);
    (void)added;
}

/* Re-emit the whole cached scene. */
void xwa_native_flush(void)
{
    static D3DTLVERTEX vb[32768];
    int i, n = 0;

    d3d11_native_reset();
    nview_build();
    n = nstars_emit(vb, n, (int)(sizeof vb / sizeof vb[0]));
    for (i = 0; i < g_nmesh_n; i++)
        n = nmesh_emit(i, vb, n, (int)(sizeof vb / sizeof vb[0]));
    /* batches are submitted per face block inside nfaces_emit / nstars_emit */

    {   static int dumped;
        if (dumped < 8 && n > 0) { int q; float x0 = 1e9f, x1 = -1e9f, y0 = 1e9f, y1 = -1e9f; dumped++;
            for (q = 0; q < n; q++) { if (vb[q].sx<x0)x0=vb[q].sx; if (vb[q].sx>x1)x1=vb[q].sx;
                                      if (vb[q].sy<y0)y0=vb[q].sy; if (vb[q].sy>y1)y1=vb[q].sy; }
            fprintf(stderr, "[NATIVEDRAW] meshes=%d verts=%d box=[%.0f..%.0f,%.0f..%.0f] "
                            "obj=(%d,%d,%d) cam=(%d,%d,%d) rot=(%d,%d,%d) camrot=(%d,%d,%d)\n",
                    g_nmesh_n, n, x0, x1, y0, y1, g_np[0], g_np[1], g_np[2], g_np[3], g_np[4], g_np[5],
                    g_nrot[0], g_nrot[1], g_nrot[2], g_camrot[0], g_camrot[1], g_camrot[2]);
            /* XWA_MODELDBG: for every craft the MISSION asks for, report whether the engine has a
             * model for it. Mission flight groups live at 0x80DC80 (stride 0xE42, craft type at
             * +0x6B); type -> craft-def index is MEM16(type*24 + 0x5FB252), the def record is
             * 0x5BB4B2 + def*0x3DB with its OPT name at +0, per-type model data is
             * 0x8D9760 + type*0x194 and the type -> model registry is MEM16(0x7CA6E0 + type*2). */
            /* XWA_HANGARDBG: the hangar/launch sequence is a state machine on 0x68BBA0, driven
             * per frame by sub_0045B0D0 from the flight loop. 0x8053E5 gates the whole hangar
             * branch at 0x0045B11D, 0x9C6754 is the hangar map craft type (0x134 = Hangar.opt,
             * 0xB3 = FamilyBase exterior) and 0x9C6750/0x68BBB8 are the docked / mission-over
             * flags. Print the tuple only when it changes, so a run shows the transitions rather
             * than one frame's worth of numbers. */
            if (getenv("XWA_HANGARDBG")) {
                static uint32_t last = 0xFFFFFFFFu; static int n;
                uint32_t now = (MEM32(0x68BBA0) & 0xFFu)
                             | ((MEM32(0x9C6750) & 0xFFu) << 8)
                             | ((uint32_t)MEM16(0x9C6754) << 16);
                if (now != last && n < 60) { last = now; n++;
                    fprintf(stderr, "[HANGAR] state(68BBA0)=%u docked(9C6750)=%u map(9C6754)=0x%X "
                                    "active(8053E5)=%u entries(AF138E)=%u end(68BBB8)=%u\n",
                            MEM32(0x68BBA0), MEM32(0x9C6750), (unsigned)MEM16(0x9C6754),
                            MEM8(0x8053E5), MEM32(0xAF138E), MEM32(0x68BBB8));
                    fflush(stderr); }
            }
            /* XWA_MEMFIND=<text>: find where a string lives in guest memory, then every dword in
             * guest .data that points at it -- the fast way from an on-screen string to the code
             * that draws it (grep the generated C for the pointer's address). Walks committed
             * readable regions with VirtualQuery, so heap copies are found too. */
            if (dumped == 3 && getenv("XWA_MEMFIND")) {
                const char *want = getenv("XWA_MEMFIND"); size_t wl = strlen(want);
                MEMORY_BASIC_INFORMATION mbi; uint8_t *p = (uint8_t *)0x10000;
                uint32_t hits[16]; int nh = 0, h;
                while (nh < 16 && (uintptr_t)p < 0x7FFF0000u && VirtualQuery(p, &mbi, sizeof mbi)) {
                    uint8_t *e = (uint8_t *)mbi.BaseAddress + mbi.RegionSize, *q;
                    if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE|PAGE_READONLY|PAGE_EXECUTE_READWRITE))
                        && !(mbi.Protect & PAGE_GUARD))
                        for (q = p; q + wl <= e && nh < 16; q++)
                            if (*q == (uint8_t)want[0] && !memcmp(q, want, wl)) hits[nh++] = (uint32_t)(uintptr_t)q;
                    p = e;
                }
                for (h = 0; h < nh; h++) {
                    uint32_t a;
                    fprintf(stderr, "[MEMFIND] '%s' at 0x%08X\n", want, hits[h]);
                    /* a table may point at the string, or at the start of its line a few bytes back */
                    for (a = 0x5AE000u; a < 0xB10000u; a += 4) {
                        uint32_t v = MEM32(a);
                        if (v <= hits[h] && v + 32u > hits[h])
                            fprintf(stderr, "[MEMFIND]   ptr at 0x%08X -> 0x%08X (+%u)\n", a, v, hits[h] - v);
                    }
                }
                fflush(stderr);
            }
            if (dumped == 1 && getenv("XWA_MODELDBG")) {
                uint32_t k, n2 = (uint32_t)MEM16(0x7B4C00u);
                int ld = 0, d2;
                fprintf(stderr, "[MODELDBG] mission FGs=%u\n", n2);
                for (k = 0; k < n2 && k < 32u; k++) {
                    uint32_t r = 0x80DC80u + k * 0xE42u, sp = MEM8(r + 0x6B), t, di, j;
                    char nm[32];
                    if (!sp) continue;
                    /* +0x6B is the .tie SPECIES. Everything downstream (craft-def, model data, the
                     * model registry) is keyed on the ENGINE TYPE, and the engine's own converter is
                     * the word table at 0x5B0F70. Reading those tables with the species instead --
                     * which this dump used to do -- reports "no model" for craft that have one. */
                    t = (sp < 0x22Du) ? (uint32_t)MEM16(0x5B0F70u + sp * 2u) : 0u;
                    di = (t && t < 0x22Du) ? MEM16(t * 24u + 0x5FB252u) : 0xFFFFu;
                    nm[0] = 0;
                    if (di < 0xC0u) { for (j = 0; j < 28u; j++) { uint8_t c = MEM8(0x5BB4B2u + di * 0x3DBu + j);
                        nm[j] = (c >= 32 && c < 127) ? (char)c : 0; if (!c) break; } nm[28] = 0; }
                    fprintf(stderr, "[MODELDBG]  fg%02u species=%3u type=%3u def=%u name=%s modeldata=0x%X reg=%u\n",
                            k, sp, t, di, nm, MEM32(0x8D9760u + t * 0x194u), (unsigned)MEM16(0x7CA6E0u + t * 2u));
                }
                for (d2 = 0; d2 < 0xC0; d2++) { uint8_t c0 = MEM8(0x5BB4B2u + (uint32_t)d2 * 0x3DBu);
                    if (c0 >= 32 && c0 < 127) { char dn[32]; uint32_t q;
                        for (q = 0; q < 28u; q++) { uint8_t c = MEM8(0x5BB4B2u + (uint32_t)d2 * 0x3DBu + q);
                            dn[q] = (c >= 32 && c < 127) ? (char)c : 0; if (!c) break; } dn[28] = 0;
                        fprintf(stderr, "[MODELDBG]  def%03d = %s\n", d2, dn); ld++; } }
                {   uint32_t tbl = MEM32(0x7B33C4u), c2 = MEM32(0x63185Cu), q2;
                    fprintf(stderr, "[MODELDBG] runtime FG table 0x%08X count=%u\n", tbl, c2);
                    for (q2 = 0; q2 < c2 && q2 < 24u; q2++) {
                        uint32_t e = tbl + q2 * 0x27u;
                        fprintf(stderr, "[MODELDBG]  rt%02u +0=%u +2=%u +4=%u +5=%u reg(+2)=%u\n",
                            q2, (unsigned)MEM16(e), (unsigned)MEM16(e + 2), MEM8(e + 4), MEM8(e + 5),
                            (unsigned)MEM16(0x7CA6E0u + (uint32_t)MEM16(e + 2) * 2u));
                    } }
                /* Hangar scene: sub_004554F0 picks the map at 0x00455A8E -- 0x9C6754 becomes 308
                 * (Hangar.opt interior) when MEM8(0xB07C6B) is 0, else 179 (FamilyBase exterior) --
                 * loads its model through sub_00456FA0 and gives it a runtime group in 0x68BCC4. */
                {   uint32_t hty = (uint32_t)MEM16(0x9C6754u), hfg = MEM32(0x68BCC4u);
                    uint32_t t3 = MEM32(0x7B33C4u);
                    fprintf(stderr, "[MODELDBG] hangar: map type=%u (0xB07C6B=%u) fg=%u reg=%u\n",
                            hty, MEM8(0xB07C6Bu), hfg,
                            (hty < 0x400u) ? (unsigned)MEM16(0x7CA6E0u + hty * 2u) : 0u);
                    if (t3 && hfg < 0x400u) {
                        uint32_t e3 = t3 + hfg * 0x27u;
                        fprintf(stderr, "[MODELDBG] hangar fg%u: +0=%u +2=%u +4=%u +5=%u ro(+0x23)=0x%X\n",
                                hfg, (unsigned)MEM16(e3), (unsigned)MEM16(e3 + 2), MEM8(e3 + 4), MEM8(e3 + 5),
                                MEM32(e3 + 0x23));
                    } }
                fprintf(stderr, "[MODELDBG] craft-defs with a name: %d of 192\n", ld);
                fflush(stderr);
            }
            if (dumped == 1 && getenv("XWA_CAMPROBE")) {
                /* the camera position lives at playerslot*0xBCF + 0x8BA028; its orientation should
                 * be a few fields away -- print the neighbourhood as int16 angle candidates */
                uint32_t base = MEM32(0x8C1CC8) * 0xBCFu + 0x8BA028u;
                int q;
                fprintf(stderr, "[CAMPROBE] base=0x%08X", base);
                for (q = -16; q < 32; q++) {
                    if ((q % 8) == 0) fprintf(stderr, "\n  %+04d:", q*2);
                    fprintf(stderr, " %6d", (int)(int16_t)MEM16(base + (uint32_t)(int32_t)(q*2)));
                }
                fprintf(stderr, "\n");
            }
            fflush(stderr);
        }
    }
}

/* Fallback entry: the mesh recogniser hands over one vertex block at a time with no model context.
 * Only useful when the per-object walk finds nothing, so it is opt-in (XWA_NRECOG). */
void xwa_native_mesh(uint32_t vnode)
{
    int pos[3], rot[3];
    if (!getenv("XWA_NRECOG") || !g_np[6]) return;
    {   double dx = (double)(g_np[0]-g_np[3]), dy = (double)(g_np[1]-g_np[4]), dz = (double)(g_np[2]-g_np[5]);
        if (dx*dx + dy*dy + dz*dz > 4.0e10) return;    /* junk flight-group coordinates */
    }
    pos[0] = g_np[0]; pos[1] = g_np[1]; pos[2] = g_np[2];
    rot[0] = g_nrot[0]; rot[1] = g_nrot[1]; rot[2] = g_nrot[2];
    if (nmesh_add(vnode, pos, rot, -1)) xwa_native_flush();
}

unsigned g_gt[4];
uint32_t g_surfreg[8192][5]; unsigned g_surfreg_n;
unsigned g_fgtype[16]; unsigned g_fgtype_n;
unsigned g_a5type[24];
uint32_t g_texnodes[512]; unsigned g_texnode_n;
unsigned g_rcount[8];
/* XWA_DRAWTRACE: call counts down the model-draw subtree, to find where submission stops. */
unsigned g_dcount[8];
const char* const g_dcount_name[8] = {"sub_004A2FB0 draw","sub_00440140","sub_0043FFB0","sub_00440E40","sub_004EA7C0","sub_004EA5D0","sub_004D5AE0 meshemit","sub_004D3520"};
const char* const g_rcount_name[8] = {
    "sub_004F2070 frame-render", "sub_004652F0 visible-list", "sub_004D3520 scene-render",
    "sub_004340D0 viewport-render", "sub_004A2FB0 MODELDRAW", "sub_00466750 obj-walk",
    "sub_004D3130 per-obj", "d3d Execute"
};

/* getenv() scans the entire environment block on every call, and the generated code calls it
 * from inside hot loops (every env-gated probe/guard does `if (getenv("XWA_..."))`). With the
 * ~25 XWA_* vars a flight run sets, that pinned the guest at ~6k calls/sec -- the flight loop
 * managed 8 frames in 480 seconds. Environment variables never change during a run, so cache
 * the result keyed on the string-literal POINTER (literals are pooled per translation unit; a
 * duplicate pointer for the same name just gets its own entry, which is still correct). */
#undef getenv
#define XWA_ENVCACHE_SLOTS 512
static struct { const char* key; char* val; } g_envcache[XWA_ENVCACHE_SLOTS];
char* xwa_getenv_cached(const char* name) {
    uintptr_t h = ((uintptr_t)name >> 4) & (XWA_ENVCACHE_SLOTS - 1);
    for (int i = 0; i < XWA_ENVCACHE_SLOTS; i++) {
        uintptr_t k = (h + i) & (XWA_ENVCACHE_SLOTS - 1);
        if (g_envcache[k].key == name) return g_envcache[k].val;
        if (g_envcache[k].key == NULL) {
            g_envcache[k].key = name;
            g_envcache[k].val = getenv(name);
            return g_envcache[k].val;
        }
    }
    return getenv(name);   /* table full: fall back (never expected) */
}

/* Real guest-pointer validity check for the recomp's garbage-pointer guards.
 * LINK_OK() is only a range test, so leftover-register garbage (e.g. 0x316A9FC0)
 * passes it and the deref still faults. VirtualQuery actually asks the OS.
 * ponytail: VirtualQuery per call is slow -- only use it inside env-gated guards. */
int xwa_readable(uint32_t addr, uint32_t len) {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t a = (uintptr_t)ADDR(addr);
    /* One-region cache: the native renderer asks this per vertex, and a VirtualQuery syscall
     * each time made it the hottest thing in flight (~12 fps after the hangar launch).
     * ponytail: re-validated every 4096 hits, so a region freed in between is trusted for at most
     * that many calls; drop the cache if a guard ever faults on decommitted memory. */
    static uintptr_t c_lo, c_hi; static unsigned c_uses;
    if (!addr) return 0;
    if (a >= c_lo && a + len <= c_hi && ++c_uses < 4096u) return 1;
    if (!VirtualQuery((void*)a, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    c_lo = (uintptr_t)mbi.BaseAddress; c_hi = c_lo + mbi.RegionSize; c_uses = 0;
    return a + len <= c_hi;
}


/* XWA_GAMELOG: sub_0050A490 is the game's own printf-style diagnostic logger. It was
 * compiled out for retail (the body is a bare `ret`), but every call site still passes a
 * real format string -- "Essential Hardware Feature NOT Supported: Z:%d Tex:%d HW:%d",
 * "NULL craft pointer in InitHUDMask()", and so on. Re-implementing it turns the engine's
 * own failure diagnostics back on, which beats guessing which branch bailed.
 * Args are cdecl on the guest stack: format at [esp+4], varargs after. */
void xwa_gamelog(uint32_t gesp) {
    static int on = -1;
    if (on < 0) on = getenv("XWA_GAMELOG") ? 1 : 0;
    if (!on) return;
    uint32_t fva = MEM32(gesp + 4);
    uint32_t _caller = MEM32(gesp);   /* #287: guest return address = which engine site logged this */
    if (!xwa_readable(fva, 1)) return;
    const char* f = (const char*)ADDR(fva);
    uint32_t argp = gesp + 8;
    char out[1024]; int o = 0;
    for (const char* c = f; *c && o < (int)sizeof(out) - 32; c++) {
        if (*c != '%') { out[o++] = *c; continue; }
        c++;
        while (*c && strchr("-+ #0123456789.lh", *c)) c++;   /* skip flags/width/length */
        uint32_t a = MEM32(argp); argp += 4;
        switch (*c) {
            case 'd': case 'i': o += sprintf(out + o, "%d", (int32_t)a); break;
            case 'u':           o += sprintf(out + o, "%u", a); break;
            case 'x':           o += sprintf(out + o, "%x", a); break;
            case 'X':           o += sprintf(out + o, "%X", a); break;
            case 'c':           out[o++] = (char)a; break;
            case 'f': case 'g': o += sprintf(out + o, "<float>"); argp += 4; break;
            case 's':           o += sprintf(out + o, "%.200s", xwa_readable(a, 1) ? (const char*)ADDR(a) : "<bad>"); break;
            case '%':           out[o++] = '%'; argp -= 4; break;
            default:            o += sprintf(out + o, "%%%c", *c ? *c : '?'); argp -= 4; break;
        }
        if (!*c) break;
    }
    out[o] = 0;
    fprintf(stderr, "[GAMELOG fmt=%06X] %s%s", fva, out, (o && out[o-1] == '\n') ? "" : "\n");
    fflush(stderr);
}

/* Simulated FS segment (Thread Environment Block) */
uint32_t g_fs_seg[256] = {0};

/* ICALL trace */
uint32_t g_icall_trace[ICALL_TRACE_SIZE] = {0};
uint32_t g_icall_trace_idx = 0;
uint32_t g_icall_count = 0;

/* Call depth tracking */
uint32_t g_call_depth = 0;
uint32_t g_call_depth_max = 0;
uint32_t g_total_calls = 0;
uint32_t g_total_icalls = 0;
int g_heap_check_enabled = 0;
/* A lifted callee that returns with esp below where the call left it lost its epilogue (or its
 * return-slot pop): every call leaks guest stack, and callers' esp-relative locals drift -- the
 * flight function read a leaked 0xDEAD0000 as its "reload the mission" flag. _chkstk-style helpers
 * lower esp on purpose; those show up here too and are expected. Report each pair once. */
uint32_t g_leak_va;   /* target of the indirect call being reported */
void recomp_esp_leak(const char *callee, uint32_t bytes, const char *caller) {
    static const char *seen_callee[256], *seen_caller[256]; static uint32_t seen_va[256]; static int n;
    uint32_t va = (strcmp(callee, "icall") && strcmp(callee, "itail")) ? 0 : g_leak_va;
    int i;
    for (i = 0; i < n; i++) if (seen_callee[i] == callee && seen_caller[i] == caller && seen_va[i] == va) return;
    if (n < 256) { seen_callee[n] = callee; seen_caller[n] = caller; seen_va[n] = va; n++; }
    if (n <= 64) { fprintf(stderr, "[ESPLEAK] %s 0x%08X returned %u bytes below the call (in %s)\n", callee, va, bytes, caller); fflush(stderr); }
}

int recomp_heap_ok(void) {
    extern uint32_t g_last_heapalloc_heap;
    HANDLE gh = (HANDLE)(uintptr_t)g_last_heapalloc_heap;
    return (!gh || HeapValidate(gh, 0, NULL)) && HeapValidate(GetProcessHeap(), 0, NULL);
}
uint32_t g_heap_check_last_ok_call = 0;
uint32_t g_heap_check_last_ok_va = 0;

/* ============================================================
 * Memory Layout Constants (from PE analysis)
 *
 * .text:  0x00401000 - 0x005A8B20  (code, not mapped - we ARE the code)
 * .rdata: 0x005A9000 - 0x005ADA24  (read-only data)
 * .data:  0x005AE000 - 0x00B0F974  (read/write data)
 *
 * We map ONE contiguous region from stack base through data end.
 * This ensures g_mem_base works for both stack and data accesses.
 * ============================================================ */

#define XWA_IMAGE_BASE    0x00400000
#define XWA_DATA_START    0x005A9000  /* .rdata start */
#define XWA_DATA_END      0x00BFB000  /* end of uncommitted region in 0x400000 heap reservation */
#define XWA_EXTENDED_END  0x02000000  /* max address for demand-paged BSS extension */
#define XWA_STACK_BASE    0x00100000  /* simulated stack start */
#define XWA_STACK_SIZE    0x00800000  /* 8 MB stack */
#define XWA_STACK_TOP     (XWA_STACK_BASE + XWA_STACK_SIZE)

/* Entire mapped region: from stack through data end */
#define XWA_REGION_START  XWA_STACK_BASE
#define XWA_REGION_END    XWA_DATA_END
#define XWA_REGION_SIZE   (XWA_REGION_END - XWA_REGION_START)

static void*  g_region_alloc = NULL;

/* ============================================================
 * VEH Crash Handler
 * ============================================================ */

static uint32_t g_seh_skip_count = 0;
static uint32_t g_esp_initial = 0;
static uint32_t g_esp_min = 0xFFFFFFFF;

static void dump_icall_trace(void) {
    fprintf(stderr, "\n=== ICALL Trace (last %d calls) ===\n", ICALL_TRACE_SIZE);
    for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
        uint32_t idx = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
        if (g_icall_trace[idx]) {
            fprintf(stderr, "  [%2d] 0x%08X\n", i, g_icall_trace[idx]);
        }
    }
    fprintf(stderr, "Total indirect calls: %u\n", g_icall_count);
}

static void dump_registers(void) {
    fprintf(stderr, "\n=== Recomp Register State ===\n");
    fprintf(stderr, "  EAX=0x%08X  ECX=0x%08X  EDX=0x%08X  EBX=0x%08X\n",
            g_eax, g_ecx, g_edx, g_ebx);
    fprintf(stderr, "  ESP=0x%08X  ESI=0x%08X  EDI=0x%08X\n",
            g_esp, g_esi, g_edi);
}

static void dump_trace_ring(void) {
    fprintf(stderr, "\n=== Trace Ring Buffer (last %d entries) ===\n", TRACE_RING_SIZE);
    uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
    for (uint32_t i = start; i < g_trace_ring_idx; i++) {
        uint32_t idx = i & (TRACE_RING_SIZE - 1);
        if (g_trace_ring[idx][0]) {
            fprintf(stderr, "  %s", g_trace_ring[idx]);
        }
    }
}

/* Hang watchdog (opt-in via XWA_WATCHDOG): every few seconds, write the call/icall
 * counters + the tail of the trace ring to a file. If the recomp hangs (e.g. flight-init
 * spins), the last dump shows which functions are spinning. */
static DWORD WINAPI watchdog_loop_thread(LPVOID p) {
    (void)p;
    uint32_t last_calls = 0; int stall = 0;
    for (;;) {
        Sleep(4000);
        uint32_t calls = g_total_calls, icalls = g_icall_count, tidx = g_trace_ring_idx;
        uint32_t delta = calls - last_calls;
        HANDLE h = CreateFileA("xwa_watchdog.log",
            GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            char buf[256]; DWORD wr;
            int n = snprintf(buf, sizeof(buf),
                "=== Watchdog ===\r\ncalls=%u (delta=%u over 4s) icalls=%u trace_idx=%u stall=%d\r\n"
                "g_esp=0x%08X eax=0x%08X ecx=0x%08X edx=0x%08X\r\n\r\n=== Trace Ring (last 96) ===\r\n",
                calls, delta, icalls, tidx, stall, g_esp, g_eax, g_ecx, g_edx);
            WriteFile(h, buf, n, &wr, NULL);
            uint32_t start = (tidx >= 96) ? (tidx - 96) : 0;
            for (uint32_t i = start; i < tidx; i++) {
                uint32_t idx = i & (TRACE_RING_SIZE - 1);
                if (g_trace_ring[idx][0]) { n = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]); WriteFile(h, buf, n, &wr, NULL); }
            }
            CloseHandle(h);
        }
        if (delta == 0) stall++; else stall = 0;
        last_calls = calls;
    }
    return 0;
}

/* Helper: write string to Win32 HANDLE */
static void wf(HANDLE h, const char* s) {
    DWORD w;
    WriteFile(h, s, (DWORD)strlen(s), &w, NULL);
}

static uint32_t g_demand_page_count = 0;

static uint32_t g_div0_skips = 0;

/* XWA_WATCH=0xADDR -- hardware write-watchpoint on a guest global.
 * "Who wrote this global?" comes up constantly here, and grepping the generated C only
 * finds direct stores: bulk memcpy/memset/rep-stosd writes, and writes through a computed
 * pointer, are invisible to grep. A debug register catches all of them and the existing
 * guest_func_for_host() names the writer.
 * Armed by raising a private exception so the VEH can set DR0/DR7 in the thread context
 * (SetThreadContext on the running thread itself is not reliable). */
#define XWA_WATCH_ARM_CODE 0xE0574348u   /* private: 'WCH' */
static uint32_t g_watch_addr = 0;
static uint32_t g_watch_hits = 0;

/* Re-arm the watchpoint on a different address at runtime (heap addresses are not known
 * until the game allocates them, so a startup-only XWA_WATCH cannot reach them). */
void xwa_watch_set(uint32_t addr) {
    g_watch_addr = addr;
    g_watch_hits = 0;
    fprintf(stderr, "[WATCH] re-arming on 0x%08X\n", addr);
    fflush(stderr);
    RaiseException(XWA_WATCH_ARM_CODE, 0, 0, NULL);
}

static void xwa_arm_watch(void) {
    const char* w = getenv("XWA_WATCH");
    if (!w) return;
    g_watch_addr = (uint32_t)strtoul(w, NULL, 0);
    if (!g_watch_addr) return;
    fprintf(stderr, "[WATCH] arming hardware write-watch on 0x%08X\n", g_watch_addr);
    fflush(stderr);
    RaiseException(XWA_WATCH_ARM_CODE, 0, 0, NULL);
}

static LONG WINAPI veh_handler(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    /* XWA_WATCH: arm the debug register (the OS applies our edits to ContextRecord). */
    if (code == XWA_WATCH_ARM_CODE) {
        CONTEXT* c = ep->ContextRecord;
        c->Dr0 = (DWORD)ADDR(g_watch_addr);
        /* L0 enable | RW0=write | LEN0=4 bytes; an unaligned address gets LEN0=1 byte, since the CPU
         * rounds a 4-byte watch down to the aligned dword and would report the neighbours' writes */
        c->Dr7 = ((c->Dr0 & 3) || getenv("XWA_WATCHBYTE")) ? 0x00010001u : 0x000D0001u;
        c->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    /* XWA_WATCH: a watched write just executed -- EIP is the instruction AFTER it. */
    if (code == EXCEPTION_SINGLE_STEP && g_watch_addr && (ep->ContextRecord->Dr6 & 1)) {
        CONTEXT* c = ep->ContextRecord;
        extern uint32_t guest_func_for_host(uintptr_t host_addr);
        extern uint32_t g_crash_host_offset;
        uint32_t gva = guest_func_for_host((uintptr_t)c->Eip);
        g_watch_hits++;
        if (g_watch_hits <= 24) {
            fprintf(stderr, "[WATCH] #%u 0x%08X = 0x%08X   writer: sub_%08X (+0x%X host) eip=0x%08X\n",
                    g_watch_hits, g_watch_addr, MEM32(g_watch_addr), gva, g_crash_host_offset, (uint32_t)c->Eip);
            fflush(stderr);
        }
        c->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    /* Integer divide-by-zero survival: the flight scene render (projection/scale math, incl. MSVC's 64-bit
     * __aulldiv/__aulldvrm helpers) divides by view/camera params that are 0 under force-launch. Decode the
     * faulting div/idiv at EIP, set quotient(EAX)/remainder(EDX)=0, and step past it so the render survives
     * (degenerate frame, not a crash). Only fires under XWA_RUNSCENE. */
    if ((code == EXCEPTION_INT_DIVIDE_BY_ZERO || code == EXCEPTION_INT_OVERFLOW) && getenv("XWA_RUNSCENE")) {
        CONTEXT* ctx = ep->ContextRecord;
        uint8_t* p = (uint8_t*)ctx->Eip;
        int len = 0;
        while (*p==0x66||*p==0x67||*p==0xF0||*p==0xF2||*p==0xF3||(*p>=0x26&&*p<=0x3E&&(*p&7)==6)||*p==0x64||*p==0x65) { p++; len++; }
        if (*p==0xF6 || *p==0xF7) {           /* div/idiv */
            p++; len++;
            uint8_t modrm = *p++; len++;
            int mod = modrm>>6, rm = modrm&7;
            if (mod!=3 && rm==4) { len++; }    /* SIB byte */
            if (mod==1) len+=1; else if (mod==2) len+=4; else if (mod==0 && rm==5) len+=4;
            ctx->Eax = 0; ctx->Edx = 0; ctx->Eip += len;
            g_div0_skips++;
            if (g_div0_skips <= 8 || (g_div0_skips & 0x3FF)==0)
                fprintf(stderr, "[DIV0] skipped divide-by-zero #%u at EIP=0x%p (len=%d)\n", g_div0_skips, (void*)(uintptr_t)ctx->Eip, len);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    /* Demand-paging: auto-commit pages for accesses in the extended BSS range.
     * The original game's data extends past the PE .data VSize, and we can't
     * pre-reserve everything due to existing allocations (DLLs, heap, etc.). */
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        uintptr_t fault_addr = ep->ExceptionRecord->ExceptionInformation[1];
        if (fault_addr >= XWA_DATA_START && fault_addr < XWA_EXTENDED_END) {
            uintptr_t page = fault_addr & ~0xFFFu;
            void* p = NULL;

            /* Strategy 1: Commit within existing reservation */
            p = VirtualAlloc((void*)page, 0x1000, MEM_COMMIT, PAGE_READWRITE);

            /* Strategy 2: Change protection on already-committed pages */
            if (!p) {
                DWORD old_prot;
                if (VirtualProtect((void*)page, 0x1000, PAGE_READWRITE, &old_prot)) {
                    p = (void*)page;
                }
            }

            /* Strategy 2b: For MEM_MAPPED pages, try PAGE_WRITECOPY */
            if (!p) {
                DWORD old_prot;
                if (VirtualProtect((void*)page, 0x1000, PAGE_WRITECOPY, &old_prot)) {
                    p = (void*)page;
                }
            }

            /* Strategy 3: Reserve+commit in free space at 64KB-aligned base */
            if (!p) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery((void*)page, &mbi, sizeof(mbi)) && mbi.State == MEM_FREE) {
                    uintptr_t block = page & ~0xFFFFu;
                    p = VirtualAlloc((void*)block, 0x10000,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                }
            }

            if (p) {
                g_demand_page_count++;
                if (g_demand_page_count <= 32 || (g_demand_page_count & 0xFF) == 0) {
                    fprintf(stderr, "[DEMAND] Page at 0x%08X (fault=0x%08X, count=%u)\n",
                            (uint32_t)(uintptr_t)p, (uint32_t)fault_addr, g_demand_page_count);
                }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            /* If all strategies failed, fall through to crash handler */
            fprintf(stderr, "[DEMAND] FAILED at 0x%08X (err=%lu)\n",
                    (uint32_t)fault_addr, GetLastError());
        }
    }

    /* Log ALL exceptions to stderr (even non-fatal ones) for debugging */
    fprintf(stderr, "\n!!! VEH: exception 0x%08lX at 0x%p !!!\n",
        code, (void*)ep->ExceptionRecord->ExceptionAddress);
    {   /* Name the generated-C line for the faulting address. Every line of the generated
         * code ends in a comment holding the original guest instruction, so this turns a raw
         * host address straight into the guest opcode that faulted. */
        static int sym_ready = -1;
        if (sym_ready < 0) {
            SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
            sym_ready = SymInitialize(GetCurrentProcess(), NULL, TRUE) ? 1 : 0;
        }
        if (sym_ready > 0) {
            DWORD disp = 0;
            IMAGEHLP_LINE64 li; li.SizeOfStruct = sizeof(li);
            if (SymGetLineFromAddr64(GetCurrentProcess(),
                                     (DWORD64)(uintptr_t)ep->ExceptionRecord->ExceptionAddress,
                                     &disp, &li)) {
                const char* base = li.FileName ? strrchr(li.FileName, '\\') : NULL;
                fprintf(stderr, "    -> %s:%lu (+%lu)\n",
                        base ? base + 1 : (li.FileName ? li.FileName : "?"),
                        (unsigned long)li.LineNumber, (unsigned long)disp);
            }
        }
    }
    {   /* Map the host fault EIP back to the guest function that contains it:
         * the dispatch entry whose host func pointer is the greatest <= the EIP
         * (functions are laid out roughly in order, so this names the crash site). */
        extern uint32_t guest_func_for_host(uintptr_t host_addr);
        uint32_t gva = guest_func_for_host((uintptr_t)ep->ExceptionRecord->ExceptionAddress);
        if (gva) {
            extern uint32_t g_crash_host_offset; extern int g_crash_contained;
            fprintf(stderr, "    -> in guest function sub_%08X (+0x%X host, %s)\n",
                    gva, g_crash_host_offset, g_crash_contained ? "CONTAINED" : "uncertain/gap");
        }
    }
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        fprintf(stderr, "    %s addr=0x%p, g_esp=0x%08X, total_calls=%u\n",
            ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
            (void*)ep->ExceptionRecord->ExceptionInformation[1],
            g_esp, g_total_calls);
    }
    {   /* If the fault is in a system DLL (not our exe), name the module and walk the host
         * stack to find the guest function(s) that called into it. */
        uintptr_t fip = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
        HMODULE hm = NULL; char modname[MAX_PATH] = "?";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)fip, &hm) && hm) GetModuleFileNameA(hm, modname, MAX_PATH);
        fprintf(stderr, "    fault module: %s (base=0x%p)\n", modname, (void*)hm);
        extern uint32_t guest_func_for_host(uintptr_t host_addr);
        uintptr_t* sp = (uintptr_t*)(uintptr_t)ep->ContextRecord->Esp;
        int found = 0;
        for (int i = 0; i < 64 && found < 5; i++) {
            uintptr_t v = 0; __try { v = sp[i]; } __except(1) { break; }
            uint32_t gv = guest_func_for_host(v);
            if (gv) { extern int g_crash_contained; fprintf(stderr, "    stack[+%02X]=0x%zX -> guest sub_%08X\n", i*4, v, gv); found++; }
        }
        /* Deep in a system DLL (the D3D runtime / WARP) the guest frames are far up the stack:
         * also print the first host return addresses inside this exe, raw, for
         * `llvm-symbolizer --obj=build-farm/xwa_recomp.exe <addr>`. */
        {   HMODULE me = GetModuleHandleA(NULL); MODULEINFO mi; int n = 0;
            if (hm != me && GetModuleInformation(GetCurrentProcess(), me, &mi, sizeof mi)) {
                uintptr_t lo = (uintptr_t)mi.lpBaseOfDll, hi = lo + mi.SizeOfImage;
                MEMORY_BASIC_INFORMATION smb; int lim = 0;
                if (VirtualQuery((void*)sp, &smb, sizeof smb))
                    lim = (int)(((uintptr_t)smb.BaseAddress + smb.RegionSize - (uintptr_t)sp) / sizeof(uintptr_t));
                if (lim > 2048) lim = 2048;
                fprintf(stderr, "    host chain:");
                for (int i = 0; i < lim && n < 8; i++) {
                    uintptr_t v = sp[i];
                    if (v > lo + 0x1000 && v < hi) { fprintf(stderr, " %zX", v); n++; }
                }
                fprintf(stderr, "\n");
            }
        }
    }
    if (code == 0xC0000374 /* STATUS_HEAP_CORRUPTION */) {
        extern uint32_t g_last_heapalloc_heap, g_last_heapalloc_size, g_last_heapalloc_ret;
        extern uint32_t g_last_heapfree_ptr, g_heapop_count;
        fprintf(stderr, "    HEAP CORRUPTION: heapop_count=%u\n", g_heapop_count);
        fprintf(stderr, "    last HeapAlloc: heap=0x%08X size=0x%08X ret=0x%08X\n",
                g_last_heapalloc_heap, g_last_heapalloc_size, g_last_heapalloc_ret);
        fprintf(stderr, "    last HeapFree: ptr=0x%08X\n", g_last_heapfree_ptr);
        fprintf(stderr, "    g_esp=0x%08X, total_calls=%u, total_icalls=%u\n",
                g_esp, g_total_calls, g_total_icalls);
        /* Dump trace ring */
        fprintf(stderr, "    Last 16 trace ring entries:\n");
        for (int i = 16; i > 0; i--) {
            uint32_t idx = (g_trace_ring_idx - i) & (TRACE_RING_SIZE-1);
            fprintf(stderr, "      [-%d] %s", i, g_trace_ring[idx]);
        }
    }
    fflush(stderr);

    /* Only handle fatal exceptions (skip C++ exceptions, breakpoints, etc.) */
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_PRIV_INSTRUCTION &&
        code != EXCEPTION_IN_PAGE_ERROR &&
        code != EXCEPTION_ARRAY_BOUNDS_EXCEEDED &&
        code != 0xC0000374 /* STATUS_HEAP_CORRUPTION */) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /* Write crash dump using raw Win32 API only - no CRT at all */
    HANDLE h = CreateFileA("xwa_crash.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[256];

        snprintf(buf, sizeof(buf), "=== CRASH: Exception 0x%08X ===\r\n"
            "  Faulting IP: 0x%p\r\n", code, (void*)ep->ExceptionRecord->ExceptionAddress);
        wf(h, buf);

        if (ep->ExceptionRecord->NumberParameters >= 2) {
            snprintf(buf, sizeof(buf), "  %s at 0x%p\r\n",
                ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
                (void*)ep->ExceptionRecord->ExceptionInformation[1]);
            wf(h, buf);
        }

        snprintf(buf, sizeof(buf),
            "\r\nEAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
            "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n"
            "Stack usage: %u bytes (initial=0x%08X)\r\n"
            "Call depth: %u (max: %u)\r\n"
            "Total calls: %u, icalls: %u\r\n",
            g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi,
            g_esp_initial - g_esp, g_esp_initial,
            g_call_depth, g_call_depth_max,
            g_total_calls, g_total_icalls);
        wf(h, buf);

        /* Dump simulated stack */
        wf(h, "\r\n=== Stack ===\r\n");
        for (int i = -4; i < 16; i++) {
            uint32_t addr = g_esp + i * 4;
            snprintf(buf, sizeof(buf), "  [ESP%+d] 0x%08X: 0x%08X\r\n", i*4, addr, MEM32(addr));
            wf(h, buf);
        }

        /* Dump trace ring */
        wf(h, "\r\n=== Trace Ring ===\r\n");
        uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
        for (uint32_t i = start; i < g_trace_ring_idx; i++) {
            uint32_t idx = i & (TRACE_RING_SIZE - 1);
            if (g_trace_ring[idx][0]) {
                snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                wf(h, buf);
            }
        }

        /* Dump ICALL trace */
        wf(h, "\r\n=== ICALL Trace ===\r\n");
        for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
            uint32_t idx = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
            if (g_icall_trace[idx]) {
                snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", i, g_icall_trace[idx]);
                wf(h, buf);
            }
        }
        snprintf(buf, sizeof(buf), "Total indirect calls: %u\r\n", g_icall_count);
        wf(h, buf);

        CloseHandle(h);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ============================================================
 * Dispatch Table Lookup (binary search)
 * ============================================================ */

recomp_func_t recomp_lookup(uint32_t va) {
    int lo = 0;
    int hi = (int)recomp_dispatch_count - 1;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint32_t mid_va = recomp_dispatch_table[mid].address;
        if (mid_va == va) {
            return recomp_dispatch_table[mid].func;
        } else if (mid_va < va) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return NULL;
}

/* Crash-diagnosis helper: given a HOST code address (a fault EIP inside the
 * compiled recomp), return the GUEST VA of the dispatch-table function whose
 * host entry pointer is the greatest value <= host_addr. MSVC lays the lifted
 * functions out roughly in table order, so the nearest entry below the EIP
 * names the crashing guest function. Linear scan — only runs on a crash. */
uint32_t g_crash_host_offset = 0;   /* EIP - resolved function's host entry */
int      g_crash_contained = 0;     /* 1 if EIP < next function's host entry (accurate) */
uint32_t guest_func_for_host(uintptr_t host_addr) {
    uintptr_t best_fn = 0, next_fn = (uintptr_t)-1;
    uint32_t best_va = 0;
    for (uint32_t i = 0; i < recomp_dispatch_count; i++) {
        uintptr_t fn = (uintptr_t)recomp_dispatch_table[i].func;
        if (fn <= host_addr && fn > best_fn) { best_fn = fn; best_va = recomp_dispatch_table[i].address; }
        if (fn > host_addr && fn < next_fn) next_fn = fn;
    }
    /* Reject matches absurdly far below the EIP (likely not the real function). */
    if (best_fn && (host_addr - best_fn) < 0x20000) {
        g_crash_host_offset = (uint32_t)(host_addr - best_fn);
        g_crash_contained = (host_addr < next_fn) ? 1 : 0;  /* EIP within [best_fn,next_fn) */
        return best_va;
    }
    g_crash_host_offset = 0; g_crash_contained = 0;
    return 0;
}

/* SafeDisc-encrypted function stubs
 * These addresses (in .text 0x5A0000-0x5A8FFF) contain encrypted code from
 * SafeDisc copy protection. The Steam version doesn't decrypt them.
 * They're called from CRT __initterm during C++ static initialization.
 * Safe to stub as no-ops since we don't need SafeDisc initialization. */
static void stub_safedisc_nop(void) {
    /* Clean return: pop return address */
    g_esp += 4;
}

/* Stub for __sbh_heap_init - returns 1 (success) without initializing SBH */
static void stub_sbh_heap_init(void) {
    g_eax = 1;  /* return TRUE (success) */
    g_esp += 4;  /* pop return address */
}

/* Stub for __sbh_find_block - always returns 0 (not found).
 * Since SBH is disabled (threshold=0), no allocations go through SBH,
 * so no blocks should ever be found. This prevents the real function
 * from traversing uninitialized SBH header list at 0x60BBF8.
 * Signature: int __sbh_find_block(void* ptr, HEADER** pHeader, REGION** pRegion)
 * cdecl, 3 args (12 bytes), caller cleans stack. */
static void stub_sbh_find_block(void) {
    g_eax = 0;  /* not found */
    g_esp += 4;  /* pop return address */
}

/* sub_0057E560: Pre-main-loop init callback.
 * Called via function pointer at 0xA1C071 before entering the game loop.
 * Initializes sound/music subsystems and loads font resources.
 * Original code: 0x0057E560-0x0057E59E */
static void manual_sub_0057E560(void) {
    extern void sub_0053F800(void);
    extern void sub_0053F5C0(void);
    extern void sub_0055BB90(void);
    extern void sub_0053F5B0(void);
    extern void sub_0053F970(void);
    extern void sub_00556B20(void);
    #define esp g_esp

    RECOMP_CALL(sub_0053F800);
    PUSH32(esp, 0);
    RECOMP_CALL(sub_0053F5C0);
    esp += 4;
    RECOMP_CALL(sub_0055BB90);
    RECOMP_CALL(sub_0053F5B0);
    RECOMP_CALL(sub_0053F970);
    PUSH32(esp, 0xAu);
    RECOMP_CALL(sub_00556B20);
    esp += 4;
    PUSH32(esp, 0xCu);
    RECOMP_CALL(sub_00556B20);
    esp += 4;
    PUSH32(esp, 0xFu);
    RECOMP_CALL(sub_00556B20);
    esp += 4;
    g_eax = 0;
    esp += 4;  /* pop return address */

    #undef esp
}

/* sub_0057E4F0: Per-frame update callback.
 * Called every game loop iteration from sub_0053E760.
 * Handles sound mixing, display flip, and frame timing.
 * Original code: 0x0057E4F0-0x0057E557 */
static void manual_sub_0057E4F0(void) {
    extern void sub_0053F010(void);
    extern void sub_0055BC20(void);
    extern void sub_0053F5D0(void);
    extern void sub_00541810(void);
    extern void sub_0053EF80(void);
    #define esp g_esp

    fprintf(stderr, "[57E4F0] ENTER\n"); fflush(stderr);
    RECOMP_CALL(sub_0053F010);
    fprintf(stderr, "[57E4F0] after 53F010\n"); fflush(stderr);
    PUSH32(esp, 0);
    PUSH32(esp, 0x00601C9Cu);
    RECOMP_CALL(sub_0055BC20);
    g_eax = MEM32(0x9F4B40);
    esp += 8;
    fprintf(stderr, "[57E4F0] movie1: 9F4B40=%u\n", g_eax); fflush(stderr);
    if (g_eax != 0) goto frame_skip;
    PUSH32(esp, 0);
    PUSH32(esp, 0x00601C94u);
    RECOMP_CALL(sub_0055BC20);
    g_eax = MEM32(0x9F4B40);
    esp += 8;
    fprintf(stderr, "[57E4F0] movie2: 9F4B40=%u\n", g_eax); fflush(stderr);
    if (g_eax != 0) goto frame_skip;
    PUSH32(esp, 0);
    PUSH32(esp, 0x00601C88u);
    RECOMP_CALL(sub_0055BC20);
    esp += 8;
    fprintf(stderr, "[57E4F0] movie3 done\n"); fflush(stderr);
frame_skip:
    fprintf(stderr, "[57E4F0] frame_skip\n"); fflush(stderr);
    RECOMP_CALL(sub_0053F5D0);
    fprintf(stderr, "[57E4F0] after flip, registering callbacks\n"); fflush(stderr);
    PUSH32(esp, 0x00584F30u);
    PUSH32(esp, 0x00584F50u);
    RECOMP_CALL(sub_00541810);
    esp += 8;
    fprintf(stderr, "[57E4F0] after 541810, calling 53EF80\n"); fflush(stderr);
    RECOMP_CALL(sub_0053EF80);
    fprintf(stderr, "[57E4F0] EXIT eax=%u\n", g_eax); fflush(stderr);
    MEM32(0x9F60D4) = g_eax;
    g_eax = 0;
    esp += 4;  /* pop return address */

    #undef esp
}

/* ponytail: drive the natural 3D flight render from present().
 * 0x7828D0 (render buffer) is 0 because sub_00509530's render branch never runs (called once,
 * takes INIT branch). sub_00511A90 allocates the buffer + registers the view; sub_004340D0(0)
 * dispatches the per-viewport render (-> sub_00433850 -> ICALL 0x9109C0). Both are the real
 * game functions, called with correct args (the old d3d11 injection passed a garbage stack arg). */
/* Drive the mission's per-frame sim update (XWA_SIMDRIVE).
 *
 * Under force-launch the flight loop that actually runs is sub_00457C20 -> sub_004596C0, which never
 * reaches the per-frame call to sub_004F6510(tick) that the engine's own frame function
 * (sub_0050FCB0) makes at 0x5109C9 -- that function enters once and stays inside the flight loop.
 * So mission state never advances and no flight group ever arrives. Call the update from the present
 * path, which really is once per frame; the engine's frame timer at 0x7D4B8C is advanced here too,
 * since the loop that would normally advance it is not running.
 *
 * This is NOT the DirectPlay handler sub_004F8A40: that one expects a message and faults on a
 * poisoned pointer when called with nothing. */
/* Ring of distinct blocks visited inside the flight loop sub_004596C0, so a spin shows up as a
 * short repeating cycle rather than a single "last block" reading. */
unsigned g_fbring[16];
unsigned g_fbidx;
void xwa_fblk(unsigned blk) {
    if (g_fbidx && g_fbring[(g_fbidx - 1u) & 15u] == blk) return;   /* same block again */
    g_fbring[g_fbidx & 15u] = blk;
    g_fbidx++;
}

/* Ring of distinct blocks inside the DirectPlay session create, so its polling wait shows up as a
 * short repeating cycle instead of a single "last block" reading. */
unsigned g_dpring[16];
unsigned g_dpridx;
void xwa_dpblk(unsigned blk) {
    if (g_dpridx && g_dpring[(g_dpridx - 1u) & 15u] == blk) return;
    g_dpring[g_dpridx & 15u] = blk;
    g_dpridx++;
}

void xwa_drive_simtick(void) {
    extern void sub_004F6510(void);
    static int _in = 0;
    static unsigned _n = 0;
    #define esp g_esp
    if (_in || !g_in_flight) return; /* only inside flight, and never re-entered */
    _in = 1;
    if (getenv("XWA_PARTFIX") && MEM32(0x8C1CD8) != 0u) {
        /* Put the world back in the player's region before stepping the sim. The per-flight-group
         * loop in sub_00417580 keeps re-partitioning to region 1 (this mission's second region), and
         * in region 1 the craft slice is empty (base == count), so the create loop has nowhere to
         * put an arriving craft. Retail flies with partition 0, base 0, craft in [0,252). */
        extern void sub_004154A0(void);
        static int _pw; if (_pw < 3) { _pw++;
            fprintf(stderr, "[PARTFIX/sim] repartitioning %u -> 0 before the tick\n",
                    MEM32(0x8C1CD8)); fflush(stderr); }
        PUSH32(esp, 0);
        RECOMP_CALL(sub_004154A0);
        esp = esp + 4;
    }
    {   /* Flight presents only ~20 frames per run here, so one tick per frame gives the mission
         * almost no time and nothing ever arrives. XWA_SIMDRIVE=N runs N updates per frame, which
         * fast-forwards mission time. */
        const char* e = getenv("XWA_SIMDRIVE");
        int steps = e ? atoi(e) : 1, k;
        if (steps < 1) steps = 1;
        if (steps > 4000) steps = 4000;
        /* Two flags gate this path, both documented at the sites that read them: sub_004F6510
         * diverts unless MEM8(0x8053E4) != 1, and the per-craft create sub_00405590 returns
         * immediately while MEM32(0x7827E4) is non-zero. Under force-launch they are left set, so
         * the update runs but the world never advances. Clear them across the call. */
        uint32_t sv1 = MEM32(0x7827E4);
        uint8_t  sv2 = MEM8(0x8053E4);
        if (getenv("XWA_SIMGATE")) { MEM32(0x7827E4) = 0; MEM8(0x8053E4) = 0; }
        /* The update returns immediately unless the tick it is handed is PAST the time it last
         * simulated, which it keeps at 0x8B94D4 (`if (last >= tick) return`). Feeding it the engine's
         * frame timer is not enough -- something else advances that too, so the value was usually
         * already behind. Drive from the last-simulated time instead, one step at a time. */
        for (k = 0; k < steps; k++) {
            uint32_t t = MEM32(0x8B94D4) + 1u;
            MEM32(0x7D4B8C) = t;
            PUSH32(esp, t);
            RECOMP_CALL(sub_004F6510);
            esp = esp + 4;
            _n++;
        }
        if (getenv("XWA_SIMGATE") && getenv("XWA_SIMRESTORE")) { MEM32(0x7827E4) = sv1; MEM8(0x8053E4) = sv2; }
        if (_n < (unsigned)steps + 1u)
            fprintf(stderr, "[SIMGATE] entry flags: 7827E4=%u 8053E4=%u\n", sv1, sv2);
    }
    if ((_n % 200u) == 1u && getenv("XWA_WHERE")) {
        extern unsigned g_frameblk, g_loaderblk, g_spawnfn[8];
        { extern unsigned g_dpcnt[8]; extern int g_dp_active;
          fprintf(stderr, "[WHERE] frameFn=%u lastblk=0x%06X loader=0x%06X | dispatch=%u handler=%u simtick=%u\n",
                  g_spawnfn[1], g_frameblk, g_loaderblk,
                  g_spawnfn[0], g_spawnfn[3], g_spawnfn[4]);
          fprintf(stderr, "        DP: Send=%u SendEx=%u Receive=%u GetMsgCount=%u dp_active=%d\n",
                  g_dpcnt[0], g_dpcnt[1], g_dpcnt[2], g_dpcnt[3], g_dp_active); }
        fflush(stderr);
    }
    if ((_n % 500u) < 2u && getenv("XWA_FLOOP")) {
        extern unsigned g_fbring[16], g_fbidx; unsigned q;
        fprintf(stderr, "[FLOOP] last blocks:");
        for (q = 0; q < 16u; q++) fprintf(stderr, " %06X", g_fbring[(g_fbidx + q) & 15u]);
        fprintf(stderr, "\n"); fflush(stderr);
    }
    if ((_n % 500u) < 2u) {          /* is the world actually growing? */
        uint32_t tbl = MEM32(0x7B33C4), cnt = MEM32(0x917E64), i, live = 0;
        if (tbl && cnt && cnt < 4096u)
            for (i = 0; i < cnt; i++)
                if (xwa_readable(tbl + i*0x27u, 0x27) && MEM16(tbl + i*0x27u + 2)) live++;
        {   /* is the sim actually simulating? watch a real craft and the pending-create cursor */
            uint32_t o3 = tbl + 3u * 0x27u;
            fprintf(stderr, "[SIMDRIVE] simtime=%u ticks=%u live=%u obj3=(%d,%d,%d) cursor=%u count=%u\n",
                    MEM32(0x8B94D4), _n, live,
                    xwa_readable(o3, 0x27) ? (int32_t)MEM32(o3 + 7) : 0,
                    xwa_readable(o3, 0x27) ? (int32_t)MEM32(o3 + 0xB) : 0,
                    xwa_readable(o3, 0x27) ? (int32_t)MEM32(o3 + 0xF) : 0,
                    MEM16(0x80B61C), MEM32(0x8BF380));
            { extern unsigned g_simblk, g_crloopblk, g_createblk; extern unsigned g_spawnfn[8];
              { extern unsigned g_crloopprev;
                fprintf(stderr, "           simblk=0x%06X crloop=0x%06X prev=0x%06X(calls=%u) create=0x%06X(calls=%u)\n",
                      g_simblk, g_crloopblk, g_crloopprev, g_spawnfn[6], g_createblk, g_spawnfn[7]); } }
        }
        fflush(stderr);
    }
    _in = 0;
    #undef esp
}

void xwa_drive_render(void) {
    extern void sub_00511A90(void);
    extern void sub_004340D0(void);
    static int _in = 0;
    #define esp g_esp
    if (_in) return;
    _in = 1;
    if (MEM32(0x7828D0) == 0) {
        RECOMP_CALL(sub_00511A90);           /* alloc render buffer + register view (one-time) */
        fprintf(stderr, "[DRIVE] after 511A90: 7828D0=0x%X 7828D4=%u\n",
                MEM32(0x7828D0), MEM32(0x7828D4)); fflush(stderr);
    }
    { static int _v; if (_v<3) { _v++;
        fprintf(stderr, "[DRIVE] gate 0x7CA1EC=0x%08X  viewport[0] @0x91B240=0x%08X  viewport[1]=0x%08X\n",
            MEM32(0x7CA1EC), MEM32(0x91B240), MEM32(0x91B244)); fflush(stderr); } }
    PUSH32(esp, 0);                          /* viewport index 0 (player cockpit view) */
    { extern int g_drv_active; g_drv_active = 1; }
    RECOMP_CALL(sub_004340D0);               /* -> sub_00433850 -> scene render */
    { extern int g_drv_active; g_drv_active = 0; }
    esp += 4;
    _in = 0;
    #undef esp
}

/* #45: drive the host-spawn (sub_004F6510 -> sub_004F6B70 create loop) from present, ONCE, when the
 * mission is fully loaded (FGcount=20) — the POSTSPAWN drive was too early (FG table not populated).
 * Set the host-spawn entry preconditions (0x7827E4==0 && 0x7D4C4D==1). XWA_DPSPAWN. */
void xwa_drive_spawn(void) {
    extern void sub_004F6510(void);
    static int _done = 0, _in = 0;
    #define esp g_esp
    if (_in || _done) return;
    if (MEM32(0x63185C) < 2) return;         /* wait for FGcount populated */
    _in = 1; _done = 1;
    { int v=0,s; for(s=0;s<0x40;s++){ uint32_t t=MEM32(s*0xBCFu+0x8B94E0u); if(t!=0xFFFFu&&t!=0)v++; }
      fprintf(stderr,"[SPAWN45] driving sub_004F6510 from present: FGcount=%u validslots_before=%d\n", MEM32(0x63185C), v); fflush(stderr); }
    /* #63: direct spawn — tag each flight-group's object slot ACTIVE (+0x8B94F1=2) and set its FG index
     * (+0), then drive sub_005064D0 (the spawn scan) which builds (sub_0041EF60) + activates each. */
    /* Directly tagging slots active + calling sub_005064D0 CRASHES: sub_0041EF60 (build) reads craft-type
     * data that isn't set on fake-tagged slots. Gated behind XWA_FORCESPAWN so the default run reaches
     * flight with the real world-build objects (validslots_before) and we can observe the render first. */
    if (getenv("XWA_FORCESPAWN")) { extern void sub_005064D0(void);
      uint32_t fgt = MEM32(0x7B33C4u), fgn = MEM32(0x63185Cu), i, tagged = 0;
      for (i = 0; i < fgn && i < 0x40; i++) {
          uint32_t slot = MEM8(fgt + i*0x27u + 5);
          if (slot < 0x40u) {
              uint32_t base = slot*0xBCFu + 0x8B94E0u;
              if (MEM32(base) == 0xFFFFu || MEM32(base) == 0) {   /* only fill empty slots */
                  MEM32(base) = i;                 /* +0  = FG index */
                  MEM8(base + 0x11) = 2;           /* +0x11 = active */
              }
              tagged++;
          }
      }
      MEM32(0x7827E4u) = 0; MEM8(0x7D4C4Du) = 1; MEM8(0x80DB68u) = 0;
      if (MEM32(0x910DECu) < 0x40u) MEM32(0x910DECu) = 0x40u;   /* scan all slots */
      fprintf(stderr, "[SPAWN63] tagged %u FG slots; driving sub_005064D0; 910DEC=%u\n", tagged, MEM32(0x910DECu)); fflush(stderr);
      RECOMP_CALL(sub_005064D0); }
    { int v=0,s; for(s=0;s<0x40;s++){ uint32_t t=MEM32(s*0xBCFu+0x8B94E0u); if(t!=0xFFFFu&&t!=0)v++; }
      fprintf(stderr,"[SPAWN45] validslots_after=%d\n", v); fflush(stderr); }
    _in = 0;
    #undef esp
}

/* sub_00584F30: Outer init callback.
 * Calls sound init, game init callback, and display init.
 * Original code: 0x00584F30-0x00584F41 */
static void manual_sub_00584F30(void) {
    extern void sub_005580D0(void);
    extern void sub_00528A50(void);
    extern void sub_0055D720(void);
    #define esp g_esp
    fprintf(stderr, "[584F30] ENTER g_esp=0x%08X\n", g_esp); fflush(stderr);
    RECOMP_CALL(sub_005580D0);
    fprintf(stderr, "[584F30] after 5580D0 g_esp=0x%08X\n", g_esp); fflush(stderr);
    {
        uint32_t _esp_save = g_esp;
        RECOMP_CALL(sub_00528A50);
        if (g_esp != _esp_save) {
            fprintf(stderr, "[584F30] FIXING 528A50 esp drift: 0x%08X -> 0x%08X (delta=%d)\n",
                    _esp_save, g_esp, (int)(g_esp - _esp_save)); fflush(stderr);
            g_esp = _esp_save;
        }
    }
    fprintf(stderr, "[584F30] after 528A50 g_esp=0x%08X\n", g_esp); fflush(stderr);
    RECOMP_CALL(sub_0055D720);
    fprintf(stderr, "[584F30] after 55D720 g_esp=0x%08X\n", g_esp); fflush(stderr);
    g_eax = 0;
    esp += 4;
    fprintf(stderr, "[584F30] EXIT g_esp=0x%08X\n", g_esp); fflush(stderr);
    #undef esp
}

/* sub_00584F50: Outer frame callback.
 * Calls sound update, then recurses with inner callbacks.
 * Original code: 0x00584F50-0x00584F72 */
static void manual_sub_00584F50(void) {
    extern void sub_00558100(void);
    extern void sub_00541810(void);
    #define esp g_esp
    fprintf(stderr, "[584F50] ENTER g_esp=0x%08X\n", g_esp); fflush(stderr);
    g_eax = MEM32(0xABD1E4);
    PUSH32(esp, g_eax);
    RECOMP_CALL(sub_00558100);
    esp += 4;
    PUSH32(esp, 0x00539760u);
    PUSH32(esp, 0x005397D0u);
    RECOMP_CALL(sub_00541810);
    esp += 8;
    g_eax = 0;
    esp += 4;
    fprintf(stderr, "[584F50] EXIT g_esp=0x%08X\n", g_esp); fflush(stderr);
    #undef esp
}

/* sub_00539760: Inner cleanup callback.
 * Frees music/sound resources and closes resource files.
 * Original code: 0x00539760-0x005397C3 */
static void manual_sub_00539760(void) {
    extern void sub_00558BE0(void);
    extern void sub_00564D10(void);
    extern void sub_0055DD40(void);
    extern void sub_0055DCE0(void);
    extern void sub_0055D480(void);
    extern void sub_005387A0(void);
    #define esp g_esp
    RECOMP_CALL(sub_00558BE0);
    PUSH32(esp, 0x00602BB4u);
    RECOMP_CALL(sub_00564D10);
    esp += 4;
    RECOMP_CALL(sub_0055DD40);
    RECOMP_CALL(sub_0055DCE0);
    g_eax = MEM32(0x9F4B98);
    if (g_eax != 0) {
        PUSH32(esp, g_eax);
        RECOMP_CALL(sub_0055D480);
        esp += 4;
        MEM32(0x9F4B98) = 0;
    }
    g_eax = MEM32(0x9F4B24);
    if (g_eax != 0) {
        PUSH32(esp, g_eax);
        RECOMP_CALL(sub_0055D480);
        esp += 4;
        MEM32(0x9F4B24) = 0;
    }
    PUSH32(esp, 0x00602BA8u);
    RECOMP_CALL(sub_005387A0);
    esp += 4;
    g_eax = 0;
    esp += 4;
    #undef esp
}

/* Headless UI driver (opt-in via XWA_FLYDEMO env var): once the concourse is the
 * active screen, simulate a mouse click on the Training door (drawn at 536,174),
 * which calls sub_57E370 (training-mission setup) + sub_541810(sub_5316B0,0) — the
 * loading screen that loads the mission and dispatches the 3D flight loop
 * (sub_5710F0 init / sub_49E600 frame). This is the shortest concourse->flight path
 * (no skirmish UI). Driven each frame from the PeekMessageA bridge.
 *
 * Active screen callback = MEM32(0xA1C8D5 + 0x850*depth), depth = MEM32(0xA1C089)
 * (sub_541810 stores cb at dword_A1C8D5[532*dword_A1C089]).
 * Mouse pos read by sub_55BA50 = dword_9F65ED+5 / dword_9F65F1+5.
 * Left click read by sub_5581D0 = (dword_9F6888 ? 0 : (uint8)dword_9F6884).
 * Holding the button across frames re-triggers and crashes, so click exactly once. */
int g_flydemo_launch_cmd = 0;  /* set by the driver, consumed once by the sub_5438B0 dispatch hook */
int g_flydemo_skip_menu = 0;   /* set by the driver: force past the skirmish config menu (sub_529330) to reach the Fly button */
int g_flydemo_confirm = 0;     /* set by the driver while the skirmish cb is active: auto-confirm sub_5593C0 dialogs */
uint32_t g_skdbg_cb = 0, g_skdbg_esp0 = 0;  /* dispatch: capture skirmish cb + esp around the dispatch ICALL (esp-leak workaround) */
/* Mirror of tools/snap_flight.py for the recomp side -- same addresses, same layout,
 * so `diff` on the two dumps points straight at what the forced launch failed to build. */
static void snap_hex(const char* tag, uint32_t base, uint32_t len) {
    fprintf(stderr, "  %s @0x%08X:\n", tag, base);
    for (uint32_t off = 0; off < len; off += 16) {
        char hex[64], txt[20]; int hp = 0;
        for (uint32_t i = 0; i < 16 && off + i < len; i++) {
            uint8_t c = xwa_readable(base + off + i, 1) ? MEM8(base + off + i) : 0;
            hp += sprintf(hex + hp, "%02X ", c);
            txt[i] = (c >= 32 && c < 127) ? (char)c : '.';
            txt[i + 1] = 0;
        }
        fprintf(stderr, "    %08X  %-48s %s\n", base + off, hex, txt);
    }
}

static const struct { const char* name; uint32_t addr; } g_snap_globals[] = {
    {"A1C089  screen depth", 0xA1C089}, {"ABD7B4  game mode", 0xABD7B4},
    {"77330C  session flag", 0x77330C}, {"773310", 0x773310},
    {"A21449  DP object", 0xA21449},    {"9AFEE4  DP saved obj", 0x9AFEE4},
    {"7B33C4  FG table", 0x7B33C4},     {"63185C  FG count (u16)", 0x63185C},
    {"8C1CC8  player slot", 0x8C1CC8},  {"7CA3B8  craft loop end", 0x7CA3B8},
    {"8BF378  craft loop start", 0x8BF378}, {"7B4C00  obj count (u16)", 0x7B4C00},
    {"8052A0  obj pool", 0x8052A0},     {"8C1CE4  view count", 0x8C1CE4},
    {"80B610  obj stride div", 0x80B610}, {"8B94C8  obj count2", 0x8B94C8},
    {"7D5240  FG total", 0x7D5240},     {"7828D0  ALERTBOXBUFFER ptr", 0x7828D0},
    {"9109C0  render fn ptr", 0x9109C0}, {"7B1CE0  scene ptr", 0x7B1CE0},
    {"7B1CE8  render ctx", 0x7B1CE8},   {"7B1CD4  render flags", 0x7B1CD4},
    {"68C898  HUD mask A", 0x68C898},   {"68C89C  HUD mask B", 0x68C89C},
    {"693594  rasterizer mode", 0x693594}, {"7CA3A8  screen h", 0x7CA3A8},
    {"7D4B6C  screen w", 0x7D4B6C},     {"8D6BB0  render gate", 0x8D6BB0},
    {"8BA034  camera ref craft", 0x8BA034}, {"8BA028  camera X", 0x8BA028},
    {"8BA02C  camera Y", 0x8BA02C},     {"8BA030  camera Z", 0x8BA030},
    {"80DC80  species tbl", 0x80DC80},  {"80DCBC  species entry", 0x80DCBC},
    {"9F4B98  skirmish buf", 0x9F4B98}, {"9EB8E0  craft tbl", 0x9EB8E0},
    {"AE2A8A  mission index", 0xAE2A8A}, {"7B1D04  block list cnt", 0x7B1D04},
};

void xwa_snap_flight(uint32_t cb, uint32_t depth) {
    const uint32_t FG_STRIDE = 0x27, OBJ_STRIDE = 0xBCF;
    fprintf(stderr, "\n=== XWA RECOMP flight snapshot (mirrors tools/snap_flight.py) ===\n");
    fprintf(stderr, "active screen cb = 0x%08X (depth=%u)\n\n", cb, depth);

    fprintf(stderr, "=== globals ===\n");
    for (size_t i = 0; i < sizeof(g_snap_globals) / sizeof(g_snap_globals[0]); i++) {
        uint32_t a = g_snap_globals[i].addr;
        uint32_t v = xwa_readable(a, 4) ? MEM32(a) : 0;
        fprintf(stderr, "  %-26s @0x%06X = 0x%08X (%u)\n", g_snap_globals[i].name, a, v, v);
    }
    fprintf(stderr, "\n=== camera view matrix 0x8D93C0..0x8D9400 ===\n");
    snap_hex("cam", 0x8D93C0, 0x40);
    fprintf(stderr, "=== camera matrix SOURCE 0x693774..0x6937B0 ===\n");
    snap_hex("camsrc", 0x693774, 0x3C);

    uint32_t fgt = MEM32(0x7B33C4), fgn = MEM16(0x63185C);
    fprintf(stderr, "\n=== flight groups: table=0x%08X count=%u (stride 0x27) ===\n", fgt, fgn);
    for (uint32_t i = 0; i < fgn && i < 24; i++) {
        uint32_t base = fgt + i * FG_STRIDE;
        if (!xwa_readable(base, FG_STRIDE)) { fprintf(stderr, "  FG[%2u] @0x%08X <unreadable>\n", i, base); continue; }
        fprintf(stderr, "  FG[%2u] @0x%08X type=%-5u slot=%-3u pos=(%d,%d,%d) ro=0x%08X\n", i, base,
                MEM16(base + 2), MEM8(base + 5), (int32_t)MEM32(base + 7), (int32_t)MEM32(base + 0xB),
                (int32_t)MEM32(base + 0xF), MEM32(base + 0x23));
        snap_hex("fg", base, FG_STRIDE);
    }

    uint32_t pslot = MEM32(0x8C1CC8);
    fprintf(stderr, "\n=== player craft: slot 0x8C1CC8 = %u ===\n", pslot);
    if (pslot < 0x400) {
        uint32_t rec = 0x8B94E0 + pslot * OBJ_STRIDE, fgidx = MEM32(rec);
        fprintf(stderr, "  record @0x%08X  FGidx(+0)=0x%X\n", rec, fgidx);
        fprintf(stderr, "    +0x004 f4=0x%02X  +0x010 craftType=0x%02X  +0x011 tag=0x%02X  +0x015 built=0x%02X\n",
                MEM8(rec + 4), MEM8(rec + 0x10), MEM8(rec + 0x11), MEM8(rec + 0x15));
        fprintf(stderr, "    +0x0EE craftID=0x%02X  +0x0F0 type=0x%02X  +0x0F1 active=0x%02X  +0x0F5 f5=0x%02X\n",
                MEM8(rec + 0xEE), MEM8(rec + 0xF0), MEM8(rec + 0xF1), MEM8(rec + 0xF5));
        snap_hex("playerobj", rec, 0x100);
        if (fgidx != 0xFFFF && fgt) {
            uint32_t fgb = fgt + fgidx * FG_STRIDE, ro = xwa_readable(fgb + 0x23, 4) ? MEM32(fgb + 0x23) : 0;
            fprintf(stderr, "  player FG[%u] @0x%08X  ro(+0x23)=0x%08X\n", fgidx, fgb, ro);
            if (ro && xwa_readable(ro, 0x120)) {
                snap_hex("ro", ro, 0x120);
                uint32_t scene = MEM32(ro + 0xDD);
                fprintf(stderr, "  ro+0xDD=0x%08X  ro+0xD9=0x%08X  ro+0x8D=0x%08X  ro+0=0x%08X\n",
                        scene, MEM32(ro + 0xD9), MEM32(ro + 0x8D), MEM32(ro));
                if (scene && xwa_readable(scene, 0x100)) snap_hex("ro+0xDD target", scene, 0x100);
            }
        }
    }

    fprintf(stderr, "\n=== object slots 0..39 (0x8B94E0, stride 0xBCF) ===\n");
    for (uint32_t s = 0; s < 40; s++) {
        uint32_t rec = 0x8B94E0 + s * OBJ_STRIDE;
        if (!xwa_readable(rec, 0x100)) continue;
        uint32_t fgidx = MEM32(rec);
        if (fgidx == 0xFFFF) continue;
        fprintf(stderr, "  slot[%2u] FGidx=0x%X type(+0x10)=0x%02X tag(+0x11)=0x%02X active(+0xF1)=0x%02X\n",
                s, fgidx, MEM8(rec + 0x10), MEM8(rec + 0x11), MEM8(rec + 0xF1));
    }
    fprintf(stderr, "=== end snapshot ===\n\n");
    fflush(stderr);
}

void xwa_ui_driver(void) {
    static int enabled = -1;
    if (enabled < 0) enabled = getenv("XWA_FLYDEMO") ? 1 : 0;
    if (!enabled) return;

    uint32_t depth = MEM32(0xA1C089);
    uint32_t cb = MEM32(0xA1C8D5 + 0x850u * depth);
    static uint32_t last_cb = 0;
    /* XWA_CLICKSWEEP: find a screen's active control empirically. Sweep the click position over a
     * grid while the screen is up and report which point was last clicked when the screen changes.
     * XWA_CLICKSWEEP=<screen-hex>, XWA_SWEEPSTEP=<px>, XWA_SWEEPHOLD=<frames per point>. */
    if (getenv("XWA_CLICKSWEEP")) {
        static int sweep_i = 0, sweep_lx = -1, sweep_ly = -1, reported = 0;
        static uint32_t sweep_screen = 0;
        uint32_t want = (uint32_t)strtoul(getenv("XWA_CLICKSWEEP"), NULL, 16);
        int step = getenv("XWA_SWEEPSTEP") ? atoi(getenv("XWA_SWEEPSTEP")) : 32;
        int hold = getenv("XWA_SWEEPHOLD") ? atoi(getenv("XWA_SWEEPHOLD")) : 3;
        if (step < 4) step = 4;
        if (hold < 1) hold = 1;
        if (cb == want) {
            int y0 = getenv("XWA_SWEEPY0") ? atoi(getenv("XWA_SWEEPY0")) : 0;
            int y1 = getenv("XWA_SWEEPY1") ? atoi(getenv("XWA_SWEEPY1")) : 480;
            int cols = 640 / step;
            int idx  = sweep_i / hold;
            int x = (idx % cols) * step + step / 2;
            int y = y0 + (idx / cols) * step + step / 2;
            sweep_screen = cb;
            if (y < y1) {
                MEM32(0x9F65ED) = (uint32_t)(x - 5);
                MEM32(0x9F65F1) = (uint32_t)(y - 5);
                g_ui_mx = x - 5; g_ui_my = y - 5;   /* survive the game's own cursor update */
                if ((sweep_i % hold) == 0) {
                    MEM8(0x9F6884) = 1;
                    g_ui_click = 3;                    /* survive the game's own click-flag clear */
                    sweep_lx = x; sweep_ly = y;
                    if ((idx % 40) == 0) {
                        fprintf(stderr, "[SWEEP] point %d -> (%d,%d)\n", idx, x, y);
                        fflush(stderr);
                    }
                }
                sweep_i++;
            }
        } else if (sweep_screen == want && !reported) {
            reported = 1;
            fprintf(stderr, "[SWEEP] *** screen 0x%08X left after clicking (%d,%d) -> now 0x%08X ***\n",
                    want, sweep_lx, sweep_ly, cb);
            fflush(stderr);
        }
    }
    static int fip = 0;            /* frames since the active screen last changed */
    /* XWA_UICLICKS="x,y;x,y;..." on screen XWA_UICLICKSCR: click a scripted sequence of points,
     * XWA_UICLICKGAP frames apart. Menus need several steps (assign the player to a flight group,
     * then launch), which a single click cannot express. */
    /* XWA_UIDRAG="x1,y1,x2,y2" on XWA_UICLICKSCR: press at the source, travel to the target with
     * the button held, release there. Assignment lists in these menus are drag-and-drop, which a
     * click event cannot express. XWA_UIDRAGAT sets the frame it starts on. */
    /* XWA_BARRSEL=<n>: the barracks screen dispatches on 0x78397C through a jump table
     * (index = value-1): 1 = concourse, 2 = screen 0x571910, 3 = Combat Simulator,
     * 4 = screen 0x5775E0 (which is one of the routines that pushes the LOADING screen).
     * The demo driver navigates by forcing this rather than by clicking, which is why clicks on
     * "Play Mission" do nothing -- these sprite rooms take a different input path entirely. */
    if (getenv("XWA_BARRSEL") && cb == 0x0055FF30) {
        static int logged = 0;
        uint32_t v = (uint32_t)strtoul(getenv("XWA_BARRSEL"), NULL, 0);
        /* The screen reads this from its FIRST call, and only consults the table once the
         * transition phase reads complete -- 0x9F4B48/0x9F4B4C = 3, exactly as the driver's own
         * barracks navigation does. Setting the selector alone does nothing. */
        MEM32(0x78397C) = v;
        MEM32(0x9F4B48) = 3;
        MEM32(0x9F4B4C) = 3;
        if (logged < 2) { logged++;
            fprintf(stderr, "[BARRSEL] forcing 0x78397C=%u with phase 9F4B48/4C=3 (fip=%d)\n", v, fip);
            fflush(stderr); }
    }
    if (getenv("XWA_UIDRAG") && getenv("XWA_UICLICKSCR")) {
        uint32_t scr = (uint32_t)strtoul(getenv("XWA_UICLICKSCR"), NULL, 16);
        int at = getenv("XWA_UIDRAGAT") ? atoi(getenv("XWA_UIDRAGAT")) : 40;
        if (cb == scr && fip >= at && fip <= at + 24) {
            int x1 = 0, y1 = 0, x2 = 0, y2 = 0;
            const char* q = getenv("XWA_UIDRAG");
            const char* c;
            x1 = atoi(q);
            c = strchr(q, ','); if (!c) c = q; else c++;
            y1 = atoi(c);
            c = strchr(c, ','); if (c) c++; else c = q;
            x2 = atoi(c);
            c = strchr(c, ','); if (c) c++; else c = q;
            y2 = atoi(c);
            {   int t = fip - at;                    /* 0..24 */
                int x, y;
                if (t <= 2)        { x = x1; y = y1; g_ui_down = 1; }
                else if (t <= 16)  { x = x1 + (x2 - x1) * (t - 2) / 14;
                                     y = y1 + (y2 - y1) * (t - 2) / 14; g_ui_down = 1; }
                else if (t <= 20)  { x = x2; y = y2; g_ui_down = 1; }
                else               { x = x2; y = y2; g_ui_down = 0;
                                     if (t == 21) { MEM8(0x9F6884) = 1; g_ui_click = 3; } }
                g_ui_mx = x - 5; g_ui_my = y - 5;
                MEM32(0x9F65ED) = (uint32_t)(x - 5);
                MEM32(0x9F65F1) = (uint32_t)(y - 5);
                if (t == 0 || t == 21) {
                    fprintf(stderr, "[UIDRAG] %s at (%d,%d) fip=%d\n",
                            t ? "release" : "press", x, y, fip);
                    fflush(stderr);
                }
            }
        }
    }
    if (getenv("XWA_UICLICKS") && getenv("XWA_UICLICKSCR")) {
        static int seq_i = 0;
        uint32_t scr = (uint32_t)strtoul(getenv("XWA_UICLICKSCR"), NULL, 16);
        int gap = getenv("XWA_UICLICKGAP") ? atoi(getenv("XWA_UICLICKGAP")) : 25;
        if (gap < 2) gap = 2;
        { static int dbg; if (dbg < 6) { dbg++;
            fprintf(stderr, "[UICLICK] driver sees cb=0x%08X (want 0x%08X) fip=%d\n", cb, scr, fip);
            fflush(stderr); } }
        if (cb == scr && fip > 10 && ((fip - 10) % gap) == 0) {
            const char* q = getenv("XWA_UICLICKS");
            int n = 0, x = -1, y = -1;
            while (*q) {                       /* walk to the seq_i'th "x,y" pair */
                int vx = atoi(q);
                const char* c = strchr(q, ',');
                if (!c) break;
                { int vy = atoi(c + 1);
                  if (n == seq_i) { x = vx; y = vy; break; }
                }
                n++;
                q = strchr(c, ';');
                if (!q) break;
                q++;
            }
            if (x >= 0 && y >= 0) {
                g_ui_mx = x - 5; g_ui_my = y - 5;
                MEM32(0x9F65ED) = (uint32_t)(x - 5);
                MEM32(0x9F65F1) = (uint32_t)(y - 5);
                MEM8(0x9F6884) = 1; g_ui_click = 3;
                fprintf(stderr, "[UICLICK] step %d -> (%d,%d) at fip=%d\n", seq_i, x, y, fip);
                fflush(stderr);
                seq_i++;
            }
        }
    }
    /* XWA_SNAPUI=N: dump the composited 2D screen N frames after the active screen last changed,
     * so a menu can actually be looked at (which control launches the mission, and where it is). */
    /* XWA_UISURF=N: dump every registered surface N frames after the active screen last changed,
     * so a menu can be inspected. Menus composite into DirectDraw surfaces, not the back buffer. */
    if (getenv("XWA_UISURF")) {
        /* XWA_UISURF="60,120,180": dump at each listed frame-after-screen-change, so a multi-step
         * menu interaction can be watched step by step. Surface #2 is the composited screen. */
        const char* q = getenv("XWA_UISURF");
        int hit = 0;
        while (*q) {
            if (atoi(q) == fip) { hit = 1; break; }
            q = strchr(q, ',');
            if (!q) break;
            q++;
        }
        if (hit) {
            unsigned i;
            fprintf(stderr, "[UISURF] screen 0x%08X at fip=%d: %u surfaces\n", cb, fip, g_surfreg_n);
            for (i = 0; i < g_surfreg_n && i < 12u; i++) {
                char nm[80];
                sprintf(nm, "ui_%08X_f%03d_surf%u.bmp", cb, fip, i);
                xwa_dump_surface(i, nm);
            }
        }
    }
    if (getenv("XWA_SNAPUI")) {
        static int _snapped_for = -1;
        int want = atoi(getenv("XWA_SNAPUI")); if (want <= 0) want = 40;
        if (fip == want && _snapped_for != want + (int)MEM32(0x9F60D4)) {
            /* Ask the PRESENT path to capture: capturing from here grabs the back buffer before
             * the frame has been composited and presented, which just yields black. */
            extern int g_ui_snap_req;
            _snapped_for = want + (int)MEM32(0x9F60D4);
            g_ui_snap_req = 1;
            fprintf(stderr, "[SNAPUI] requested a capture of the presented screen at fip=%d\n", fip);
            fflush(stderr);
        }
    }

    /* Activate the DirectPlay loopback (com_mocks) only on the mission-load screens
     * (skirmish lobby / loading / flight-init), so it doesn't replay unrelated
     * startup/frontend messages (which cause a clean early exit). */
    { extern int g_dp_active;
      g_dp_active = (cb == 0x005438B0 || cb == 0x005316B0 || cb == 0x005710F0) ? 1 : 0; }

    /* Clear the dialog-auto-confirm each frame; it's re-armed below only while the skirmish cb is active,
     * so boot/concourse dialogs are never auto-confirmed. */
    { extern int g_flydemo_confirm; if (cb != 0x005438B0) g_flydemo_confirm = 0; }

    /* EXPERIMENT (XWA_FORCEGATE): single-player never opens the DirectPlay message
     * gate dword_A21449 (all gate-setters are multiplayer). Force it to a mock
     * IDirectPlay4 object once we're past the concourse, so sub_52CEE0/sub_52CF50
     * actually write the loopback mission-load message — to test whether the gate
     * is what blocks the SP world build. */
    if (getenv("XWA_FORCEGATE")) {
        if ((cb == 0x0053B500 || cb == 0x005438B0 || cb == 0x005316B0 ||
             cb == 0x005710F0 || cb == 0x0057ECE0) && MEM32(0xA21449) == 0) {
            extern uint32_t com_alloc_dplay_object(void);
            uint32_t obj = com_alloc_dplay_object();
            if (obj) { MEM32(0xA21449) = obj;
                fprintf(stderr, "[FORCEGATE] set dword_A21449=0x%08X at cb=0x%06X\n", obj, cb);
                fflush(stderr); }
        }
        /* #50: the host never QUEUES the per-FG create messages because there's no DP session
         * (0x77330C=0). Give it a session object on the mission-load screens so the host-side
         * mission-object spawn queues+sends the type-0x3E creates. XWA_DPSESS. */
        /* #54: calling the session creator sub_0050C640(1) runs the chain (→ sub_00441EE0 →
         * sub_0059453F) but it FAILS GRACEFULLY (returns 0, 0x77330C ends up 0) — session init fails at
         * the DirectPlay CONNECTION level: our DP COM mock doesn't implement real EnumConnections/
         * InitializeConnection/Open/CreatePlayer session semantics. THE ROOT: implement DirectPlay
         * session/connection in com_mocks.c so sub_0059453F succeeds → 0x77330C set → host spawns craft.
         * Left as a no-op. Complete blueprint (DP COM connection → session → creates → render) in #48-54. */
    }
    static uint32_t clicked = 0;   /* one-shot: which screen we've already clicked */
    if (cb != last_cb) {
        const char* nm =
            cb == 0x005316B0 ? " (LOADING SCREEN)" :
            cb == 0x005710F0 ? " (FLIGHT INIT)" :
            cb == 0x0049E600 ? " (*** 3D FLIGHT FRAME ***)" :
            cb == 0x005397D0 ? " (concourse)" :
            cb == 0x0053B500 ? " (combat sim)" :
            cb == 0x005438B0 ? " (skirmish setup)" : "";
        fprintf(stderr, "[FLYDEMO] active screen cb -> 0x%06X (depth=%u)%s\n", cb, depth, nm);
        if (getenv("XWA_RCTXPROBE"))
            fprintf(stderr, "[RCTX] cb=0x%06X 7828D0(rbuf)=0x%X 7828D4=0x%X 7B1CE0(scene)=0x%X 7B1CD4(flags)=0x%X 7B1CE8=0x%X 773358(prim)=0x%X\n",
                cb, MEM32(0x7828D0), MEM32(0x7828D4), MEM32(0x7B1CE0), MEM32(0x7B1CD4), MEM32(0x7B1CE8), MEM32(0x773358)), fflush(stderr);
        /* NOTE (#123): 0x7B1CE8 (3D render context) is 0 at EVERY screen (concourse/menus/flight) — the DirectDraw
         * 3D render-context/texture backend is NEVER built in this recomp. Primary surface 0x773358 exists (2D/HUD
         * draws), but per-texture 3D surfaces need the render context (sub_00441EE0->sub_0059453F) which never
         * completes on the incomplete DDraw mocks. Root of no-3D-render, project-wide. Gate behind XWA_RENDERINIT if re-added. */
        /* XWA_RUNSCENE: on the concourse->flight transition, reset the render-object block list
         * (head 0x7B1D08 / tail 0x7B1D0C / count 0x7B1D04). Force-launch skips sub_0059453F's
         * re-init (@0x594936), so the flight render inherits the concourse's stale list and its
         * first block-free (sub_00597E5F) walks into a freed concourse block -> wild write crash.
         * Zeroing here makes flight blocks link into a fresh empty list. One-shot per transition. */
        if (cb == 0x005710F0 && getenv("XWA_RUNSCENE")) {
            /* NOTE: calling the REAL render-ctx init (sub_00441EE0) crashes deep in sub_00594063 on a COM
             * mock sentinel (READ 0xDEAD0000) — the DDraw/D3D surface+device establish derefs mock returns
             * that are still placeholders. So instead we fake just enough render state (below) to let the
             * software/execute-buffer render path run, guarding the un-initialized pool's garbage derefs. */
            MEM32(0x7B1D04) = 0; MEM32(0x7B1D08) = 0; MEM32(0x7B1D0C) = 0;
            MEM32(0x77330C) = 1;   /* session/render-context flag: ungate the per-frame 3D scene render */
            if (MEM32(0x7B1CE0) == 0) MEM32(0x7B1CE0) = 0x00B0D8A0;
            /* Measured in a live skirmish: the real game has the 3D render context
             * 0x7B1CE8 = 0x00B0D2CC (a STATIC address, same base+index scheme as 0x7B1CE0,
             * both with index 0). Earlier notes wrote this off as a red herring because it
             * is 0 on the concourse -- it is not 0 in flight. */
            if (MEM32(0x7B1CE8) == 0) MEM32(0x7B1CE8) = 0x00B0D2CC;
            /* Wire all three D3D device-interface globals used by the flight render to the mock device:
             * 0x7B15BC (execute submit), 0x7B1D14 (CreateExecuteBuffer, vtable[6]), 0x7B1D18 (aux). */
            { extern uint32_t com_ensure_d3d_device(void); uint32_t d = com_ensure_d3d_device();
              if (d) { if (MEM32(0x7B15BC) == 0) MEM32(0x7B15BC) = d;
                       if (MEM32(0x7B1D14) == 0) MEM32(0x7B1D14) = d;
                       if (MEM32(0x7B1D18) == 0) MEM32(0x7B1D18) = d;
                       if (MEM32(0x7B1180) == 0) MEM32(0x7B1180) = d; } }  /* frame Execute device (sub_005984BA) */
            fprintf(stderr, "[RUNSCENE] render ctx: 0x77330C=%u pool=0x%08X d3ddev(BC/D14/D18)=0x%08X/0x%08X/0x%08X\n",
                    MEM32(0x77330C), MEM32(0x7B1CE0), MEM32(0x7B15BC), MEM32(0x7B1D14), MEM32(0x7B1D18)); fflush(stderr);
            /* PROBE (#117): drive the REAL render-context init sub_00441EE0 (which runs sub_0059453F -> sets the
             * render-ctx pointer 0x7B1CE8 needed by the OPT geometry loader). main.c note says it crashes deep in
             * sub_00594063 on a DirectDraw COM-mock sentinel; capture the EXACT crash to fix that one mock. */
            if (getenv("XWA_RENDERINIT")) { static int _ri=0; if(!_ri){ _ri=1;
                extern void sub_00441EE0(void);
                /* sub_00441EE0(arg1=MEM32(0x773358), arg2=MEM32(0x773348)) — the DirectDraw device/surface objects
                 * (-> 0x7B1D14/0x7B1D18). Pass them exactly as the real caller @0x50C408 does (push eax=0x773348,
                 * push ecx=0x773358). My earlier no-arg call read stack garbage (0xDEAD0000) — that was the bug. */
                fprintf(stderr, "[RENDERINIT] ddraw globals 773344=0x%08X 773348=0x%08X 773358=0x%08X 7B1CE4=0x%08X\n",
                        MEM32(0x773344), MEM32(0x773348), MEM32(0x773358), MEM32(0x7B1CE4)); fflush(stderr);
                /* 0x773348 (arg2, the secondary/back DDraw surface) is null under force-launch; the real flow sets
                 * it = MEM32(0x773344) @0x50C226. Populate it (fall back to the valid primary 0x773358) so
                 * sub_00441EE0 takes the real init path instead of the null-bail. */
                if (MEM32(0x773348) == 0) { uint32_t s = MEM32(0x773344); if (!s) s = MEM32(0x773358);
                    MEM32(0x773348) = s; fprintf(stderr, "[RENDERINIT] seeded 773348=0x%08X\n", s); fflush(stderr); }
                uint32_t _a1 = MEM32(0x773358), _a2 = MEM32(0x773348);
                PUSH32(g_esp, _a2); PUSH32(g_esp, _a1); PUSH32(g_esp, 0xDEAD0000u); sub_00441EE0(); g_esp += 8;
                fprintf(stderr, "[RENDERINIT] RETURNED OK -> 0x7B1CE8=0x%08X 0x7B1D14=0x%08X 0x7B1D18=0x%08X\n",
                        MEM32(0x7B1CE8), MEM32(0x7B1D14), MEM32(0x7B1D18)); fflush(stderr); } }
        }
        /* On the loading/flight transitions, dump the mission-load state: is the
         * message gate open (dword_A21449), are the mission globals set, and is the
         * species/craft table (0x80DCBC) populated? This tells us whether the
         * message-driven mission load delivered anything. */
        if (cb == 0x005316B0 || cb == 0x005710F0 || cb == 0x0057ECE0 ||
            cb == 0x005438B0 || cb == 0x0053B500) {
            uint32_t spec0 = MEM32(0x80DCBC), spec1 = MEM32(0x80DCBC + 0xE38);
            fprintf(stderr, "[MSTATE] A21449(msggate)=%u ABD7B4(mode)=%u AE2A8A(missIdx)=%u "
                    "9E9708(craftIdx)=%u flyGates(9F4B4C/9F4B48)=%u/%u\n",
                    MEM32(0xA21449), MEM32(0xABD7B4), MEM32(0xAE2A8A), MEM16(0x9E9708),
                    MEM32(0x9F4B4C), MEM32(0x9F4B48));
            fprintf(stderr, "[MSTATE] species[0x80DCBC]=0x%08X entry1=0x%08X craftSrc(7B33C4)=0x%08X ABC0E5(craftCnt)=%u crafttbl(9EB8E0)=0x%08X skmbuf(9F4B98)=0x%08X\n",
                    spec0, spec1, MEM32(0x7B33C4), MEM32(0xABC0E5), MEM32(0x9EB8E0), MEM32(0x9F4B98));
            fflush(stderr);
        }
        /* campaign progression state: won flag, progression gate, mission index (pilot AE2A8E[AE2A8A]) */
        fprintf(stderr, "[CAMPAIGN] cb 0x%06X: 9EAA04=%u B07B53=%u ABC970=%u ABC96C=%u AE2A8A=%u AE2A9E=%u ABD7C8=%u 7831AC=%u ABD81E=%u\n",
                cb, MEM32(0x9EAA04), MEM32(0xB07B53), MEM32(0xABC970), MEM32(0xABC96C), MEM32(0xAE2A8A), MEM32(0xAE2A9E),
                MEM32(0xABD7C8), MEM32(0x7831AC), MEM32(0xABD81E));
        {   uint32_t g = MEM32(0x9EB8E0);   /* the debrief's result inputs (sub_00582ED0) */
            fprintf(stderr, "[CAMPAIGN]   result: AE2A86=%u AF3CC6[0..2]=%u,%u,%u 9C6E2C=%u B1B82=%u B1B83=%u 807A60=%u\n",
                    MEM32(0xAE2A86), MEM32(0xAF3CC6), MEM32(0xAF3CC6 + 0x1C), MEM32(0xAF3CC6 + 0x38), MEM32(0x9C6E2C),
                    g ? MEM8(g + 0xB1B82) : 0xFFu, g ? MEM8(g + 0xB1B83) : 0xFFu, MEM8(0x807A60));
            /* per-mission records (0xAED75E + id*0x30: +0 played, +0x10 won) and the mission list's ids
             * (0x9F4B98, 0x148-byte entries, id at +0x140): sub_0053AA90 picks the first unwon one */
            uint32_t l = MEM32(0x9F4B98); if (l && !xwa_readable(l, 0x290 + 0x144)) l = 0;   /* stale between screens */
            {   /* sub_0042E750 records a campaign mission only with exactly one active player slot
                 * (dword 0x8BA077 + k*0xBCF) and mission type 0x7B6FAA = 5 or 6 */
                uint32_t a, np = 0; for (a = 0x8BA077u; a < 0x8BFEEFu; a += 0xBCFu) np += MEM32(a) != 0;
                fprintf(stderr, "[CAMPAIGN]   recorder: players=%u type(7B6FAA)=%u\n", np, MEM8(0x7B6FAA)); }
            fprintf(stderr, "[CAMPAIGN]   missions: played/won id0=%u/%u id1=%u/%u id2=%u/%u | list(%u) ids %d %d %d\n",
                    MEM32(0xAED75E), MEM32(0xAED76E), MEM32(0xAED75E + 0x30), MEM32(0xAED76E + 0x30), MEM32(0xAED75E + 0x60), MEM32(0xAED76E + 0x60),
                    MEM32(0x9F5EC0), l ? (int)MEM32(l + 0x140) : -1, l ? (int)MEM32(l + 0x148 + 0x140) : -1, l ? (int)MEM32(l + 0x290 + 0x140) : -1); }
        fflush(stderr);
        last_cb = cb; fip = 0;
    }
    fip++;

    /* XWA_DEBRSEL=<n> (default 1 under XWA_AUTOPLAY): the debriefing room (0x57ECE0) is a sprite
     * room like the barracks -- no keys; it dispatches on 0x784B00 (1..7) once its transition
     * phase 0x9F4B48/4C reads 3. 1 = accept: copies the active pilot record (0xABD7E0) over the
     * saved one (0xAE2A60) and goes to 0x5397D0; 4 = refly (LOADING); 6 = route 0x5775E0. */
    if (cb == 0x0057ECE0 && fip > 300 && (getenv("XWA_DEBRSEL") || getenv("XWA_AUTOPLAY"))) {
        uint32_t v = getenv("XWA_DEBRSEL") ? (uint32_t)strtoul(getenv("XWA_DEBRSEL"), NULL, 0) : 1u;
        MEM32(0x784B00) = v; MEM32(0x9F4B48) = 3; MEM32(0x9F4B4C) = 3;
        if (fip % 100 == 1) { fprintf(stderr, "[DEBRSEL] forcing 0x784B00=%u with phase 9F4B48/4C=3 (fip=%d)\n", v, fip); fflush(stderr); }
    }

    /* XWA_TRAINLAUNCH: skip the flaky door-click entirely. Once the concourse is
     * settled, run the training door's own handler sequence directly (from
     * 0x0053A244): sub_57E370 (training-mission setup) then sub_541810(0x5316B0,0)
     * which pushes the loading screen that loads the mission and dispatches the
     * 3D flight loop (sub_5710F0 init / sub_49E600 frame). Training missions carry
     * the player craft in the .tie, so this avoids the skirmish craft-config wall.
     * Callee-saved regs are preserved (the guest game loop that called us via the
     * PeekMessage bridge relies on ebx/esi/edi across the call). Fire once. */
    static int tl_env = -1;
    if (tl_env < 0) tl_env = getenv("XWA_TRAINLAUNCH") ? 1 : 0;
    {
        static int tl_done = 0;
        /* The barracks<->concourse ping-pong resets `fip` (consecutive-frames) every flip, so it
         * rarely rested 30 frames on concourse — the old cause of the intermittent launch. Count
         * CUMULATIVE frames on EITHER the concourse (0x5397D0) or the more-stable barracks (0x55FF30)
         * so we fire reliably regardless of the oscillation. sub_57E370/sub_541810 don't need the
         * concourse specifically active — they set up the training mission + push the loading screen. */
        static int conc_frames = 0;
        if (cb == 0x005397D0 || cb == 0x0055FF30) conc_frames++;
        if (tl_env && !tl_done && (cb == 0x005397D0 || cb == 0x0055FF30) && conc_frames >= 40) {
            extern void sub_0057E370(void);
            extern void sub_00541810(void);
            extern void sub_0050EC70(void);
            uint32_t sb = g_ebx, ss = g_esi, sd = g_edi;
            /* XWA_DPSESSION: set the DP session-active flag (0xB0C7BC, low byte -> 0x77330C) BEFORE the
             * world-build, so the host's create-broadcast sub_004E7A10 (gated on 0x77330C!=0 in sub_004F6510)
             * runs and generates the 0x3E creates for the mission craft. This is the documented sole blocker
             * (#58-59). Set it here (pre loading-screen) so it's active through the whole mission-load. */
            /* 0xB0C7BC is a TWO-entry byte array, not a dword: worldinit does
             * 0x77330C = MEM8(0xB0C7BC + (sub_0049C950() > 0)) @0x50ACAE. Writing a dword 1
             * set [0]=1 but left [1]=0, so when that index came out 1 the session flag was
             * cleared right back to 0 -- which is why 0x77330C was 0 by [WI-CKPT] despite
             * XWA_RUNSCENE setting it. The real game runs a skirmish with 0x77330C==1
             * (measured live), so set both entries. */
            if (getenv("XWA_DPSESSION")) { MEM8(0xB0C7BCu) = 1; MEM8(0xB0C7BDu) = 1;
                fprintf(stderr, "[DPSESSION] set 0xB0C7BC=1 (0x77330C session flag) before world-build\n"); fflush(stderr); }
            fprintf(stderr, "[TRAINLAUNCH] invoking sub_50EC70 (craft-def load) + sub_57E370 + sub_541810(0x5316B0,0)\n");
            fflush(stderr);
            /* XWA_LOADCRAFT: also run the craft-definition loader (sub_0050EC70) that
             * the SP force-launch path skips — it fills the static craft table 0x7825F8
             * and sets _pctype-like 0x7B33C4, which the .tie/world-build derefs. */
            if (getenv("XWA_LOADCRAFT")) {
                PUSH32(g_esp, 0xDEAD0000u);
                sub_0050EC70();
                fprintf(stderr, "[TRAINLAUNCH] sub_50EC70 done: 0x7B33C4=0x%08X\n", MEM32(0x7B33C4));
                fflush(stderr);
            }
            PUSH32(g_esp, 0xDEAD0000u);            /* ret addr */
            sub_0057E370();
            /* sub_57E370 leaves ABD7B4=2 (skirmish/message path) -> the loading screen instantly
             * transitions to flight-init WITHOUT running sub_549330 (the .tie loader), so FGcount=0.
             * The loading screen gets only ONE tick, too fast for the driver's cb==0x5316B0 check to
             * catch it — so force the sub_549330 gate HERE (ABD7B4=1 non-skirmish, 9EAC20 load-pending,
             * timer base 0 = 2s gate already elapsed). Then the loading screen's first tick loads the
             * mission's flight groups. Gated on XWA_LOADMISSION. */
            if (getenv("XWA_LOADMISSION")) {
                MEM32(0xABD7B4) = 3;   /* 3 (not 1): loading screen needs !=2 for sub_549330, AND flight-init
                                        * sub_5710F0 requires ABD7B4==3 to proceed to real flight (else it
                                        * sends a return-to-base msg and aborts to concourse). 3 satisfies both. */
                MEM32(0x9EAC20) = 1;
                MEM32(0x782DE4) = 0;
                fprintf(stderr, "[TRAINLAUNCH] forced sub_549330 gate (ABD7B4=1,9EAC20=1,timer=0)\n"); fflush(stderr);
            }
            PUSH32(g_esp, 0);                       /* arg1 */
            PUSH32(g_esp, 0x005316B0u);             /* arg0 = loading-screen cb */
            PUSH32(g_esp, 0xDEAD0000u);            /* ret addr */
            sub_00541810();
            g_esp += 8;                             /* cdecl: clean 2 args */
            g_ebx = sb; g_esi = ss; g_edi = sd;
            tl_done = 1;
        }
    }

    /* XWA_LOADMISSION: make the loading screen 0x5316B0 call the real SP mission
     * loader sub_549330 through its OWN handler (calling it directly from this
     * message-pump context deadlocks — sub_549330 sends a local mission-load
     * message and waits for the game loop to process it). The loading screen's
     * gate (sub_5316B0 @0x005317C6/E4) fires sub_549330(0) when 0x9EAC20 != 0 AND
     * the ~2s timer sub_0055ECE0() > 0x782DE4 + 0x7D0 elapses. Our fast transition
     * skips it, so from here (safe memory writes only) force the load flag on and
     * zero the timer base so the gate passes on the loading screen's next tick. */
    {
        static int lm = -1;
        if (lm < 0) lm = getenv("XWA_LOADMISSION") ? 1 : 0;
        if (lm && cb == 0x005316B0) {
            MEM32(0xABD7B4) = 3;      /* 3: non-skirmish loader (!=2) AND flight-init's required mode (==3) */
            MEM32(0x9EAC20) = 1;      /* mission-load pending */
            MEM32(0x782DE4) = 0;      /* timer base 0 -> 2s gate already elapsed */
            { static int _p; if (_p < 1) { fprintf(stderr,
                "[LOADMISSION] forcing loading-screen sub_549330 gate (ABD7B4=1, 9EAC20=1, timer=0); AE2A8A=%u A21449=0x%X\n",
                MEM32(0xAE2A8A), MEM32(0xA21449)); fflush(stderr); _p++; } }
        }
    }

    /* Default: button released, mouse parked off all hot-spots, so no screen sees a
     * spurious hover/click. We only deviate from this to issue one concourse click. */
    MEM32(0x9F6888) = 0;          /* clicks ungated */
    MEM8(0x9F6884) = 0;           /* button up */

    /* SKIRMISH PATH (default): concourse -> Combat Simulator door -> combat-sim
     * menu -> skirmish setup (sub_5438B0). The skirmish screen's init loads the
     * craft/mission data that the training-door shortcut skips. Set XWA_TRAINDOOR
     * to use the old 1-click Training-door path instead. Clicks are timing-flaky
     * vs modals, so each retries a one-frame pulse every ~40 frames. */
    static int train = -1;
    if (train < 0) train = getenv("XWA_TRAINDOOR") ? 1 : 0;

    if (cb == 0x005397D0 && tl_env) {                  /* concourse: settle & let the direct-launch hook fire (no click) */
        MEM32(0x9F4B48) = 0;
        MEM32(0x9F4B4C) = 0;
        MEM32(0x78397C) = 1;                           /* KEEP concourse room (was 0=barracks -> caused the
                                                        * concourse<->barracks ping-pong vs the barracks routing). */
        MEM32(0x9F65ED) = 0;                           /* park mouse off all hot-spots */
        MEM32(0x9F65F1) = 0;
    } else if (cb == 0x005397D0 && train && !getenv("XWA_NONAV")) {            /* concourse -> Training door (sprite origin 536,174) */
        /* Clear the barracks transition gates so the concourse SETTLES (otherwise 9F4B48/9F4B4C==3
         * keeps firing a transition back to the barracks, oscillating concourse<->barracks and the
         * door never gets a stable frame to be clicked). */
        MEM32(0x9F4B48) = 0;
        MEM32(0x9F4B4C) = 0;
        MEM32(0x78397C) = 0;
        /* Mirror the working combat-door offset (origin 35,174 -> click 60,210 = +25,+36). */
        MEM32(0x9F65ED) = (uint32_t)(561 - 5);
        MEM32(0x9F65F1) = (uint32_t)(210 - 5);
        if (fip >= 15 && (fip % 40) == 15) {
            MEM8(0x9F6884) = 1;
            fprintf(stderr, "[FLYDEMO] click Training door (561,210) at fip=%d\n", fip);
            fflush(stderr);
        }
    } else if (cb == 0x005397D0 && !getenv("XWA_NONAV")) {   /* concourse -> Combat Simulator door */
        MEM32(0x9F65ED) = (uint32_t)(60 - 5);          /* (60,210) inside the combatdoor sprite */
        MEM32(0x9F65F1) = (uint32_t)(210 - 5);
        if (fip >= 15 && (fip % 40) == 15) {
            MEM8(0x9F6884) = 1;
            fprintf(stderr, "[FLYDEMO] click Combat door (60,210) at fip=%d\n", fip);
            fflush(stderr);
        }
    } else if (cb == 0x0053B500) {                      /* combat sim -> menu hot-spot -> skirmish */
        /* The combat-sim frame handler switches on 0x782FFC (view sub-state): init=0 (intro),
         * 1=single-select (where the 'single' button -> skirmish setup lives). The state-0->1
         * advance needs a click at y~400-440 the door-entry path makes; force it so the
         * 'single' handler (case 0) runs and our 507,338 click can reach sub_5438B0. */
        if (MEM32(0x782FFC) == 0 && fip >= 8) {
            static int _vp = 0;
            int sk = getenv("XWA_SKIRMISH") ? 1 : 0;   /* XWA_SKIRMISH: offline skirmish (case 3) vs historical (case 1) */
            if (_vp < 2) { fprintf(stderr, "[CSIM] forcing 0x782FFC 0->%d %s\n", sk?4:2, sk?"(OFFLINE SKIRMISH, ABD7B4=2)":"(historical 'single')"); fflush(stderr); _vp++; }
            /* #390: the lobby launch needs ABD7B4 != edi, and edi is hardcoded 2 at L_00544BA3 --
             * so forcing ABD7B4=2 here GUARANTEES the launch check fails. With the pump fixed the
             * game reaches the lobby on its own; let it set the phase itself. XWA_NOPHASE skips the force. */
            if (sk) { MEM32(0x782FFC) = 4;
                if (!getenv("XWA_NOPHASE")) MEM32(0xABD7B4) = 2;
                else { static int _np; if(!_np){_np=1; fprintf(stderr,"[NOPHASE] not forcing ABD7B4 (was %u)\n", MEM32(0xABD7B4u)); fflush(stderr);} } }
            else      MEM32(0x782FFC) = 2;                          /* case 1 = historical campaign-mission */
        }
        /* XWA_PUSHSKIRM (#359): on the ORIGINAL loader path the simulated click never causes the
         * transition (#358/#358b). The real path pushes the skirmish-setup screen at 0x0053B824:
         *     push 0x00543720; push 0x005438B0; call sub_00541810
         * reached when sub_005321F0 returns 0x23. Drive that push directly instead of clicking. */
        if (getenv("XWA_PUSHSKIRM")) {
            static int _ps = 0;
            if (!_ps && fip >= 30) { _ps = 1;
                extern void sub_00541810(void);
                uint32_t sb = g_ebx, ss = g_esi, sd = g_edi;
                fprintf(stderr, "[PUSHSKIRM] pushing skirmish setup (0x5438B0) directly at fip=%d\n", fip); fflush(stderr);
                PUSH32(g_esp, 0x00543720u);
                PUSH32(g_esp, 0x005438B0u);
                PUSH32(g_esp, 0xDEAD0000u);
                sub_00541810();
                g_esp += 8;
                g_ebx = sb; g_esi = ss; g_edi = sd;
            }
        }
        MEM32(0x9F65ED) = (uint32_t)(507 - 5);         /* (507,338) inside rect 384,252..630,424 */
        MEM32(0x9F65F1) = (uint32_t)(338 - 5);
        if (fip >= 10 && (fip % 40) == 10) {
            MEM8(0x9F6884) = 1;
            fprintf(stderr, "[FLYDEMO] click combat-sim menu (507,338) at fip=%d\n", fip);
            fflush(stderr);
        }
    } else if (cb == 0x0055FF30 && !getenv("XWA_NONAV")) {   /* barracks (post create-pilot) */
        /* The autopilot lands here after pilot creation, not the concourse. The barracks transitions to the
         * next screen via the reconstructed jump table at 0x560124 (gated on 78397C-selector + 9F4B48/9F4B4C==3
         * transition phase). Drive it to the concourse (78397C=1) so the combat-door click logic can run. */
        if (fip >= 0) {   /* #372: was fip>=20 -- the barracks handler reads 78397C from its FIRST call (#371), so the force must land immediately */
            static int _bp = 0;
            /* XWA_TRAINDOOR: route barracks -> CONCOURSE (78397C=1) so the Training-door click can fire
             * (concourse -> sub_57E370 training setup -> sub_5316B0 loading -> sub_549330 REAL mission loader
             * -> flight). Default: route -> combat sim (78397C=3) for the skirmish path. */
            uint32_t sel = (train || tl_env) ? 1u : 3u;
            if (_bp < 3) { fprintf(stderr, "[BARRACKS] forcing 78397C=%u (%s); was 78397C=%u 9F4B48=%u 9F4B4C=%u\n",
                sel, (train||tl_env)?"concourse":"combat sim", MEM32(0x78397C), MEM32(0x9F4B48), MEM32(0x9F4B4C)); fflush(stderr); _bp++; }
            MEM32(0x78397C) = sel;        /* 1 -> concourse 0x5397D0; 3 -> combat sim 0x53B500 */
            MEM32(0x9F4B48) = 3;          /* transition phase complete -> fire the switch */
            MEM32(0x9F4B4C) = 3;
        }
    } else if (cb == 0x005438B0) {                       /* skirmish config / lobby screen (REACHED, mission .tie loaded) */
        /* The setup is now reached reliably with AE2A8A=3, the 24-entry mission list, and missions\1b0m1fw.tie
         * loaded. It waits here for the FLY/LAUNCH. With ABD7B4=0 it routes to the campaign cmd-dispatch
         * (sub_571DE0 @L_5445D9, launch=cmd 0x5B). Forcing ABD7B4=2 (skirmish lobby) does NOT stick -- the setup
         * overwrites it each frame (e.g. 0x545419). The launch needs the lobby's own command state machine
         * (sub_571DE0, 1780 lines) to emit 0x5B from the Fly button, or a genuine ready+craft for sub_552160.
         * This is the final step. Left as a no-op for now. */
        (void)fip;
        /* XWA_ADDCRAFT: the launch gate sub_552160 fails because no player craft is
         * configured (craft0 @0x9F5EE8=0). The add-craft handler sub_0054E4B0 sets
         * 0x9F5EE8[slot]=selected-craft(0x9F6084) + 0x9F5EE2[slot]=type on a craft-list
         * click. Populate slot 0 directly with a player craft so the ready-check can
         * pass. Craft id/type via env (default 1); iterate to find valid values. */
        if (getenv("XWA_ADDCRAFT")) {
            /* Fake skirmish craft-slot config (only needed to pass the lobby launch
             * gate sub_552160; NOT needed when we push the loading screen directly).
             * Gated separately (XWA_CRAFTSLOT) because for a CAMPAIGN mission
             * (XWA_SESSMISSION) this fake craft makes 0xB07B5B inconsistent with the
             * mission's real craft region and crashes sub_004C40B0. */
            if (getenv("XWA_CRAFTSLOT")) {
                static int cid = -1, ctype = -1;
                if (cid < 0) { const char* s = getenv("XWA_CRAFTID"); cid = s ? atoi(s) : 1; }
                if (ctype < 0) { const char* s = getenv("XWA_CRAFTTYPE"); ctype = s ? atoi(s) : 1; }
                MEM32(0x9F5EE8) = (uint32_t)cid;
                MEM16(0x9F5EE0) = (uint16_t)ctype;
                MEM16(0x9F5EE2) = 1;
                MEM32(0x9F5EE4) = (uint32_t)cid;
                MEM32(0x9EAC4E) = (uint32_t)cid;
                { static int _p; if (_p < 1) { fprintf(stderr, "[ADDCRAFT] set slot0 craft id=%d type=%d\n", cid, ctype); fflush(stderr); _p++; } }
            }

            /* Once the craft is configured (sub_552160 passes), push the loading
             * screen directly so sub_549330(0) builds the world (the lobby's own
             * launch only calls sub_549330(1), which queues rather than builds).
             * With KEEPCRAFT the craft-def data is wired, so the build shouldn't
             * fault. Fire once after the lobby settles. Preserve callee-saved regs. */
            static int pushed = 0;
            if (!pushed && fip >= 200 && getenv("XWA_PUSHLOAD")) {
                extern void sub_00541810(void);
                extern void sub_0057E8D0(void);
                uint32_t sb = g_ebx, ss = g_esi, sd = g_edi;
                /* Compute 0xB07B5B (per-mission craft-count/size from the craft table
                 * 0x9EB8E0) that the training-setup normally sets but the skirmish
                 * path skips — sub_00415760 divides by it during the .tie parse. */
                fprintf(stderr, "[ADDCRAFT] sub_57E8D0 (compute 0xB07B5B) + push loading screen; B07B5B was 0x%X\n", MEM32(0xB07B5B));
                fflush(stderr);
                PUSH32(g_esp, 0xDEAD0000u);
                sub_0057E8D0();
                fprintf(stderr, "[ADDCRAFT] after sub_57E8D0: B07B5B=0x%X\n", MEM32(0xB07B5B));
                fflush(stderr);
                PUSH32(g_esp, 0);
                PUSH32(g_esp, 0x005316B0u);
                PUSH32(g_esp, 0xDEAD0000u);
                sub_00541810();
                g_esp += 8;
                g_ebx = sb; g_esi = ss; g_edi = sd;
                pushed = 1;
            }
        }
    } else {
        MEM32(0x9F65ED) = (uint32_t)(5 - 5);          /* park mouse top-left, off everything */
        MEM32(0x9F65F1) = (uint32_t)(5 - 5);
    }
    (void)clicked;

    /* XWA_DRIVEREND: drive the real per-viewport 3D scene render each frame while on the flight
     * screen (flight-init 0x5710F0 or flight-frame 0x49E600). The dispatcher never transitions to
     * the flight-frame cb, so the scene render never ticks on the LIVE flight surface — but the
     * render path itself works (builds a real visible list, objcount=2). xwa_drive_render() runs
     * sub_00511A90 (alloc rbuf/register view) + sub_004340D0(0) (per-viewport render) — the real
     * game fns with correct args. Test whether ticking it here draws pixels. */
    /* XWA_CAMSEED: the flight render loop RUNS (sub_0049E600->sub_004F2070) but outputs 0 pixels
     * because the camera view matrix 0x8D93xx is ZERO -> projection divides by 0 (DIV0 x8) -> vertices
     * collapse. sub_004949B0 copies the matrix from source 0x693774..0x6937A8 each frame. Seed that
     * SOURCE non-zero so the copy propagates a non-zero matrix -> no DIV0. DIAGNOSTIC: if ANY pixels
     * appear (even distorted), the camera matrix is confirmed as the sole blocker + seeding works. */
    /* XWA_SNAP: dump the same field set tools/snap_flight.py reads out of the REAL game,
     * so the recomp's flight state can be diffed against ground truth line-for-line instead
     * of guessed at. One shot, on the first 3D-flight frame. */
    if (getenv("XWA_SNAP")) {
        /* The screen-callback slot the driver reads (0xA1C8D5) holds the flight INIT cb;
         * the 3D FRAME cb 0x0049E600 lives in the neighbouring slot (0xA1C8D9) -- see #167.
         * Accept either, else the snapshot never fires even though the frame loop is running. */
        /* Don't trigger on the frame-cb slot alone: 0x0049E600 is already parked in the
         * callback table long before flight, so that fires during boot and dumps all zeros.
         * Wait until flight-init has been the active screen AND the world build has actually
         * produced an FG table, then give it N more frames (XWA_SNAP=N, default 60). */
        static int _snapped = 0, _fltframes = -1;
        if (!_snapped) {
            if (cb == 0x005710F0 || cb == 0x0049E600) { if (_fltframes < 0) _fltframes = 0; _fltframes++; }
            int want = atoi(getenv("XWA_SNAP")); if (want <= 0) want = 60;
            if (_fltframes >= want && MEM32(0x7B33C4) != 0) {
                _snapped = 1; xwa_snap_flight(cb, depth);
            }
        }
    }

    if (getenv("XWA_CAMSEED") && (cb == 0x005710F0 || cb == 0x0049E600)) {
        static int _cs; if (_cs < 3) { fprintf(stderr, "[CAMSEED] seeding IDENTITY camera matrix source (cb=0x%X)\n", cb); fflush(stderr); _cs++; }
        /* zero the whole rotation source region, then set the identity diagonal + the 0x8D6BB0 gate.
         * src->dest map (sub_004949B0): 79C->8D93CC, 77C->8D93E4, 794->8D93C0 (diagonal candidates);
         * 798->8D6BB0 (gate, must be >0). All others -> off-diagonal = 0. Scale 1.0 = 0x8000 (>>15). */
        for (uint32_t a = 0x693774u; a <= 0x6937A8u; a += 4) MEM32(a) = 0;
        MEM32(0x693794u) = 0x8000u;  /* -> 0x8D93C0 (diag) */
        MEM32(0x69377Cu) = 0x8000u;  /* -> 0x8D93E4 (diag) */
        MEM32(0x69379Cu) = 0x8000u;  /* -> 0x8D93CC (diag) */
        MEM32(0x693798u) = 0x8000u;  /* -> 0x8D6BB0 (gate >0) */
    }

    if (getenv("XWA_DRIVEREND") && (cb == 0x005710F0 || cb == 0x0049E600)) {
        /* Drive the PROVEN render entry sub_004F2070 (RENDPROBE confirmed it builds a real visible
         * list: objcount=2, 1 solid queued) directly on the LIVE flight surface each frame — the
         * real per-frame loop never ticks it (screen never transitions to the 0x49E600 frame cb). */
        extern void sub_004F2070(void);
        static int _dr; if (_dr < 3) { fprintf(stderr, "[DRIVEREND] ticking sub_004F2070 on flight screen cb=0x%X\n", cb); fflush(stderr); _dr++; }
        #define esp g_esp
        RECOMP_CALL(sub_004F2070);
        #undef esp
    }
}

/* sub_00559B50: Frontend display/input callback.
 * Dead code after ret in sub_00559A90 (missed by code generator).
 * Called frequently via dispatch mechanism (registered by sub_00541890).
 * Shows UI, waits for Enter/Escape, returns 0 or 1. */
static void manual_sub_00559B50(void) {
    extern void sub_0055BA70(void);
    extern void sub_0055B590(void);
    extern void sub_00531D70(void);
    extern void sub_0053F830(void);
    extern void sub_00535470(void);
    extern void sub_00532350(void);
    extern void sub_0053F8D0(void);
    extern void sub_00558C90(void);
    extern void sub_0055CB50(void);
    extern void sub_005575A0(void);
    extern void sub_00555CF0(void);
    extern void sub_00555FE0(void);
    extern void sub_0055B570(void);
    extern void sub_0055B5B0(void);
    extern void sub_00532080(void);
    #define esp g_esp
    /* 0x559B50: entry */
    g_eax = MEM32(esp + 0x4);
    esp = esp - 0x10u;
    /* test eax, eax */
    PUSH32(esp, g_esi);
    { static int _cb; if (_cb < 10) { fprintf(stderr, "[559B50] call #%d, arg(eax)=%u\n", _cb, g_eax); _cb++; } }
    /* Headless test harness (opt-in via XWA_AUTOPILOT env var): after a delay on
     * the Create Pilot screen, queue a pilot name + Enter into the game's keyboard
     * ring buffer the same way the game's own WM_CHAR handler (sub_0053E4xx) does:
     *   write_idx = 0x9F6F7F, read_idx = 0x9F6F83, buffer base = 0x9F6B7F.
     * The name-entry widget consumes A/U/T/O into 0x783668 and the create-pilot
     * logic commits on the trailing CR. Reproduces the post-creation concourse
     * transition without an interactive user. */
    if (getenv("XWA_AUTOPILOT")) {
        static DWORD _aa_start = 0;
        static int _aa_done = 0;
        if (!_aa_start) _aa_start = GetTickCount();
        if (!_aa_done && GetTickCount() - _aa_start > 3000) {
            /* Type an EXISTING pilot's callsign so the game LOADS that .plt (read-only)
             * instead of creating a fresh pilot every run — faster iteration, no
             * AUTOn.plt clutter, and real campaign progress. Override with XWA_PILOT.
             * Falls back to creating "AUTO" if the named pilot doesn't exist. */
            const char* nm = getenv("XWA_PILOT");
            if (!nm || !*nm) nm = "Test";  /* throwaway Test0.plt; XWA re-saves on load */
            for (const char* p = nm; *p; p++) {
                uint32_t w = MEM32(0x9F6F7F);
                MEM8(0x9F6B7F + w) = (uint8_t)(unsigned char)*p;
                MEM32(0x9F6F7F) = w + 1;
            }
            { uint32_t w = MEM32(0x9F6F7F); MEM8(0x9F6B7F + w) = (uint8_t)'\r'; MEM32(0x9F6F7F) = w + 1; }
            _aa_done = 1;
            fprintf(stderr, "[AUTO] Injected pilot callsign '%s'+Enter into kbd ring (write_idx=%u)\n",
                    nm, MEM32(0x9F6F7F)); fflush(stderr);
        }
    }
    if (CMP_NE(g_eax, 0)) goto L_BB6;
    /* 0x559B5C: eax==0 path */
    { static int _p0; if (_p0 < 3) { fprintf(stderr, "[559B50] eax==0 path, calling sub_55BA70/55B590/531D70/53F830...\n"); _p0++; } }
    PUSH32(esp, 0x123u);
    PUSH32(esp, 0x1A1u);
    RECOMP_CALL(sub_0055BA70);
    esp = esp + 8;
    RECOMP_CALL(sub_0055B590);
    PUSH32(esp, 0x0060377Cu);
    PUSH32(esp, 0x0060375Cu);
    RECOMP_CALL(sub_00531D70);
    esp = esp + 8;
    { static int _f8; if (_f8 < 3) { fprintf(stderr, "[559B50] sub_531D70 ret=%u, calling sub_53F830 (9F702A=%u 9F702E=0x%X)\n", g_eax, MEM32(0x9F702A), MEM32(0x9F702E)); _f8++; } }
    RECOMP_CALL(sub_0053F830);
    { static int _f9; if (_f9 < 3) { fprintf(stderr, "[559B50] sub_53F830 ret=%u\n", g_eax); _f9++; } }
    PUSH32(esp, 0);
    PUSH32(esp, 0);
    PUSH32(esp, 0x0060377Cu);
    RECOMP_CALL(sub_00535470);
    esp = esp + 0xCu;
    { static int _s5; if (_s5 < 3) {
        uint32_t lpSurf = MEM32(0x9F60D4);
        fprintf(stderr, "[559B50] after sub_535470: lpSurface=0x%X bpp_9F700A=%u pitch_9F6FFA=%u", lpSurf, MEM32(0x9F700A), MEM32(0x9F6FFA));
        if (lpSurf) {
            uint8_t* p = (uint8_t*)(uintptr_t)lpSurf;
            int nz = 0;
            for (uint32_t i = 0; i < 640*480*2; i++) { if (p[i]) { nz = 1; fprintf(stderr, " first_nz=%u(0x%02X)", i, p[i]); break; } }
            if (!nz) fprintf(stderr, " ALL ZERO");
        }
        fprintf(stderr, "\n"); _s5++;
    } }
    PUSH32(esp, 0);
    PUSH32(esp, 0);
    PUSH32(esp, 0x0060374Cu);
    RECOMP_CALL(sub_00532350);
    esp = esp + 0xCu;
    { static int _s3; if (_s3 < 3) {
        uint32_t lpSurf = MEM32(0x9F60D4);
        fprintf(stderr, "[559B50] after sub_532350: lpSurface=0x%X", lpSurf);
        if (lpSurf) {
            uint8_t* p = (uint8_t*)(uintptr_t)lpSurf;
            int nz = 0;
            for (uint32_t i = 0; i < 640*480*2; i++) { if (p[i]) { nz = 1; fprintf(stderr, " first_nz=%u(0x%02X)", i, p[i]); break; } }
            if (!nz) fprintf(stderr, " ALL ZERO");
        }
        fprintf(stderr, "\n"); _s3++;
    } }
    PUSH32(esp, 1);
    RECOMP_CALL(sub_0053F8D0);
    esp = esp + 4;
L_BB6:
    /* 0x559BB6 */
    PUSH32(esp, 0xF5u);
    PUSH32(esp, 0x1BDu);
    PUSH32(esp, 0xE1u);
    g_eax = esp + 0x10;
    PUSH32(esp, 0xF5u);
    PUSH32(esp, g_eax);
    RECOMP_CALL(sub_00558C90);
    esp = esp + 0x14u;
    PUSH32(esp, 0xFFFFu);
    g_ecx = esp + 0x8;
    PUSH32(esp, g_ecx);
    PUSH32(esp, 0x254u);
    RECOMP_CALL(sub_0055CB50);
    esp = esp + 4;
    { static int _td; if (_td < 5) {
        uint32_t font15 = MEM32(0xF * 4 + 0x9FBC69);
        uint32_t lpSurf = MEM32(0x9F60D4);
        fprintf(stderr, "[TEXT] sub_5575A0: str=0x%08X('%s') fontIdx=0xF fontPtr=0x%08X lpSurf=0x%X\n",
                g_eax, g_eax ? (const char*)(uintptr_t)g_eax : "(null)",
                font15, lpSurf);
        fprintf(stderr, "[TEXT]   clipRect: L=%d T=%d R=%d B=%d\n",
                (int32_t)MEM32(0x9F708A), (int32_t)MEM32(0x9F7092),
                (int32_t)MEM32(0x9F708E), (int32_t)MEM32(0x9F7096));
        fflush(stderr);
        _td++;
    } }
    PUSH32(esp, g_eax);
    PUSH32(esp, 0xFu);
    RECOMP_CALL(sub_005575A0);
    esp = esp + 0x10u;
    PUSH32(esp, 0x109u);
    PUSH32(esp, 0x1B8u);
    PUSH32(esp, 0xF5u);
    g_edx = esp + 0x10;
    PUSH32(esp, 0xFAu);
    PUSH32(esp, g_edx);
    RECOMP_CALL(sub_00558C90);
    esp = esp + 0x14u;
    PUSH32(esp, 0x00603748u);
    PUSH32(esp, 0xCu);
    PUSH32(esp, 0);
    PUSH32(esp, 0xDu);
    g_eax = esp + 0x14;
    PUSH32(esp, 0x00783668u);
    PUSH32(esp, g_eax);
    RECOMP_CALL(sub_00555CF0);
    esp = esp + 0x18u;
    PUSH32(esp, 0x127u);
    PUSH32(esp, 0x1B8u);
    PUSH32(esp, 0x113u);
    g_ecx = esp + 0x10;
    PUSH32(esp, 0xFAu);
    PUSH32(esp, g_ecx);
    g_esi = g_eax;
    RECOMP_CALL(sub_00558C90);
    esp = esp + 0x14u;
    PUSH32(esp, 0x00603140u);
    PUSH32(esp, 0x14u);
    PUSH32(esp, 0xFFFFu);
    PUSH32(esp, 0xFu);
    PUSH32(esp, 0x255u);
    RECOMP_CALL(sub_0055CB50);
    esp = esp + 4;
    PUSH32(esp, g_eax);
    g_edx = esp + 0x18;
    PUSH32(esp, g_edx);
    RECOMP_CALL(sub_00555FE0);
    esp = esp + 0x18u;
    g_esi = g_esi | g_eax;
    { static int _nc; if (_nc < 20) {
        fprintf(stderr, "[CREATE] frame: esi=%u charR=%u charW=%u name='%.12s' (0x%02X)\n",
            g_esi, MEM32(0x9F6F83), MEM32(0x9F6F7F),
            (const char*)(uintptr_t)0x783668, MEM8(0x783668));
        fflush(stderr); _nc++;
    } }
    RECOMP_CALL(sub_0055B570);
    if (CMP_NE(LO8(g_eax), 0xDu)) goto L_C9A;
    RECOMP_CALL(sub_0055B5B0);
    g_esi = 1;
    goto L_CA8;
L_C9A:
    RECOMP_CALL(sub_0055B570);
    if (CMP_NE(LO8(g_eax), 0x1Bu)) goto L_CA8;
    RECOMP_CALL(sub_0055B5B0);
L_CA8:
    if (TEST_Z(g_esi, g_esi)) goto L_CCC;
    SET_LO8(g_eax, MEM8(0x783668));
    if (TEST_Z(LO8(g_eax), LO8(g_eax))) goto L_CCC;
    PUSH32(esp, 0x0060377Cu);
    RECOMP_CALL(sub_00532080);
    esp = esp + 4;
    g_eax = 1;
    goto L_exit;
L_CCC:
    g_eax = 0;
L_exit:
    g_esi = POP32_VAL(esp);
    esp = esp + 0x10u;
    esp += 4;
    #undef esp
}

/* Frontend menu display callback (second menu screen).
 * Called from sub_005593C0 via sub_00541890 dispatch loop.
 * Body at L_005595AF through L_00559612 in recomp_0003.c (dead code).
 * Prologue (0x5595A0-0x5595AE) is SafeDisc-encrypted; reconstructed
 * from epilogue: pop edi, pop esi, add esp 0x10, ret.
 * The body renders the menu and always returns 0 (keep polling).
 * Auto-advance: returns 1 after 2s to exit the dispatch loop. */
static void manual_sub_005595A0(void) {
    extern void sub_0055B590(void);
    extern void sub_0055BA70(void);
    extern void sub_0053F830(void);
    extern void sub_00534A60(void);
    extern void sub_0053F8D0(void);
    extern void sub_005580A0(void);

    #define esp g_esp
    /* Prologue: sub esp 0x10; push esi; push edi */
    esp = esp - 0x10u;
    PUSH32(esp, g_esi);
    PUSH32(esp, g_edi);

    /* Auto-advance: after 15 seconds, return 1 to exit dispatch loop */
    {
        static DWORD _auto_start = 0;
        if (!_auto_start) _auto_start = GetTickCount();
        if (GetTickCount() - _auto_start > 15000) {
            static int _auto_log = 0;
            if (!_auto_log) { fprintf(stderr, "[AUTO] Auto-advancing past second frontend menu\n"); fflush(stderr); _auto_log = 1; }
            g_eax = 1;
            goto L_exit;
        }
    }

    /* Display body from L_005595AF through L_0055960B */
    RECOMP_CALL(sub_0055B590);
    SET_LO8(g_eax, MEM8(0x783450));
    if (TEST_NZ(LO8(g_eax), LO8(g_eax))) goto L_D2;
    SET_LO8(g_eax, MEM8(0x7835E0));
    if (TEST_Z(LO8(g_eax), LO8(g_eax))) goto L_D2;
    PUSH32(esp, 0xECu);
    PUSH32(esp, 0x20Eu);
    goto L_D9;
L_D2:
    PUSH32(esp, 0xECu);
    PUSH32(esp, 0x5Au);
L_D9:
    RECOMP_CALL(sub_0055BA70);
    esp = esp + 8;
    RECOMP_CALL(sub_0053F830);
    PUSH32(esp, 0);
    PUSH32(esp, 0);
    PUSH32(esp, 0x00602D1Cu);
    RECOMP_CALL(sub_00534A60);
    esp = esp + 0xCu;
    PUSH32(esp, 1);
    RECOMP_CALL(sub_0053F8D0);
    esp = esp + 4;
    PUSH32(esp, 0x14u);
    RECOMP_CALL(sub_005580A0);
    esp = esp + 4;
    g_eax = 0;

L_exit:
    g_edi = POP32_VAL(esp);
    g_esi = POP32_VAL(esp);
    esp = esp + 0x10u;
    esp += 4;
    #undef esp
}

/* sub_005397D0: Main game tick function.
 * Handles input, game state updates, rendering for one frame.
 * TODO: Properly implement this large function (~300 bytes).
 * For now, stub it to return 0 (skip game logic), but present
 * a frame so the D3D11 window stays visible. */
/* sub_005397D0 is now a proper generated function in recomp_0003.c.
 * It was previously stubbed because the code generator treated it as dead code
 * within sub_00539740 (it follows a ret at 0x5397C3). The function has been
 * split out with its missing prologue (0x5397D0-0x5397E0) restored. */

/* Stub for sub_00556B20 (font/resource loader) - returns 1 (success).
 * The real function tries to load .abp font files (which don't exist),
 * falls back to GDI rendering on a DD surface, and fails during the
 * complex pixel readback pipeline. Stubbing lets us get past DD init.
 * cdecl, 1 arg (caller cleans), returns 1 in eax. */
static void stub_font_loader(void) {
    uint32_t fontIdx = MEM32(g_esp + 4);
    fprintf(stderr, "[STUB] sub_00556B20(fontIdx=%u) -> returning 1 (success)\n", fontIdx);
    g_eax = 1;
    g_esp += 4;  /* pop return address */
}

/* Tracing helper: log when specific functions are entered */
static void trace_winmain_entry(void) {
    fprintf(stderr, "[TRACE] WinMain (sub_0050A4A0) entered\n");
    fflush(stderr);
    /* Tail to real function */
    extern void sub_0050A4A0(void);
    sub_0050A4A0();
}

/* Stub for calls through uninitialized function pointers (NULL/0).
 * Returns 0 in eax, pops return address from simulated stack. */
static void stub_null_funcptr(void) {
    g_eax = 0;
    g_esp += 4;  /* pop return address */
}

/* _initstdio (0x59CC80) - CRT$XI initializer for FILE stream table.
 * SafeDisc-encrypted in original binary; reimplemented from VC6 CRT source.
 * The generated code for this function body exists as unreachable labels
 * L_0059CC8A-L_0059CD3A inside sub_0059CC10, but the entry prologue at
 * 0x59CC80-0x59CC89 was encrypted and never lifted.
 *
 * Initializes _nstream (0xB0F960) and _piob (0xB0E948) so that CRT fopen works.
 */
static void manual_initstdio(void) {
    extern void sub_0059C9B0(void);  /* _calloc_crt */
    extern void sub_0059CF10(void);  /* _amsg_exit */

    /* Use 'esp' as a local alias that the RECOMP_CALL macro expects.
     * RECOMP_CALL expands to PUSH32(esp, ...) so esp must resolve to g_esp.
     * Define esp as a macro only within this function scope. */
    #define esp g_esp

    /* This is a void(*)(void) callback from __initterm; pop return address */
    esp += 4;

    /* Read _nstream; if 0, default to 0x200; if < 0x14, minimum 0x14 */
    uint32_t nstream = MEM32(0xB0F960);
    if (nstream == 0) {
        nstream = 0x200;  /* default: 512 streams */
    } else if ((int32_t)nstream < 0x14) {
        nstream = 0x14;   /* minimum: 20 streams */
    }
    MEM32(0xB0F960) = nstream;

    /* calloc(_nstream, 4) via _calloc_crt */
    PUSH32(esp, 4);           /* element size */
    PUSH32(esp, nstream);     /* count */
    RECOMP_CALL(sub_0059C9B0);
    esp += 8;
    uint32_t piob = g_eax;
    MEM32(0xB0E948) = piob;

    /* If allocation failed, retry with minimum 20 */
    if (piob == 0) {
        MEM32(0xB0F960) = 0x14;
        PUSH32(esp, 4);
        PUSH32(esp, 0x14u);
        RECOMP_CALL(sub_0059C9B0);
        esp += 8;
        piob = g_eax;
        MEM32(0xB0E948) = piob;

        if (piob == 0) {
            /* Fatal: _amsg_exit(0x1a) */
            PUSH32(esp, 0x1Au);
            RECOMP_CALL(sub_0059CF10);
            esp += 4;
            piob = MEM32(0xB0E948);
        }
    }

    /* Initialize _piob entries pointing to static FILE structs at 0x60AF10.
     * Each FILE struct is 0x20 bytes. Range: 0x60AF10 to 0x60B190. */
    {
        uint32_t offset = 0;
        uint32_t file_addr = 0x60AF10u;
        while (file_addr < 0x60B190u) {
            MEM32(piob + offset) = file_addr;
            file_addr += 0x20;
            offset += 4;
            piob = MEM32(0xB0E948);  /* re-read in case of aliasing */
        }
    }

    /* Initialize _file fields for pre-allocated IOB entries (stdin/stdout/stderr).
     * For each index, look up the OS handle from __pioinfo table.
     * If handle is -1 or 0, set _file = -1 in the FILE struct. */
    {
        uint32_t idx = 0;
        uint32_t edx = 0x60AF20u;
        while (edx < 0x60AF80u) {
            uint32_t bucket = (uint32_t)((int32_t)idx >> 5);
            uint32_t slot = idx & 0x1F;
            uint32_t pioinfo_ptr = MEM32(bucket * 4 + 0xB0E840);
            uint32_t handle = MEM32(pioinfo_ptr + (slot + slot * 8) * 4);
            if (handle == 0xFFFFFFFF || handle == 0) {
                MEM32(edx) = 0xFFFFFFFF;
            }
            edx += 0x20;
            idx += 1;
        }
    }

    #undef esp

    fprintf(stderr, "[MANUAL] _initstdio: _nstream=%u, _piob=0x%08X\n",
            MEM32(0xB0F960), MEM32(0xB0E948));
    fflush(stderr);
}

/* Stub for DirectInput internal dispatch table entries (sub_0049A490).
 * These are COM method implementations stored as function pointers at
 * 0x6937D4-0x693838. They are mid-function labels within sub_0049A490
 * that the dispatch table doesn't know about. All return DD_OK (0)
 * and pop the return address (stdcall with 'this' ptr + variable args).
 * Most take 1-3 args; we pop conservatively and let the caller handle
 * the rest via the known ecx-based dispatch pattern. */
static void stub_dinput_nop(void) {
    g_eax = 0;
    g_esp += 4;  /* pop return address */
}

/* ============================================================
 * WndProc Bridge
 *
 * Windows calls the WndProc at the address stored in the WNDCLASS
 * structure. The game stores 0x0053E650 which is a mid-function
 * label inside sub_0053E340 (the actual WndProc). Since our .text
 * pages are data-only (not executable), we need a real native
 * stdcall function that bridges to the recompiled WndProc.
 *
 * We write our bridge function's address into the WNDCLASS at the
 * point where the game stores the WndProc pointer. But actually,
 * the better approach: override the address 0x0053E650 in the manual
 * override table, AND write a real native WndProc bridge.
 *
 * The game's WndProc (sub_0053E340) is stdcall with 4 args:
 *   LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM)
 * It pops ebx, ebp, esi, edi, processes the message, and returns
 * via ret 0x10 (pops 4 args + 16 bytes from stack).
 * ============================================================ */
extern void sub_0053E340(void);

static LRESULT CALLBACK native_wndproc_bridge(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static uint32_t wndproc_count = 0;
    wndproc_count++;
    /* Always log input messages; log others only for first 30 or every 5000 */
    int is_input = (msg == 0x0200 || msg == 0x0201 || msg == 0x0202 ||
                    msg == 0x0204 || msg == 0x0205 || msg == 0x0100 ||
                    msg == 0x0101 || msg == 0x0102);
    if (is_input || wndproc_count <= 30 || (wndproc_count % 5000 == 0)) {
        fprintf(stderr, "[WND] #%u: msg=0x%04X wP=0x%X lP=0x%X\n",
                wndproc_count, msg, (uint32_t)wParam, (uint32_t)lParam);
        fflush(stderr);
    }


    /* Force game to stay active even when window loses focus */
    if (msg == 0x001C /* WM_ACTIVATEAPP */ && wParam == 0) {
        fprintf(stderr, "[WND] WM_ACTIVATEAPP deactivate intercepted, forcing active\n");
        fflush(stderr);
        wParam = 1;  /* Force "activated" so game doesn't pause */
    }

    /* Save callee-saved globals - WndProc is re-entrant from native Windows
     * callbacks and must not corrupt the caller's register state */
    uint32_t saved_esp = g_esp;
    uint32_t saved_ebx = g_ebx;
    uint32_t saved_esi = g_esi;
    uint32_t saved_edi = g_edi;

    /* Push args right-to-left on simulated stack (stdcall convention) */
    PUSH32(g_esp, (uint32_t)lParam);
    PUSH32(g_esp, (uint32_t)wParam);
    PUSH32(g_esp, (uint32_t)msg);
    PUSH32(g_esp, (uint32_t)(uintptr_t)hwnd);
    PUSH32(g_esp, 0xDEAD0000u);  /* return address (will be consumed by ret 0x10) */

    g_call_depth++;
    if (g_call_depth > g_call_depth_max) g_call_depth_max = g_call_depth;
    sub_0053E340();
    g_call_depth--;

    /* Diagnostic: after mouse messages, check stored globals */
    if ((msg == 0x0200 || msg == 0x0201 || msg == 0x0202) && (wndproc_count % 10 == 0)) {
        fprintf(stderr, "[INPUT] mouseXY=(%u,%u) btn=%u/%u rel=%u/%u gate=%u\n",
                MEM32(0x9F65ED), MEM32(0x9F65F1),
                MEM8(0x9F6882), MEM8(0x9F6883),
                MEM8(0x9F6884), MEM8(0x9F6885),
                MEM8(0x9F6888));
        fflush(stderr);
    }

    /* Restore callee-saved globals */
    g_esp = saved_esp;
    g_ebx = saved_ebx;
    g_esi = saved_esi;
    g_edi = saved_edi;

    return (LRESULT)g_eax;
}

/* Stub that stores the native WndProc bridge address instead of 0x0053E650.
 * When the game stores the WndProc address into the WNDCLASS, it uses the
 * instruction at 0x0053EB47: mov [esp+0x18], 0x53E650. We intercept the
 * ICALL/address to write our bridge address instead.
 *
 * BUT: since the address 0x0053E650 is a constant embedded in the code,
 * we patch the .text data at 0x0053E650 to contain a thunk. Actually,
 * the simplest approach: patch the memory at the location where the game
 * stores this constant in the WNDCLASS structure. That happens at the
 * instruction at 0x0053EB47. We'll patch the constant there after .text
 * is loaded. OR: we can just patch the .text word at the operand location.
 *
 * Even simpler: add 0x0053E650 as a manual override that acts as the
 * WndProc entry point. When called via ITAIL/ICALL it would work. But
 * Windows calls it as a real function pointer, not through our dispatch.
 *
 * The real fix: patch the DWORD at 0x0053E648 (the mov operand for the
 * instruction at 0x0053EB47) OR write the native bridge address into
 * the WNDCLASS after the game sets it up. BUT the WNDCLASS is on the
 * stack, allocated dynamically.
 *
 * Cleanest approach: patch the .text data at the instruction that stores
 * the WndProc address. The instruction at 0x0053EB47 is:
 *   C7 44 24 18 50 E6 53 00  (mov [esp+0x18], 0x0053E650)
 * The immediate operand 0x0053E650 is at file/VA offset 0x0053EB4B.
 * We overwrite it with our native bridge address. */

/* shim_0052A198: Mid-function ITAIL target inside sub_00529ECD.
 * Tail-called from sub_00529950. At entry, the stack frame is already
 * set up: sub esp,0x108 + push ebx,ebp,esi,edi.
 * This code builds a sort index for CBM entries, then tears down the
 * stack frame and returns 1 (success). */
static void shim_0052A198(void) {
    extern void sub_0059CF70(void);
    extern void sub_0052ADD0(void);
    #define esp g_esp
    uint32_t eax, ecx, edx, esi, edi, ebx, ebp;
    (void)ebp;

    /* Retrieve ebx from saved position on stack.
     * Stack layout: [locals 0x108][ebx][ebp][esi][edi] <- esp
     * So ebx is at esp + 0x10 + 0x108 - 4... actually ebx was pushed first,
     * then ebp, esi, edi. So: esp+0x0C = ebx value (edi@esp, esi@esp+4, ebp@esp+8, ebx@esp+0xC).
     * But the code uses ebx for comparison without setting it first, so it must
     * already be in g_ebx from the caller. */
    ebx = g_ebx;

    eax = MEM32(0xABD7DC);
    ecx = MEM32(0xABD22C);
    PUSH32(esp, 0x0052A210u);
    PUSH32(esp, 0x128u);
    PUSH32(esp, eax);
    PUSH32(esp, ecx);
    RECOMP_CALL(sub_0059CF70);
    edx = MEM32(esp + 0x24);
    esp = esp + 0x10u;
    PUSH32(esp, edx);
    RECOMP_CALL(sub_0052ADD0);
    edx = MEM32(0xABD7DC);
    eax = 0;
    esp = esp + 4;
    /* cmp edx, ebx */
    ecx = 0x100u;
    edi = 0x00ABD280u;
    MEMSET32((void*)ADDR(edi), eax, ecx);
    edi += ecx * 4; ecx = 0;
    if (CMP_BE(edx, ebx)) goto L_done;

    ecx = MEM32(0xABD22C);
    ecx = ecx + 0x100u;
L_loop:
    esi = MEM32(ecx);
    MEM32(esi * 4 + 0xABD280) = eax;
    eax = eax + 1;
    ecx = ecx + 0x128u;
    /* cmp eax, edx */
    if (CMP_B(eax, edx)) goto L_loop;

L_done:
    edi = POP32_VAL(esp);
    esi = POP32_VAL(esp);
    ebp = POP32_VAL(esp);
    eax = 1;
    ebx = POP32_VAL(esp);
    esp = esp + 0x108u;
    esp += 4; /* pop return address */

    g_eax = eax;
    g_ebx = ebx;
    g_esi = esi;
    g_edi = edi;
    #undef esp
}

/* =================================================================
 * FILE* registry: the game sometimes uses an uninitialized / misread
 * (non-NULL garbage) value as a FILE*, which crashes host ucrtbase when
 * passed to fread/fseek/fclose/etc. Track the FILE*s our fopen wrappers
 * actually returned; the CRT wrappers validate against this set and skip
 * the op (returning an error code) when given a pointer we never handed out.
 * ================================================================= */
#define RECOMP_MAX_FP 256
static FILE* g_recomp_fps[RECOMP_MAX_FP];
void recomp_fp_register(FILE* fp) { if (!fp) return; for (int i=0;i<RECOMP_MAX_FP;i++) if (!g_recomp_fps[i]) { g_recomp_fps[i]=fp; return; } }
void recomp_fp_unregister(FILE* fp) { for (int i=0;i<RECOMP_MAX_FP;i++) if (g_recomp_fps[i]==fp) { g_recomp_fps[i]=NULL; return; } }
int  recomp_fp_valid(FILE* fp) { if (!fp) return 0; for (int i=0;i<RECOMP_MAX_FP;i++) if (g_recomp_fps[i]==fp) return 1; return 0; }

/* Manual override table */
/* =================================================================
 * Native file I/O replacements.
 * The game's recompiled CRT has corrupted internal state (_nstream gets
 * zeroed, FILE structs break). Replace the VFS-level file wrappers with
 * native host CRT calls. FILE* is treated as opaque by all callers.
 * ================================================================= */

/* sub_0052AD30: VFS fopen wrapper.
 * Args: esp+4 = filename (char*), esp+8 = mode (char*).
 * Returns: FILE* in eax (0 on failure). cdecl.
 * Forwards to the game's own CRT fopen (sub_0059ADD0) so the returned
 * FILE* is compatible with the game's CRT fgets/fread/fclose. */
extern void sub_0059ADD0(void);
static void native_fopen_0052AD30(void) {
    /* VFS fopen wrapper. Returns host CRT FILE*.
     * All VFS wrappers and game CRT file functions also use host CRT. */
    #define esp g_esp
    uint32_t fn_addr = MEM32(esp + 4);
    uint32_t mode_addr = MEM32(esp + 8);
    const char *filename = (const char*)ADDR(fn_addr);
    const char *mode = (const char*)ADDR(mode_addr);
    FILE *fp = fopen(filename, mode);
    g_eax = (uint32_t)(uintptr_t)fp;
    if (fp) {
        MEM16(0x7829C8) = (uint16_t)(MEM16(0x7829C8) + 1);
        recomp_fp_register(fp);
    }
    esp += 4; /* pop return address */
    #undef esp
}

static recomp_dispatch_entry_t g_manual_overrides[] = {
    { 0x00000000, stub_null_funcptr },  /* NULL function pointer calls */
    { 0x005A0750, stub_safedisc_nop },
    { 0x005A0EC0, stub_safedisc_nop },
    { 0x005A1100, stub_safedisc_nop },
    { 0x005A13B0, stub_safedisc_nop },
    /* SafeDisc-encrypted CRT functions called during __initterm.
     * These are void(*)(void) callbacks; safe to stub as no-ops. */
    { 0x0059A5F0, stub_safedisc_nop },
    { 0x0059C150, stub_safedisc_nop },
    { 0x0059CC80, manual_initstdio },
    /* CRT atexit callback (called during exit cleanup via _initterm).
     * Address 0x59CD40 is in .text but not in dispatch table. */
    { 0x0059CD40, stub_safedisc_nop },
    /* DirectInput internal dispatch table entries (sub_0049A490).
     * These are mid-function label addresses stored in the DI vtable
     * at 0x6937D4-0x693838 for joystick/keyboard device handling. */
    { 0x0049A630, stub_dinput_nop },
    { 0x0049A670, stub_dinput_nop },
    { 0x0049A6B0, stub_dinput_nop },
    { 0x0049A6F0, stub_dinput_nop },
    { 0x0049A730, stub_dinput_nop },
    { 0x0049A770, stub_dinput_nop },
    { 0x0049A7C0, stub_dinput_nop },
    { 0x0049A7D0, stub_dinput_nop },
    { 0x0049A800, stub_dinput_nop },
    { 0x0049A830, stub_dinput_nop },
    { 0x0049A870, stub_dinput_nop },
    { 0x0049A880, stub_dinput_nop },
    { 0x0049A8A0, stub_dinput_nop },
    { 0x0049A8B0, stub_dinput_nop },
    { 0x0049A8D0, stub_dinput_nop },
    { 0x0049A8F0, stub_dinput_nop },
    { 0x0049A910, stub_dinput_nop },
    { 0x0049A920, stub_dinput_nop },
    { 0x0049A930, stub_dinput_nop },
    { 0x0049A950, stub_dinput_nop },
    { 0x0049A9A0, stub_dinput_nop },
    { 0x0049A9C0, stub_dinput_nop },
    { 0x0049A9E0, stub_dinput_nop },
    { 0x0049AA00, stub_dinput_nop },
    { 0x0049AA20, stub_dinput_nop },
    { 0x0049AA30, stub_dinput_nop },
    /* Mid-function ITAIL targets in sub_005241B0 (DirectInput init).
     * These are cleanup/exit paths jumped to on error conditions.
     * The function has a large stack frame; these labels restore it. */
    { 0x005252BC, stub_null_funcptr },
    { 0x005252C5, stub_null_funcptr },
    /* Stub __sbh_heap_init (0x5A3560) - SBH is disabled but this func
     * still allocates 4MB of virtual memory. Return 1 (success). */
    { 0x005A3560, stub_sbh_heap_init },
    /* Stub __sbh_find_block (0x5A3800) - always returns 0 (not found).
     * Prevents traversal of uninitialized SBH header linked list. */
    { 0x005A3800, stub_sbh_find_block },
    /* Pre-main-loop init callback - missed by code generator */
    { 0x0057E560, manual_sub_0057E560 },
    /* Per-frame update callback - missed by code generator */
    { 0x0057E4F0, manual_sub_0057E4F0 },
    /* Outer init callback (calls sub_005580D0, sub_00528A50, sub_0055D720) */
    { 0x00584F30, manual_sub_00584F30 },
    /* Outer frame callback (calls sub_00558100, then sub_00541810 with inner callbacks) */
    { 0x00584F50, manual_sub_00584F50 },
    /* Inner cleanup callback (frees music/sound resources) */
    { 0x00539760, manual_sub_00539760 },
    /* Frontend display/input callback (dead code after ret in sub_00559A90) */
    { 0x00559B50, manual_sub_00559B50 },
    /* Second frontend menu display callback (dead code in sub_005593C0) */
    { 0x005595A0, manual_sub_005595A0 },
    /* VFS fopen wrapper — forwards to game CRT fopen */
    { 0x0052AD30, native_fopen_0052AD30 },
    /* Mid-function ITAIL target in sub_00529ECD (CBM sort index builder).
     * Tail-called from sub_00529950 at 0x52A198. */
    { 0x0052A198, shim_0052A198 },
};
static const int g_manual_override_count = 48;

recomp_func_t recomp_lookup_manual(uint32_t va) {
    for (int i = 0; i < g_manual_override_count; i++) {
        if (g_manual_overrides[i].address == va) {
            return g_manual_overrides[i].func;
        }
    }
    return NULL;
}

/* Import bridge table (populated during init) */
#define MAX_IMPORT_BRIDGES 1024
recomp_dispatch_entry_t g_import_bridges[MAX_IMPORT_BRIDGES];
int g_import_bridge_count = 0;

recomp_func_t recomp_lookup_import(uint32_t va) {
    for (int i = 0; i < g_import_bridge_count; i++) {
        if (g_import_bridges[i].address == va) {
            return g_import_bridges[i].func;
        }
    }
    return NULL;
}

/* ============================================================
 * Dynamic Native Function Registry
 *
 * When the game calls GetProcAddress at runtime, it gets a real
 * DLL function address. When it later ICALLs that address, we
 * need to bridge the call (read args from simulated stack, call
 * real function, adjust g_esp). This registry maps native
 * addresses to arg counts for correct bridging.
 * ============================================================ */

/* Common Win32 function arg counts (stdcall) */
typedef struct { const char* name; int nargs; } native_func_info_t;
static const native_func_info_t g_known_native_funcs[] = {
    /* KERNEL32 */
    { "GetVersion", 0 }, { "GetVersionExA", 1 }, { "GetVersionExW", 1 },
    { "GetCurrentProcessId", 0 }, { "GetCurrentThreadId", 0 },
    { "GetCurrentProcess", 0 }, { "GetTickCount", 0 },
    { "QueryPerformanceCounter", 1 }, { "QueryPerformanceFrequency", 1 },
    { "GetSystemInfo", 1 }, { "GlobalMemoryStatus", 1 },
    { "GetModuleHandleA", 1 }, { "GetModuleHandleW", 1 },
    { "GetProcAddress", 2 }, { "LoadLibraryA", 1 }, { "LoadLibraryW", 1 },
    { "FreeLibrary", 1 },
    { "GetSystemDirectoryA", 2 }, { "GetWindowsDirectoryA", 2 },
    { "CreateFileA", 7 }, { "CreateFileW", 7 },
    { "ReadFile", 5 }, { "WriteFile", 5 },
    { "CloseHandle", 1 }, { "SetFilePointer", 4 },
    { "GetFileSize", 2 }, { "DeleteFileA", 1 },
    { "GetLastError", 0 }, { "SetLastError", 1 },
    { "Sleep", 1 }, { "GetTickCount", 0 },
    { "VirtualAlloc", 4 }, { "VirtualFree", 3 },
    { "HeapAlloc", 3 }, { "HeapFree", 3 },
    { "HeapCreate", 3 }, { "HeapDestroy", 1 },
    { "InitializeCriticalSection", 1 }, { "DeleteCriticalSection", 1 },
    { "EnterCriticalSection", 1 }, { "LeaveCriticalSection", 1 },
    { "CreateMutexA", 3 }, { "ReleaseMutex", 1 },
    { "WaitForSingleObject", 2 }, { "CreateEventA", 4 },
    { "SetEvent", 1 }, { "ResetEvent", 1 },
    { "GetEnvironmentVariableA", 3 },
    { "OutputDebugStringA", 1 },
    { "InterlockedIncrement", 1 }, { "InterlockedDecrement", 1 },
    { "InterlockedExchange", 2 },
    { "TlsAlloc", 0 }, { "TlsFree", 1 },
    { "TlsGetValue", 1 }, { "TlsSetValue", 2 },
    { "GetModuleFileNameA", 3 },
    { "MultiByteToWideChar", 6 }, { "WideCharToMultiByte", 8 },
    { "lstrcpyA", 2 }, { "lstrcatA", 2 }, { "lstrlenA", 1 },
    { "GetPrivateProfileStringA", 6 }, { "GetPrivateProfileIntA", 3 },
    { "WritePrivateProfileStringA", 4 },
    /* USER32 */
    { "MessageBoxA", 4 }, { "GetDesktopWindow", 0 },
    { "ShowWindow", 2 }, { "UpdateWindow", 1 },
    { "SetWindowPos", 7 }, { "GetWindowRect", 2 },
    { "GetClientRect", 2 }, { "SetWindowTextA", 2 },
    { "GetForegroundWindow", 0 }, { "SetForegroundWindow", 1 },
    { "ShowCursor", 1 }, { "SetCursor", 1 }, { "LoadCursorA", 2 },
    { "PostQuitMessage", 1 }, { "DestroyWindow", 1 },
    { "SendMessageA", 4 }, { "PostMessageA", 4 },
    { "PeekMessageA", 5 }, { "GetMessageA", 4 },
    { "TranslateMessage", 1 }, { "DispatchMessageA", 1 },
    { "DefWindowProcA", 4 }, { "RegisterClassA", 1 },
    { "RegisterClassExA", 1 },
    { "CreateWindowExA", 12 }, { "AdjustWindowRect", 3 },
    { "GetSystemMetrics", 1 }, { "GetDC", 1 }, { "ReleaseDC", 2 },
    { "InvalidateRect", 3 }, { "MoveWindow", 6 },
    { "SetTimer", 4 }, { "KillTimer", 2 },
    { "GetKeyState", 1 }, { "GetAsyncKeyState", 1 },
    { "GetActiveWindow", 0 }, { "GetLastActivePopup", 1 },
    { "SetActiveWindow", 1 }, { "GetFocus", 0 }, { "SetFocus", 1 },
    { "EnableWindow", 2 }, { "IsWindow", 1 }, { "IsWindowVisible", 1 },
    { "GetParent", 1 }, { "SetParent", 2 },
    { "GetDlgItem", 2 }, { "SetDlgItemTextA", 3 },
    { "DialogBoxParamA", 5 }, { "EndDialog", 2 },
    { "LoadIconA", 2 }, { "LoadStringA", 4 },
    { "wsprintfA", -1 }, /* cdecl, variable args */
    { "CharUpperA", 1 }, { "CharLowerA", 1 },
    /* GDI32 */
    { "GetDeviceCaps", 2 },
    /* ADVAPI32 */
    { "RegOpenKeyExA", 5 }, { "RegCloseKey", 1 },
    { "RegQueryValueExA", 6 }, { "RegSetValueExA", 6 },
    { "RegCreateKeyExA", 9 },
    /* WINMM */
    { "timeGetTime", 0 }, { "timeBeginPeriod", 1 }, { "timeEndPeriod", 1 },
    { "joyGetNumDevs", 0 }, { "joyGetDevCapsA", 3 },
    { "joyGetPosEx", 2 },
    /* OLE32 */
    { "CoInitialize", 1 }, { "CoUninitialize", 0 },
    { "CoCreateInstance", 5 },
    /* SHELL32 */
    { "SHGetSpecialFolderPathA", 4 },
    { NULL, 0 }
};

int lookup_native_nargs(const char* name) {
    for (int i = 0; g_known_native_funcs[i].name != NULL; i++) {
        if (strcmp(g_known_native_funcs[i].name, name) == 0)
            return g_known_native_funcs[i].nargs;
    }
    return -1; /* unknown */
}

/* Dynamic native function registry */
#define MAX_NATIVE_FUNCS 128
typedef struct {
    uint32_t addr;      /* real DLL function address */
    int nargs;          /* argument count */
    char name[64];      /* function name for debugging */
} native_reg_entry_t;

static native_reg_entry_t g_native_reg[MAX_NATIVE_FUNCS];
static int g_native_reg_count = 0;

/* Register a dynamically resolved native function */
void recomp_register_native(uint32_t addr, const char* name, int nargs) {
    /* Check for duplicate */
    for (int i = 0; i < g_native_reg_count; i++) {
        if (g_native_reg[i].addr == addr) return;
    }
    if (g_native_reg_count >= MAX_NATIVE_FUNCS) {
        fprintf(stderr, "WARNING: native function registry full\n");
        return;
    }
    native_reg_entry_t* e = &g_native_reg[g_native_reg_count++];
    e->addr = addr;
    e->nargs = nargs;
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    fprintf(stderr, "[*] Registered native: %s @ 0x%08X (%d args)\n", name, addr, nargs);
}

/* Stdcall function pointer types by arg count (from imports.c) */
typedef uint32_t (__stdcall *STDFN0_t)(void);
typedef uint32_t (__stdcall *STDFN1_t)(uint32_t);
typedef uint32_t (__stdcall *STDFN2_t)(uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN3_t)(uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN4_t)(uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN5_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN6_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN7_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN8_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN9_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN10_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN11_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN12_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

/* Call a native stdcall function with args from simulated stack */
int recomp_native_call(uint32_t va) {
    for (int i = 0; i < g_native_reg_count; i++) {
        if (g_native_reg[i].addr != va) continue;

        int n = g_native_reg[i].nargs;
        uint32_t a[12];
        for (int j = 0; j < n && j < 12; j++)
            a[j] = MEM32(g_esp + 4 + j * 4);

        /* Log MessageBoxA calls with text content */
        if (strcmp(g_native_reg[i].name, "MessageBoxA") == 0) {
            const char* text = a[1] ? (const char*)(uintptr_t)a[1] : "(null)";
            const char* caption = a[2] ? (const char*)(uintptr_t)a[2] : "(null)";
            fprintf(stderr, "[*] MessageBoxA: hwnd=0x%X text=\"%s\" caption=\"%s\" type=0x%X\n",
                    a[0], text, caption, a[3]);
        }

        uint32_t r = 0;
        void* fn = (void*)(uintptr_t)va;
        switch (n) {
            case 0:  r = ((STDFN0_t)fn)(); break;
            case 1:  r = ((STDFN1_t)fn)(a[0]); break;
            case 2:  r = ((STDFN2_t)fn)(a[0],a[1]); break;
            case 3:  r = ((STDFN3_t)fn)(a[0],a[1],a[2]); break;
            case 4:  r = ((STDFN4_t)fn)(a[0],a[1],a[2],a[3]); break;
            case 5:  r = ((STDFN5_t)fn)(a[0],a[1],a[2],a[3],a[4]); break;
            case 6:  r = ((STDFN6_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5]); break;
            case 7:  r = ((STDFN7_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6]); break;
            case 8:  r = ((STDFN8_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]); break;
            case 9:  r = ((STDFN9_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]); break;
            case 10: r = ((STDFN10_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9]); break;
            case 11: r = ((STDFN11_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10]); break;
            case 12: r = ((STDFN12_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11]); break;
            default:
                fprintf(stderr, "WARNING: native call %s has %d args (max 12)\n",
                        g_native_reg[i].name, n);
                break;
        }
        g_eax = r;
        g_esp += 4 + n * 4; /* pop return addr + args (stdcall) */
        return 1;
    }
    return 0; /* not found */
}

/* ============================================================
 * Memory Setup
 * ============================================================ */

/*
 * CRITICAL: The process heap on Windows 10/11 (32-bit) typically reserves
 * 0x400000-0xBFB000. Our game data sections (0x5A9000-0xB10000) fall within
 * that range. As the heap grows, it writes metadata into our data pages,
 * causing STATUS_HEAP_CORRUPTION (0xC0000374) non-deterministically.
 *
 * Fix: Replace the process heap with a new one at a non-conflicting address.
 * This is done by creating a new heap via HeapCreate and patching the PEB's
 * ProcessHeap field. The old heap reservation remains but is never grown into.
 */
static HANDLE g_old_process_heap = NULL;

static void relocate_process_heap(void) {
    HANDLE oldHeap = GetProcessHeap();

    /* Check if the old heap's reservation overlaps our data range */
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(oldHeap, &mbi, sizeof(mbi))) {
        uintptr_t heap_start = (uintptr_t)mbi.AllocationBase;
        /* Find the end of the reservation */
        uintptr_t heap_end = heap_start;
        uintptr_t scan = heap_start;
        while (1) {
            if (VirtualQuery((void*)scan, &mbi, sizeof(mbi)) == 0) break;
            if (mbi.AllocationBase != (void*)heap_start) break;
            heap_end = scan + mbi.RegionSize;
            scan = heap_end;
        }
        printf("[*] Process heap at %p, reservation: 0x%08X-0x%08X\n",
               oldHeap, (uint32_t)heap_start, (uint32_t)heap_end);

        /* Check for overlap with game data */
        if (heap_end <= XWA_DATA_START || heap_start >= XWA_DATA_END) {
            printf("[*] No overlap with game data - heap is safe\n");
            return; /* No conflict, no need to relocate */
        }
        printf("[!] Heap reservation OVERLAPS game data (0x%08X-0x%08X)!\n",
               XWA_DATA_START, XWA_DATA_END);
    }

    /* Create a new heap at a non-conflicting address */
    HANDLE newHeap = HeapCreate(0, 0x100000, 0);
    if (!newHeap) {
        fprintf(stderr, "ERROR: Failed to create replacement heap\n");
        return;
    }

    /* Patch PEB->ProcessHeap to point to the new heap.
     * On 32-bit Windows: TEB at fs:[0x18], PEB at TEB+0x30, ProcessHeap at PEB+0x18 */
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    uint8_t* peb = *(uint8_t**)(teb + 0x30);
    HANDLE* pProcessHeap = (HANDLE*)(peb + 0x18);

    g_old_process_heap = *pProcessHeap;
    *pProcessHeap = newHeap;

    printf("[*] Replaced process heap: old=%p new=%p\n", g_old_process_heap, newHeap);

    /* Verify it worked */
    if (GetProcessHeap() == newHeap) {
        printf("[*] Process heap relocation successful\n");
    } else {
        fprintf(stderr, "WARNING: GetProcessHeap() returned %p, expected %p\n",
                GetProcessHeap(), newHeap);
    }
}

static int setup_memory(const char* data_file) {
    /*
     * Allocate one contiguous region covering both the simulated stack
     * and original data sections. A single g_mem_base offset translates
     * all original VAs to real addresses.
     *
     * We try to map at the original addresses first (g_mem_base = 0),
     * but fall back to wherever the OS gives us.
     */

    printf("[*] Allocating %u MB region (0x%08X - 0x%08X)\n",
           (unsigned)(XWA_REGION_SIZE / (1024*1024)), XWA_REGION_START, XWA_REGION_END);

    /* Relocate process heap if it conflicts with our data section */
    relocate_process_heap();

    /* Enumerate ALL heaps to find which one owns 0x400000-0xBFB000 */
    {
        HANDLE heaps[64];
        DWORD nheaps = GetProcessHeaps(64, heaps);
        printf("[*] Process has %lu heaps:\n", nheaps);
        for (DWORD i = 0; i < nheaps && i < 64; i++) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(heaps[i], &mbi, sizeof(mbi))) {
                printf("    Heap %lu: %p (alloc base %p, region 0x%lX bytes)\n",
                    i, heaps[i], mbi.AllocationBase, mbi.RegionSize);
                /* Check if this heap has a segment at 0x400000 */
                if ((uintptr_t)mbi.AllocationBase == 0x00400000 ||
                    ((uintptr_t)heaps[i] >= 0x400000 && (uintptr_t)heaps[i] < 0xBFB000)) {
                    printf("    *** THIS HEAP is in the 0x400000-0xBFB000 range! ***\n");
                }
            }
        }
    }

    /* Debug: check what's at our target addresses (scan past reservation too) */
    {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t scan = XWA_REGION_START;
        printf("[*] Memory map at target range:\n");
        while (scan < XWA_REGION_END + 0x100000) {  /* scan a bit past the region */
            if (VirtualQuery((void*)scan, &mbi, sizeof(mbi)) == 0) break;
            printf("    0x%08X-0x%08X: State=0x%lX Type=0x%lX Alloc=0x%p\n",
                   (uint32_t)scan, (uint32_t)(scan + mbi.RegionSize),
                   mbi.State, mbi.Type, mbi.AllocationBase);
            scan += mbi.RegionSize;
            if (mbi.RegionSize == 0) break;
        }
    }

    /* Try 1: Full region at exact addresses */
    g_region_alloc = VirtualAlloc(
        (void*)(uintptr_t)XWA_REGION_START,
        XWA_REGION_SIZE,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (g_region_alloc) {
        g_mem_base = 0;
        printf("[*] Mapped at original addresses (g_mem_base = 0)\n");
        goto alloc_done;
    }

    /* Try 2: Commit pages within existing reservation (data section).
     * The old heap reservation at 0x400000-0xBFB000 is still present
     * (we can't free it) but the process heap has been relocated,
     * so the heap won't grow into our data pages anymore. */
    {
        void* data_try = VirtualAlloc(
            (void*)(uintptr_t)XWA_DATA_START,
            XWA_DATA_END - XWA_DATA_START,
            MEM_COMMIT,  /* just commit, don't reserve */
            PAGE_READWRITE
        );
        if (data_try == (void*)(uintptr_t)XWA_DATA_START) {
            printf("[*] Data committed at original VA 0x%08X (within old heap reservation)\n",
                   XWA_DATA_START);
            g_mem_base = 0;
            g_region_alloc = data_try;

            /* Stack: also try to commit at original address, else use real address */
            void* stack_try = VirtualAlloc(
                (void*)(uintptr_t)XWA_STACK_BASE, XWA_STACK_SIZE,
                MEM_COMMIT, PAGE_READWRITE);
            if (!stack_try) {
                stack_try = VirtualAlloc(
                    (void*)(uintptr_t)XWA_STACK_BASE, XWA_STACK_SIZE,
                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            }
            if (stack_try == (void*)(uintptr_t)XWA_STACK_BASE) {
                printf("[*] Stack committed at original VA 0x%08X\n", XWA_STACK_BASE);
            } else {
                /* Stack at different address - use REAL address for ESP */
                if (!stack_try) {
                    stack_try = VirtualAlloc(NULL, XWA_STACK_SIZE,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                }
                if (!stack_try) {
                    fprintf(stderr, "ERROR: Failed to allocate stack\n");
                    return 0;
                }
                /* With g_mem_base=0, ESP must be real address since MEM32 won't translate */
                g_esp = (uint32_t)((uintptr_t)stack_try + XWA_STACK_SIZE - 16);
                printf("[*] Stack at %p (real addr, ESP=0x%08X)\n", stack_try, g_esp);
            }

            /* Proactively commit FREE pages from BFB000 to extended end.
             * IMPORTANT: Do NOT commit RESERVED pages - they may belong to
             * heap reservations, thread stacks, or other system structures.
             * Committing them corrupts the owning allocator's metadata. */
            {
                MEMORY_BASIC_INFORMATION mbi;
                uintptr_t scan = XWA_DATA_END;
                uint32_t committed = 0, gaps = 0, reserved_skip = 0;
                while (scan < XWA_EXTENDED_END) {
                    if (!VirtualQuery((void*)scan, &mbi, sizeof(mbi))) break;
                    if (mbi.RegionSize == 0) break;

                    if (mbi.State == MEM_FREE) {
                        SIZE_T sz = mbi.RegionSize;
                        if (scan + sz > XWA_EXTENDED_END) sz = XWA_EXTENDED_END - scan;
                        void* p = VirtualAlloc((void*)scan, sz,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                        if (p) committed += (uint32_t)sz;
                    } else if (mbi.State == MEM_RESERVE) {
                        /* Skip - belongs to another allocation (heap, etc.) */
                        reserved_skip++;
                        gaps++;
                        if (gaps <= 8) {
                            printf("    [reserved] 0x%08X-0x%08X type=0x%lX (skipped)\n",
                                (uint32_t)scan, (uint32_t)(scan + mbi.RegionSize),
                                mbi.Type);
                        }
                    } else if (mbi.State == MEM_COMMIT) {
                        /* Existing allocation - log it as a gap */
                        gaps++;
                        if (gaps <= 8) {
                            printf("    [gap] 0x%08X-0x%08X type=0x%lX prot=0x%lX\n",
                                (uint32_t)scan, (uint32_t)(scan + mbi.RegionSize),
                                mbi.Type, mbi.Protect);
                        }
                    }
                    scan += mbi.RegionSize;
                }
                printf("[*] Extended BSS: committed %u KB, %u gaps, %u reserved-skips (0x%08X-0x%08X)\n",
                       committed / 1024, gaps, reserved_skip, XWA_DATA_END, XWA_EXTENDED_END);
            }

            goto alloc_done;
        }
    }

    /* Try 3: Complete fallback - let OS pick */
    printf("[*] Fixed allocation failed, using OS-picked address...\n");
    g_region_alloc = VirtualAlloc(NULL, XWA_REGION_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g_region_alloc) {
        fprintf(stderr, "ERROR: Failed to allocate %u MB region\n",
                (unsigned)(XWA_REGION_SIZE / (1024*1024)));
        return 0;
    }
    g_mem_base = (ptrdiff_t)((uintptr_t)g_region_alloc - XWA_REGION_START);
    printf("[*] Region at %p (offset %lld from original)\n",
           g_region_alloc, (long long)g_mem_base);

alloc_done:

memory_ready:
    /* Set initial stack pointer (as a VIRTUAL address, translated via ADDR) */
    if (g_esp == 0) {
        g_esp = XWA_STACK_TOP - 16;
    }

    /* Load .rdata and .data sections from the original binary */
    if (data_file) {
        FILE* f = fopen(data_file, "rb");
        if (f) {
            /*
             * Section offsets from PE section headers:
             * .rdata: file offset 0x001A8000, VA 0x005A9000, VSize 0x4A24, RawSize 0x4C00
             * .data:  file offset 0x001ACC00, VA 0x005AE000, VSize 0x561974, RawSize 0x60600
             * BSS (zero-initialized) portion of .data is VSize - RawSize = 0x501374 bytes,
             * which is already zeroed by VirtualAlloc. Only read the on-disk RawSize.
             */
            /* Commit pages for the .text range so we can load embedded data
             * tables, jump tables, and string constants that recompiled code
             * references via MEM macros.  Our exe lives at 0x10000000, so the
             * 0x401000-0x5A9000 range is inside the old heap reservation but
             * may not be committed yet.  MEM_COMMIT within MEM_RESERVE is OK. */
            {
                void* text_pages = VirtualAlloc(
                    (void*)(uintptr_t)0x00401000,
                    0x5A9000 - 0x401000,     /* .text through end of gap before .rdata */
                    MEM_COMMIT, PAGE_READWRITE);
                if (text_pages) {
                    printf("[*] Committed .text data pages at 0x%p (0x%X bytes)\n",
                           text_pages, 0x5A9000 - 0x401000);
                } else {
                    fprintf(stderr, "WARNING: Failed to commit .text pages (err=%lu)\n",
                            GetLastError());
                }
            }

            /* Read .text (contains embedded data tables, jump tables, string
             * constants that the recompiled code still references via MEM macros).
             * .text: file offset 0x400, VA 0x401000, RawSize 0x1A7C00
             *
             * IMPORTANT: The Steam binary has SafeDisc encryption on large parts
             * of .text (roughly 0x599000-0x5A1000+). We try to load from a
             * decrypted binary first; fall back to the game binary. */
            {
                int text_loaded = 0;
                /* Try decrypted binary: same dir as game exe, or known paths */
                const char* dec_paths[] = {
                    "xwingalliance_decrypted.exe",
                    "../recomp/config/xwingalliance_decrypted.exe",
                    NULL
                };
                for (int i = 0; dec_paths[i]; i++) {
                    FILE* fd = fopen(dec_paths[i], "rb");
                    if (fd) {
                        fseek(fd, 0x00000400, SEEK_SET);
                        size_t n = fread((void*)ADDR(0x00401000), 1, 0x1A7C00, fd);
                        fclose(fd);
                        if (n == 0x1A7C00) {
                            printf("[*] Loaded .text from decrypted binary: %s\n", dec_paths[i]);
                            text_loaded = 1;
                            break;
                        }
                    }
                }
                if (!text_loaded) {
                    fprintf(stderr, "WARNING: Using encrypted .text from game binary"
                            " (jump tables may be garbage)\n");
                    fseek(f, 0x00000400, SEEK_SET);
                    fread((void*)ADDR(0x00401000), 1, 0x1A7C00, f);
                }
            }

            /* Read .rdata (VSize) */
            fseek(f, 0x001A8000, SEEK_SET);
            fread((void*)ADDR(0x005A9000), 1, 0x4A24, f);

            /* Read .data (RawSize only; rest is BSS, already zero from VirtualAlloc) */
            fseek(f, 0x001ACC00, SEEK_SET);
            fread((void*)ADDR(0x005AE000), 1, 0x60600, f);

            fclose(f);
            printf("[*] Loaded data sections from %s\n", data_file);

            /* Patch SafeDisc-encrypted CRT data tables in .text section.
             * These tables are used by sub_005A03B0 (_openfile/_sopen) for
             * parsing fopen mode strings ("r", "rb", "w+", etc.).
             *
             * Jump table at 0x5A050C: 10 entries mapping class index → handler VA.
             * Byte table at 0x5A0534: 74 entries mapping (char - '+') → class index.
             */
            {
                /* Jump table: class index → handler address */
                static const uint32_t jump_table[10] = {
                    0x005A049C,  /* [0] default: invalid character */
                    0x005A0427,  /* [1] '+': read+write mode */
                    0x005A043A,  /* [2] 'S': sequential access */
                    0x005A0444,  /* [3] 'R': random access */
                    0x005A044E,  /* [4] 'b': binary mode */
                    0x005A045F,  /* [5] 't': text mode */
                    0x005A0470,  /* [6] 'c': commit on flush */
                    0x005A047D,  /* [7] 'n': no commit */
                    0x005A048A,  /* [8] 'T': short-lived */
                    0x005A0494,  /* [9] 'D': temporary/delete-on-close */
                };
                memcpy((void*)ADDR(0x5A050C), jump_table, sizeof(jump_table));

                /* Byte table: (char - 0x2B) → class index (0 = default/invalid) */
                uint8_t byte_table[74];
                memset(byte_table, 0, sizeof(byte_table));
                byte_table['+' - 0x2B] = 1;  /* offset 0  */
                byte_table['D' - 0x2B] = 9;  /* offset 25 */
                byte_table['R' - 0x2B] = 3;  /* offset 39 */
                byte_table['S' - 0x2B] = 2;  /* offset 40 */
                byte_table['T' - 0x2B] = 8;  /* offset 41 */
                byte_table['b' - 0x2B] = 4;  /* offset 55 */
                byte_table['c' - 0x2B] = 6;  /* offset 56 */
                byte_table['n' - 0x2B] = 7;  /* offset 67 */
                byte_table['t' - 0x2B] = 5;  /* offset 73 */
                memcpy((void*)ADDR(0x5A0534), byte_table, sizeof(byte_table));

                printf("[*] Patched SafeDisc-encrypted CRT tables at 0x5A050C, 0x5A0534\n");
            }

            /* Patch WndProc address in sub_0053EB30's code data.
             * Instruction at 0x0053EB47: mov [esp+0x18], 0x0053E650
             * The 4-byte immediate 0x0053E650 is at VA 0x0053EB4B.
             * Replace with address of our native WndProc bridge so
             * Windows can call it directly (our .text pages aren't executable). */
            {
                extern LRESULT CALLBACK native_wndproc_bridge(HWND, UINT, WPARAM, LPARAM);
                uint32_t bridge_addr = (uint32_t)(uintptr_t)&native_wndproc_bridge;
                MEM32(0x0053EB4B) = bridge_addr;
                printf("[*] Patched WndProc: 0x0053E650 -> 0x%08X (native bridge)\n", bridge_addr);
            }
        } else {
            fprintf(stderr, "WARNING: Could not open %s for data loading\n", data_file);
        }
    }

    return 1;
}

static void cleanup_memory(void) {
    if (g_region_alloc) {
        VirtualFree(g_region_alloc, 0, MEM_RELEASE);
        g_region_alloc = NULL;
    }
}

/* ============================================================
 * Entry Point
 * ============================================================ */

/* Dump ICALL trace on exit */
/* Write one registered DirectDraw surface (16bpp RGB565) out as a 24bpp BMP.
 *
 * The surface scan/dump used to live only in the atexit handler, so it never fired for a menu: a
 * timed-out run is killed and atexit never runs. Menus also never reach the D3D11 back buffer, so
 * capturing there yields black -- this is the only way to actually LOOK at a menu screen. */
void xwa_dump_surface(unsigned idx, const char* name)
{
    const uint32_t* e;
    uint32_t w, h, pitch, rowb, img;
    const uint8_t* base;
    FILE* f;
    if (idx >= g_surfreg_n) return;
    e = (const uint32_t*)(uintptr_t)g_surfreg[idx][0];
    if (!e || IsBadReadPtr(e, 20) || !e[0] || !e[1] || !e[2]) return;
    w = e[1]; h = e[2]; pitch = e[4] ? e[4] : w * 2u;
    if (!w || !h || w > 4096u || h > 4096u) return;
    base = (const uint8_t*)(uintptr_t)e[0];
    if (IsBadReadPtr(base, (size_t)pitch * h)) return;
    rowb = ((w * 3u) + 3u) & ~3u;
    img  = rowb * h;
    f = fopen(name, "wb");
    if (!f) return;
    {   uint8_t hd[54]; uint32_t off = 54, fsz = 54 + img, v = 40;
        uint16_t pl = 1, bc = 24;
        memset(hd, 0, sizeof hd); hd[0] = 'B'; hd[1] = 'M';
        memcpy(hd+2,&fsz,4); memcpy(hd+10,&off,4); memcpy(hd+14,&v,4);
        memcpy(hd+18,&w,4);  memcpy(hd+22,&h,4);
        memcpy(hd+26,&pl,2); memcpy(hd+28,&bc,2); memcpy(hd+34,&img,4);
        fwrite(hd,1,54,f);
    }
    {   uint8_t* row = (uint8_t*)malloc(rowb);
        uint32_t y, x;
        for (y = 0; y < h && row; y++) {
            const uint16_t* sp = (const uint16_t*)(base + (size_t)(h-1-y) * pitch);
            memset(row, 0, rowb);
            for (x = 0; x < w; x++) {
                uint16_t c = sp[x];                      /* RGB565 */
                row[x*3+0] = (uint8_t)(( c        & 0x1F) << 3);
                row[x*3+1] = (uint8_t)(((c >> 5)  & 0x3F) << 2);
                row[x*3+2] = (uint8_t)(((c >> 11) & 0x1F) << 3);
            }
            fwrite(row, 1, rowb, f);
        }
        free(row);
    }
    fclose(f);
    fprintf(stderr, "[UISURF] wrote %s from surface #%u (%ux%u)\n", name, idx, w, h);
    fflush(stderr);
}

/* XWA_WI=1: block trace for sub_0050FCB0 -- worldinit plus the flight frame body, 312 stamps.
 * These used to print unconditionally and with a fixed 100k cap, which a single busy-wait loop
 * early in worldinit (0x510247/0x510260/0x51026E) exhausts before the frame body is ever reached.
 *   XWA_WIFROM=0xADDR  only stamp blocks at or above this address (skip the init prologue)
 *   XWA_WIMAX=N        line cap (default 100000)
 * Consecutive repeats of the same block are collapsed and reported as a count, so a spin costs
 * one line instead of the whole budget. */
void xwa_wi(unsigned blk)
{
    static int on = -1;
    static unsigned from, cap, n, last, runlen;
    if (on < 0) {
        on   = getenv("XWA_WI") ? 1 : 0;
        from = getenv("XWA_WIFROM") ? (unsigned)strtoul(getenv("XWA_WIFROM"), NULL, 0) : 0u;
        cap  = getenv("XWA_WIMAX")  ? (unsigned)strtoul(getenv("XWA_WIMAX"),  NULL, 0) : 100000u;
    }
    if (!on || blk < from) return;
    if (blk == last) { runlen++; return; }
    if (runlen > 1u) fprintf(stderr, "[WI] %06X x%u\n", last, runlen);
    last = blk; runlen = 1;
    if (n++ >= cap) return;
    fprintf(stderr, "[WI] %06X\n", blk);
    fflush(stderr);
}

/* Block ring for sub_004F9320, the engine's "put the player in a craft" routine. It is 3400 lines
 * of generated C with 529 blocks; a linear trace drowns, but the last 24 blocks before it returns
 * name the exit path exactly. Same trick that found the DirectPlay wait loop. */
unsigned g_pcring[512], g_pcridx;
void xwa_pcblk(unsigned blk)
{
    g_pcring[g_pcridx] = blk;
    g_pcridx = (g_pcridx + 1u) % 512u;
    /* XWA_PCWHO=0xADDR: when this block is reached, walk the HOST stack and name the guest
     * functions on it. A block ring says what is spinning; it cannot say who is driving the spin
     * when the driver's own blocks are not stamped. Same walk the VEH handler does on a fault. */
    {   static int on = -1; static unsigned want, hits;
        if (on < 0) {
            const char* e = getenv("XWA_PCWHO");
            on = e ? 1 : 0;
            want = e ? (unsigned)strtoul(e, NULL, 0) : 0u;
        }
        /* Only sample while the player-craft call is actually running. malloc is called constantly
         * from startup and the main loop, so "the first N hits" samples the wrong moment entirely
         * -- which is exactly the mistake that produced a bogus "the chain has unwound" reading. */
        {   extern int g_pc_incall;
            if (on && want && !g_pc_incall) return;
        }
        /* Sample the FIRST hit and then deep into the loop -- the first one only shows how the
         * loop was entered, not what it is doing once it settles. */
        if (on && blk == want && (++hits == 1u || hits == 2000u || hits == 40000u)) {
            extern uint32_t guest_func_for_host(uintptr_t host_addr);
            uintptr_t* sp = (uintptr_t*)_AddressOfReturnAddress();
            int i, found = 0;
            fprintf(stderr, "[PCWHO] hit #%u, called from:", hits);
            for (i = 0; i < 262144 && found < 40; i++) {
                uintptr_t v = 0;
                __try { v = sp[i]; } __except(1) { break; }
                { uint32_t gv = guest_func_for_host(v);
                  if (gv) { fprintf(stderr, " sub_%08X", gv); found++; } }
            }
            fprintf(stderr, "\n");
            {   /* the block ring at the same instant, so the stack and the trace agree */
                unsigned q;
                fprintf(stderr, "[PCWHO] ring:");
                for (q = 0; q < 512u; q++) fprintf(stderr, " %06X", g_pcring[(g_pcridx + q) % 512u]);
                fprintf(stderr, "\n");
            }
            fflush(stderr);
        }
    }
}

/* XWA_PCRINGDUMP=<ms>: print the ring from a watchdog thread. A hang leaves the ring holding the
 * spin, but nothing downstream ever runs to print it -- so print it from outside. */
static DWORD WINAPI xwa_pcring_dump(LPVOID unused)
{
    unsigned ms = (unsigned)strtoul(getenv("XWA_PCRINGDUMP"), NULL, 0);
    (void)unused;
    if (ms < 1000u) ms = 1000u;
    for (;;) {
        unsigned q;
        Sleep(ms);
        /* Only dump while the player-craft call is running, otherwise the ring shows the main loop
         * -- which is what made an ordinary per-frame malloc/free look like the spin. */
        { extern int g_pc_incall; if (!g_pc_incall) continue; }
        {   /* The player record, so a hang can be told apart from "the craft exists and the game
             * simply moved on to another screen". */
            uint32_t pb = MEM32(0x8C1CC8) * 0xBCFu;
            fprintf(stderr, "[PCRING] player: obj=0x%X +0x15(flying)=%u +0x12=%u +0x219=%u +0x11=%u\n",
                    MEM32(pb + 0x8B94E0u), MEM8(pb + 0x8B94F5u), MEM8(pb + 0x8B94F2u),
                    (unsigned)MEM16(pb + 0x8B96F9u), MEM8(pb + 0x8B94F1u));
        }
        fprintf(stderr, "[PCRING]");
        for (q = 0; q < 512u; q++) fprintf(stderr, " %06X", g_pcring[(g_pcridx + q) % 512u]);
        fprintf(stderr, "\n"); fflush(stderr);
    }
}
void xwa_pcring_watch(void)
{
    if (getenv("XWA_PCRINGDUMP"))
        CreateThread(NULL, 0, xwa_pcring_dump, NULL, 0, NULL);
}


/* Set only while XWA_PLAYERCRAFT is driving the seat, so hooks that must not disturb the engine's
 * own flight-group activation walk can tell the two apart. */
int g_pc_seating = 0;
int g_pc_incall = 0;
uint32_t g_scr_cb = 0;   /* screen callback most recently dispatched by sub_0053FD00 */   /* set while XWA_PLAYERCRAFT is inside sub_004F9320 */

/* XWA_MILE: ordered milestone trace. Which of worldinit's steps runs before which is the whole
 * question when a record is still empty at a use site -- a per-site counter cannot answer it, and
 * a full call trace is far too big. One line per stamp, in execution order, is enough. */
void xwa_mile(const char* tag)
{
    static unsigned n;
    static int on = -1;               /* stamped at function entry in hot paths -- resolve once */
    if (on < 0) on = getenv("XWA_MILE") ? 1 : 0;
    if (!on || ++n > 400u) return;
    fprintf(stderr, "[MILE] %3u %s\n", n, tag);
    fflush(stderr);
}

static void dump_trace_atexit(void) {
    /* Write trace to file using raw Win32 API (reliable even in exit context) */
    HANDLE h = CreateFileA("xwa_atexit.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[256];
        DWORD written;
        int len = snprintf(buf, sizeof(buf),
            "=== ATEXIT TRACE DUMP ===\r\n"
            "Total calls: %u, icalls: %u, depth: %u (max: %u)\r\n"
            "trace_ring_idx: %u\r\n"
            "EAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
            "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n\r\n",
            g_total_calls, g_total_icalls, g_call_depth, g_call_depth_max,
            g_trace_ring_idx,
            g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi);
        WriteFile(h, buf, len, &written, NULL);

        len = snprintf(buf, sizeof(buf), "=== Trace Ring ===\r\n");
        WriteFile(h, buf, len, &written, NULL);
        uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
        for (uint32_t i = start; i < g_trace_ring_idx; i++) {
            uint32_t idx = i & (TRACE_RING_SIZE - 1);
            if (g_trace_ring[idx][0]) {
                len = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                WriteFile(h, buf, len, &written, NULL);
            }
        }

        len = snprintf(buf, sizeof(buf), "\r\n=== ICALL Trace ===\r\n");
        WriteFile(h, buf, len, &written, NULL);
        for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
            uint32_t idx2 = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
            if (g_icall_trace[idx2]) {
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", i, g_icall_trace[idx2]);
                WriteFile(h, buf, len, &written, NULL);
            }
        }
        CloseHandle(h);
    }

    { extern unsigned g_rcount[8]; extern const char* const g_rcount_name[8];
      { extern unsigned g_ccount[4];
        fprintf(stderr, "[CAMCOUNT] build_sub_00478490=%u copy_sub_004949B0=%u percraft_sub_004EE820=%u | matrix 8D93C0=%08X CC=%08X E0=%08X E4=%08X F0=%08X F8=%08X FC=%08X gate_8D6BB0=%08X\n",
          g_ccount[0], g_ccount[1], g_ccount[2], MEM32(0x8D93C0), MEM32(0x8D93CC), MEM32(0x8D93E0),
          MEM32(0x8D93E4), MEM32(0x8D93F0), MEM32(0x8D93F8), MEM32(0x8D93FC), MEM32(0x8D6BB0)); }
      { extern volatile unsigned g_t7[2]; { extern volatile unsigned g_up2[2]; fprintf(stderr, "[TYPE7] 42A4B0=%u 47D710=%u | up: 42A010=%u 4EFE00=%u\n", g_t7[0], g_t7[1], g_up2[0], g_up2[1]); } }
      { extern volatile unsigned g_ld[4]; fprintf(stderr, "[LOADFN] 4CDED0=%u 4CE130=%u 4CF920=%u 462BE0=%u\n", g_ld[0],g_ld[1],g_ld[2],g_ld[3]); }
      { extern volatile unsigned g_dev[8]; fprintf(stderr, "[DEVFN] 5593C0=%u 55D270=%u 558120=%u 556B10=%u 55BBA0=%u 556AF0=%u\n", g_dev[0],g_dev[1],g_dev[2],g_dev[3],g_dev[4],g_dev[5]); }
      { extern volatile unsigned g_hw[4]; fprintf(stderr, "[HWINIT] 441EE0=%u 593F1D=%u 594063=%u 50BC20=%u | 7B1D14=0x%08X 77330C=%u\n", g_hw[0],g_hw[1],g_hw[2],g_hw[3], MEM32(0x7B1D14u), MEM32(0x77330Cu)); }
      { extern volatile unsigned g_ty[10]; fprintf(stderr, "[TYPE] t0=%u t1=%u t2=%u t3=%u t4=%u t5=%u t6=%u t7+=%u | arg0=%u badebp=%u\n", g_ty[0],g_ty[1],g_ty[2],g_ty[3],g_ty[4],g_ty[5],g_ty[6],g_ty[7],g_ty[8],g_ty[9]); }
      { extern volatile unsigned g_ebf[4]; extern volatile unsigned g_up[4]; fprintf(stderr, "[EBFN] 595006=%u 5954D6=%u | 442F70=%u 448000=%u 482000=%u 481AD0(per-craft)=%u | 480370=%u 482000=%u\n", g_ebf[0], g_ebf[1], g_ebf[2], g_ebf[3], g_up[0], g_up[1]); }
      { extern volatile unsigned g_sd[4]; fprintf(stderr, "[SCENEDRAW] 448660=%u 50D780=%u 448B80=%u 4D3520=%u\n", g_sd[0],g_sd[1],g_sd[2],g_sd[3]); fflush(stderr); }
      if (getenv("XWA_DRAWTRACE")) { extern unsigned g_dcount[8]; extern const char* const g_dcount_name[8];
        fprintf(stderr, "[DRAWTRACE]");
        for (int _i = 0; _i < 8; _i++) fprintf(stderr, "  %s=%u", g_dcount_name[_i], g_dcount[_i]);
        fprintf(stderr, "\n"); fflush(stderr); }
      if (getenv("XWA_TEXPATH")) { extern unsigned g_texpath[3]; extern unsigned g_texnode_n; extern unsigned g_bindfn[8];
        fprintf(stderr, "[TEXPATH] sub_00597784 calls=%u -> create(sub_0059786E)=%u resident(sub_00597DBE)=%u distinct-nodes=%u | binders: 442F70=%u 44A5A0=%u 44A7B0=%u 448000=%u 482000=%u 481AD0-percraft=%u 45A520=%u 43FE50-drawobj=%u\n", g_texpath[0], g_texpath[1], g_texpath[2], g_texnode_n, g_bindfn[0], g_bindfn[1], g_bindfn[2], g_bindfn[3], g_bindfn[4], g_bindfn[5], g_bindfn[6], g_bindfn[7]); fflush(stderr); }
      if (getenv("XWA_OBJTYPE")) { extern unsigned g_objtype[40]; extern unsigned g_node1;
        fprintf(stderr, "[OBJTYPE] type1-nodes-created=%u |", g_node1);
        for (int _i = 0; _i < 40; _i++) if (g_objtype[_i]) fprintf(stderr, " type%d=%u", _i, g_objtype[_i]);
        fprintf(stderr, "\n"); fflush(stderr); }
      if (getenv("XWA_FGTYPE")) { extern unsigned g_fgtype[16]; extern unsigned g_fgtype_n;
        fprintf(stderr, "[FGTYPE] gate checks=%u  distinct [fg+2] values:", g_fgtype_n);
        for (int _i = 0; _i < 15; _i++) if (g_fgtype[_i]) fprintf(stderr, " 0x%X", g_fgtype[_i]);
        fprintf(stderr, "  (need 0xDE)\n"); fflush(stderr); }
      if (getenv("XWA_A5TYPE")) { extern unsigned g_a5type[24];
        fprintf(stderr, "[A5TYPE] switch @0x0045AA11 (need 11 or 13):");
        for (int _i = 0; _i < 24; _i++) if (g_a5type[_i]) fprintf(stderr, " t%d=%u", _i, g_a5type[_i]);
        fprintf(stderr, "\n"); fflush(stderr); }
      if (getenv("XWA_SURFSCAN")) { extern uint32_t g_surfreg[8192][5]; extern unsigned g_surfreg_n;
        fprintf(stderr, "[SURFSCAN] %u surfaces registered\n", g_surfreg_n);
        unsigned _best = 0, _bestd = 0;
        for (unsigned _i = 0; _i < g_surfreg_n; _i++) {
            const uint32_t* _e = (const uint32_t*)(uintptr_t)g_surfreg[_i][0];
            if (!_e || IsBadReadPtr(_e, 20)) continue;
            uint32_t _px = _e[0], _w = _e[1], _h = _e[2];
            if (!_px || !_w || !_h || _w > 4096 || _h > 4096) continue;
            if (IsBadReadPtr((void*)(uintptr_t)_px, (size_t)_w * _h * 2)) continue;
            const uint16_t* _p = (const uint16_t*)(uintptr_t)_px;
            /* distinct-colour estimate over a sparse sample */
            uint16_t _seen[64]; unsigned _n = 0;
            for (unsigned _k = 0; _k < (unsigned)(_w * _h); _k += 37u) {
                uint16_t _c = _p[_k]; unsigned _j; int _f = 0;
                for (_j = 0; _j < _n; _j++) if (_seen[_j] == _c) { _f = 1; break; }
                if (!_f) { if (_n < 64) _seen[_n++] = _c; else { _n = 65; break; } }
            }
            if (_n > _bestd) { _bestd = _n; _best = _i; }
            if (_n >= 8) fprintf(stderr, "[SURFSCAN]   surf#%u %ux%u distinct~%u%s\n",
                                 _i, _w, _h, _n, (_n > 32) ? "  <-- RICH CONTENT" : "");
        }
        /* XWA_SURFDUMP=N: write surface N to surf_N.bmp (16bpp RGB565 -> 24bpp BMP). */
        if (getenv("XWA_SURFDUMP")) {
            unsigned _want = (unsigned)atoi(getenv("XWA_SURFDUMP"));
            if (_want < g_surfreg_n) {
                const uint32_t* _e = (const uint32_t*)(uintptr_t)g_surfreg[_want][0];
                if (_e && !IsBadReadPtr(_e, 20) && _e[0] && _e[1] && _e[2]) {
                    uint32_t _w = _e[1], _h = _e[2], _pitch = _e[4] ? _e[4] : _w * 2;
                    const uint8_t* _base = (const uint8_t*)(uintptr_t)_e[0];
                    uint32_t _rowb = ((_w * 3u) + 3u) & ~3u, _img = _rowb * _h;
                    char _nm[64]; sprintf(_nm, "surf_%u.bmp", _want);
                    FILE* _f = fopen(_nm, "wb");
                    if (_f) {
                        uint8_t _hd[54]; uint32_t _off = 54, _fsz = 54 + _img;
                        memset(_hd, 0, sizeof _hd); _hd[0]='B'; _hd[1]='M';
                        memcpy(_hd+2,&_fsz,4); memcpy(_hd+10,&_off,4);
                        { uint32_t _v=40; memcpy(_hd+14,&_v,4); }
                        memcpy(_hd+18,&_w,4); memcpy(_hd+22,&_h,4);
                        { uint16_t _pl=1,_bc=24; memcpy(_hd+26,&_pl,2); memcpy(_hd+28,&_bc,2); }
                        memcpy(_hd+34,&_img,4);
                        fwrite(_hd,1,54,_f);
                        uint8_t* _row = (uint8_t*)malloc(_rowb);
                        for (uint32_t _y = 0; _y < _h && _row; _y++) {
                            const uint16_t* _sp = (const uint16_t*)(_base + (size_t)(_h-1-_y) * _pitch);
                            memset(_row, 0, _rowb);
                            for (uint32_t _x = 0; _x < _w; _x++) {
                                uint16_t _c = _sp[_x];              /* RGB565 */
                                _row[_x*3+0] = (uint8_t)(( _c        & 0x1F) << 3);
                                _row[_x*3+1] = (uint8_t)(((_c >> 5)  & 0x3F) << 2);
                                _row[_x*3+2] = (uint8_t)(((_c >> 11) & 0x1F) << 3);
                            }
                            fwrite(_row,1,_rowb,_f);
                        }
                        free(_row); fclose(_f);
                        fprintf(stderr, "[SURFDUMP] wrote %s (%ux%u pitch=%u)\n", _nm, _w, _h, _pitch);
                        fflush(stderr);
                    }
                }
            }
        }
        { uint32_t _rt = MEM32(0x6002BC), _match = 0xFFFFFFFFu;
          for (unsigned _i = 0; _i < g_surfreg_n; _i++) {
              const uint32_t* _e2 = (const uint32_t*)(uintptr_t)g_surfreg[_i][0];
              if (_e2 && !IsBadReadPtr(_e2, 20) && _e2[0] == _rt) { _match = _i; break; }
          }
          fprintf(stderr, "[RTARGET] 0x6002BC=0x%08X -> surf#%d  dims=%ux%u\n",
                  _rt, (int)_match, MEM32(0x6002B0), MEM32(0x6002B4));
          fflush(stderr); }
        fprintf(stderr, "[SURFSCAN] richest surf#%u distinct~%u (%ux%u)\n",
                _best, _bestd, ((const uint32_t*)(uintptr_t)g_surfreg[_best][0])[1], ((const uint32_t*)(uintptr_t)g_surfreg[_best][0])[2]);
        fflush(stderr); }
      if (getenv("XWA_WALK")) { extern unsigned g_walk[4]; extern unsigned g_exits[4]; extern unsigned g_link_n; extern unsigned g_subload_n;
        fprintf(stderr, "[LINKS] sub_004CCC40 calls=%u child-array writes=%u | [WALK] 480A80=%u 482D60=%u 4836F0=%u 483EB0=%u | exits: 4848A9=%u 4848E5=%u 484953=%u\n",
                g_subload_n, g_link_n, g_walk[0], g_walk[1], g_walk[2], g_walk[3], g_exits[0], g_exits[1], g_exits[2]); fflush(stderr); }
      if (getenv("XWA_BLD")) { extern unsigned g_bld[4];
        fprintf(stderr, "[BLD] sub_0041EF60 calls=%u  write@41F471=%u  write@41F77F=%u  slot=%u  gate=0x%X\n",
                g_bld[0], g_bld[1], g_bld[2], MEM32(0x8C1CC8),
                MEM16(MEM32(0x8C1CC8) * 0xBCFu + 0x8B96F9)); fflush(stderr); }
      if (getenv("XWA_BLD")) { extern unsigned g_cal[8];
        fprintf(stderr, "[CALLERS] 4034D0=%u 457C20=%u 4F9320=%u 4FBA80=%u 500F9A=%u 5064D0=%u 507D60=%u\n",
          g_cal[0],g_cal[1],g_cal[2],g_cal[3],g_cal[4],g_cal[5],g_cal[6]); fflush(stderr); }
      if (getenv("XWA_GATES")) { extern unsigned g_gt[4];
        fprintf(stderr, "[GATES] gateA(91AE7C) checks=%u passed=%u | gateB(+0x219) checks=%u passed=%u\n",
                g_gt[0], g_gt[1], g_gt[2], g_gt[3]); fflush(stderr); }
      { extern unsigned g_spawnfn[8]; extern unsigned g_frameblk;
        uint32_t tbl = MEM32(0x7B33C4), cnt = MEM32(0x917E64), i, live = 0;
        if (tbl && cnt && cnt < 4096u) for (i = 0; i < cnt; i++)
            if (xwa_readable(tbl + i*0x27u, 0x27) && MEM16(tbl + i*0x27u + 2)) live++;
        fprintf(stderr, "[SPAWN-FINAL] frameFn=%u lastblk=0x%06X preTick=%u simtick=%u arrsched=%u create=%u | live objects=%u\n",
                g_spawnfn[1], g_frameblk, g_spawnfn[2], g_spawnfn[4], g_spawnfn[6], g_spawnfn[7], live); }
      fprintf(stderr, "[RENDCOUNT-FINAL]");
      for (int i = 0; i < 8; i++) fprintf(stderr, "  %s=%u", g_rcount_name[i], g_rcount[i]);
      fprintf(stderr, "\n"); fflush(stderr); }
    fprintf(stderr, "\n=== EXIT TRACE DUMP ===\n");
    fprintf(stderr, "Total ICALLs: %u, call depth: %u (max %u)\n",
            g_icall_count, g_call_depth, g_call_depth_max);
    fprintf(stderr, "ICALL trace (last %d):\n", ICALL_TRACE_SIZE);
    for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
        int idx = (g_icall_trace_idx + i) & (ICALL_TRACE_SIZE - 1);
        if (g_icall_trace[idx])
            fprintf(stderr, "  [%2d] 0x%08X\n", i, g_icall_trace[idx]);
    }
    fprintf(stderr, "ESP: 0x%08X (initial: 0x%08X)\n", g_esp, g_esp_initial);
    fflush(stderr);
}

/* Watchdog thread: dumps trace to file using raw Win32 API, then terminates */
/* XWA_PROFILE=<ms> -- sampling profiler. Suspends the guest thread every <ms>, reads EIP and
 * attributes it to a guest function via guest_func_for_host(). The trace ring only shows the
 * last 512 CALLS, which is useless when time is being burned INSIDE one long-running function
 * (or in host code); this shows where the time actually goes. Prints a top-15 every 10s. */
static HANDLE g_guest_thread = NULL;
#define PROF_SLOTS 4096
static struct { uint32_t gva; unsigned hits; } g_prof[PROF_SLOTS];
static unsigned g_prof_total, g_prof_host;

static void prof_record(uint32_t gva) {
    unsigned h = (gva * 2654435761u) & (PROF_SLOTS - 1);
    for (unsigned i = 0; i < PROF_SLOTS; i++) {
        unsigned k = (h + i) & (PROF_SLOTS - 1);
        if (g_prof[k].gva == gva) { g_prof[k].hits++; return; }
        if (g_prof[k].hits == 0) { g_prof[k].gva = gva; g_prof[k].hits = 1; return; }
    }
}

#define PROF_CHAINS 512
static struct { uint32_t a[4]; unsigned hits; } g_pchain[PROF_CHAINS];
static void prof_chain_record(const uint32_t *ch) {
    unsigned h = (ch[0] ^ ch[1] * 31u ^ ch[2] * 131u ^ ch[3] * 1031u) * 2654435761u & (PROF_CHAINS - 1), i;
    for (i = 0; i < PROF_CHAINS; i++) {
        unsigned k = (h + i) & (PROF_CHAINS - 1);
        if (g_pchain[k].hits && !memcmp(g_pchain[k].a, ch, 16)) { g_pchain[k].hits++; return; }
        if (!g_pchain[k].hits) { memcpy(g_pchain[k].a, ch, 16); g_pchain[k].hits = 1; return; }
    }
}
static void prof_chain_dump(void) {
    int rank;
    for (rank = 0; rank < 8; rank++) {
        unsigned best = 0; int bi = -1, i;
        for (i = 0; i < PROF_CHAINS; i++) if (g_pchain[i].hits > best) { best = g_pchain[i].hits; bi = i; }
        if (bi < 0) break;
        fprintf(stderr, "[PROFHOST] %6u  %08X <- %08X <- %08X <- %08X\n", best,
                g_pchain[bi].a[0], g_pchain[bi].a[1], g_pchain[bi].a[2], g_pchain[bi].a[3]);
        g_pchain[bi].hits = 0;
    }
    memset(g_pchain, 0, sizeof g_pchain);
}

static void prof_dump(void) {
    prof_chain_dump();
    { extern unsigned g_rcount[8]; extern const char* const g_rcount_name[8];
      if (getenv("XWA_RENDCOUNT")) { fprintf(stderr, "[RENDCOUNT]");
        for (int i = 0; i < 8; i++) fprintf(stderr, "  %s=%u", g_rcount_name[i], g_rcount[i]);
        fprintf(stderr, "\n"); } }
    fprintf(stderr, "[PROF] %u samples (%u unattributed)\n", g_prof_total, g_prof_host);
    for (int rank = 0; rank < 15; rank++) {
        unsigned best = 0; int bi = -1;
        for (int i = 0; i < PROF_SLOTS; i++) if (g_prof[i].hits > best) { best = g_prof[i].hits; bi = i; }
        if (bi < 0 || !best) break;
        fprintf(stderr, "[PROF]   %5.1f%%  %6u  sub_%08X\n",
                100.0 * best / (g_prof_total ? g_prof_total : 1), best, g_prof[bi].gva);
        g_prof[bi].hits = 0;   /* consume so the next rank surfaces */
    }
    fflush(stderr);
}

static DWORD WINAPI profiler_thread(LPVOID param) {
    DWORD period = (DWORD)(uintptr_t)param;
    /* this exe's image range, looked up here: doing it while the guest thread is suspended can
     * deadlock on the loader lock (it did -- the profiler and the game both stopped) */
    static uint32_t lo, hi;
    { MODULEINFO mi; if (GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof mi)) {
          lo = (uint32_t)(uintptr_t)mi.lpBaseOfDll; hi = lo + mi.SizeOfImage; } }
    extern uint32_t guest_func_for_host(uintptr_t host_addr);
    unsigned since_dump = 0;
    for (;;) {
        Sleep(period);
        if (!g_guest_thread) continue;
        if (SuspendThread(g_guest_thread) == (DWORD)-1) continue;
        CONTEXT c; c.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(g_guest_thread, &c)) {
            uint32_t gva = guest_func_for_host((uintptr_t)c.Eip);
            g_prof_total++;
            if (gva) prof_record(gva);
            else {
                /* In host code (a bridge, the runtime, a system DLL): charge the sample to the
                 * nearest lifted function on the stack, so a guest loop spinning on a mocked API
                 * shows up as that loop rather than as "unattributed". Tagged with bit 31. */
                /* Raw host chain: EIP plus the first three stack words that point into this exe's
                 * code. guest_func_for_host() maps any host address to the nearest lifted function
                 * below it, which mislabels native runtime code; symbolize these offline instead
                 * (llvm-symbolizer --obj=build-farm/xwa_recomp.exe <addr>). */
                const uint32_t* sp = (const uint32_t*)(uintptr_t)c.Esp; int k, nch = 1;
                uint32_t ch[4] = { (uint32_t)c.Eip, 0, 0, 0 };
                g_prof_host++;
                {   MEMORY_BASIC_INFORMATION smb; int lim = 0;
                    if (VirtualQuery((void*)sp, &smb, sizeof smb))
                        lim = (int)(((uintptr_t)smb.BaseAddress + smb.RegionSize - (uintptr_t)sp) / 4);
                    if (lim > 2048) lim = 2048;
                for (k = 0; k < lim && nch < 4; k++)
                    if (sp[k] > lo && sp[k] < hi && sp[k] != ch[nch - 1]) ch[nch++] = sp[k];
                }
                prof_chain_record(ch);
            }
        }
        ResumeThread(g_guest_thread);
        if (++since_dump >= (10000 / (period ? period : 1))) { since_dump = 0; prof_dump(); }
    }
    return 0;
}

static DWORD WINAPI watchdog_thread(LPVOID param) {
    DWORD timeout_ms = (DWORD)(uintptr_t)param;
    Sleep(timeout_ms);

    /* Use raw Win32 CreateFile to avoid CRT locking issues */
    HANDLE hFile = CreateFileA("xwa_watchdog.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        char buf[512];
        DWORD written;
        int len;

        len = snprintf(buf, sizeof(buf),
            "=== Watchdog dump after %u ms ===\r\n"
            "Total calls: %u, total icalls: %u, call_depth: %u (max: %u)\r\n"
            "EAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
            "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n"
            "trace_ring_idx=%u\r\n\r\n",
            timeout_ms,
            g_total_calls, g_total_icalls, g_call_depth, g_call_depth_max,
            g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi,
            g_trace_ring_idx);
        WriteFile(hFile, buf, len, &written, NULL);

        /* Dump trace ring */
        len = snprintf(buf, sizeof(buf), "=== Trace Ring (last %d) ===\r\n", TRACE_RING_SIZE);
        WriteFile(hFile, buf, len, &written, NULL);
        uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
        for (uint32_t i = start; i < g_trace_ring_idx; i++) {
            uint32_t idx = i & (TRACE_RING_SIZE - 1);
            if (g_trace_ring[idx][0]) {
                len = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                WriteFile(hFile, buf, len, &written, NULL);
            }
        }

        /* Dump ICALL trace */
        len = snprintf(buf, sizeof(buf), "\r\n=== ICALL Trace (last %d) ===\r\n", ICALL_TRACE_SIZE);
        WriteFile(hFile, buf, len, &written, NULL);
        for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
            uint32_t idx2 = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
            if (g_icall_trace[idx2]) {
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", i, g_icall_trace[idx2]);
                WriteFile(hFile, buf, len, &written, NULL);
            }
        }
        len = snprintf(buf, sizeof(buf), "Total indirect calls: %u\r\n", g_icall_count);
        WriteFile(hFile, buf, len, &written, NULL);

        CloseHandle(hFile);
    }

    /* TerminateProcess bypasses loader lock, unlike ExitProcess */
    TerminateProcess(GetCurrentProcess(), 42);
    return 0;
}

/* Forward declaration of the recompiled game entry points */
extern void sub_0050A4A0(void);  /* WinMain */
extern void sub_0059CD60(void);  /* CRT startup (calls WinMain internally) */

/* Import bridge registration (generated by gen_bridges.py) */
extern void register_import_bridges(void);

/* ============================================================
 * NtTerminateProcess Inline Hook
 *
 * Catches ALL process termination paths:
 *  - Our ExitProcess bridge (via TerminateProcess -> NtTerminateProcess)
 *  - Real ExitProcess calls from DLLs
 *  - Heap corruption handler (RtlReportCriticalFailure -> NtTerminateProcess)
 *  - Any other termination path
 *
 * Dumps the native callstack + recomp trace ring to a file.
 * ============================================================ */

typedef long NTSTATUS_T;
typedef NTSTATUS_T (NTAPI *PFN_NtTerminateProcess)(HANDLE, NTSTATUS_T);
static PFN_NtTerminateProcess g_real_NtTerminateProcess = NULL;
static uint8_t g_nttp_orig_bytes[16];
static volatile LONG g_terminate_hook_entered = 0;

/* Flag set by our ExitProcess bridge so hook knows it's a "known" exit */
volatile int g_exit_via_bridge = 0;

static void NTAPI hook_NtTerminateProcess(HANDLE hProcess, NTSTATUS_T exitStatus) {
    /* Signal on stderr FIRST (before any file I/O) */
    { extern volatile unsigned g_lastblk;
      fprintf(stderr, "=== TERMINATE CONTEXT === last guest block: L_%08X  guest esp=0x%08X\n", g_lastblk, g_esp);
      fprintf(stderr, "recent ICALLs:");
      for (int _i = 0; _i < 12; _i++) { unsigned _k = (g_icall_trace_idx - 1 - _i) & (ICALL_TRACE_SIZE - 1);
          fprintf(stderr, " 0x%08X", g_icall_trace[_k]); }
      fprintf(stderr, "\n"); fflush(stderr); }
    fprintf(stderr, "\n!!! NtTerminateProcess HOOKED: handle=0x%X status=0x%08X bridge=%d !!!\n",
        (uint32_t)(uintptr_t)hProcess, (uint32_t)exitStatus, g_exit_via_bridge);
    fflush(stderr);

    /* Prevent re-entrancy */
    if (InterlockedExchange(&g_terminate_hook_entered, 1)) {
        /* Re-entrant: restore original and call directly */
        DWORD oldProt;
        VirtualProtect((void*)g_real_NtTerminateProcess, 16, PAGE_EXECUTE_READWRITE, &oldProt);
        memcpy((void*)g_real_NtTerminateProcess, g_nttp_orig_bytes, 8);
        VirtualProtect((void*)g_real_NtTerminateProcess, 16, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), (void*)g_real_NtTerminateProcess, 16);
        g_real_NtTerminateProcess(hProcess, exitStatus);
        return;
    }

    /* Capture native call stack */
    void* bt[48];
    WORD nframes = CaptureStackBackTrace(0, 48, bt, NULL);

    /* Write diagnostics to file using raw Win32 API */
    HANDLE h = CreateFileA("xwa_terminate.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[512];
        int len;

        len = snprintf(buf, sizeof(buf),
            "=== NtTerminateProcess Hook ===\r\n"
            "Exit status: 0x%08X (%d)\r\n"
            "Handle: 0x%08X\r\n"
            "Via bridge: %s\r\n\r\n",
            (uint32_t)exitStatus, (int)exitStatus,
            (uint32_t)(uintptr_t)hProcess,
            g_exit_via_bridge ? "YES (known exit)" : "NO (unknown/unexpected)");
        wf(h, buf);

        /* Native call stack with module resolution */
        wf(h, "=== Native Call Stack ===\r\n");
        for (int i = 0; i < nframes; i++) {
            HMODULE hMod = NULL;
            char modName[260];
            if (GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    (LPCSTR)bt[i], &hMod)) {
                GetModuleFileNameA(hMod, modName, sizeof(modName));
                /* Extract just filename */
                char* slash = strrchr(modName, '\\');
                char* name = slash ? slash + 1 : modName;
                uint32_t offset = (uint32_t)((uint8_t*)bt[i] - (uint8_t*)hMod);
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%p  %s + 0x%X\r\n",
                    i, bt[i], name, offset);
            } else {
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%p  (unknown module)\r\n",
                    i, bt[i]);
            }
            wf(h, buf);
        }

        /* Recomp register state */
        len = snprintf(buf, sizeof(buf),
            "\r\n=== Recomp State ===\r\n"
            "EAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
            "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n"
            "Total calls: %u, icalls: %u, depth: %u (max: %u)\r\n"
            "trace_ring_idx: %u\r\n\r\n",
            g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi,
            g_total_calls, g_total_icalls, g_call_depth, g_call_depth_max,
            g_trace_ring_idx);
        wf(h, buf);

        /* Trace ring */
        wf(h, "=== Trace Ring ===\r\n");
        uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE)
            ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
        for (uint32_t i = start; i < g_trace_ring_idx; i++) {
            uint32_t idx = i & (TRACE_RING_SIZE - 1);
            if (g_trace_ring[idx][0]) {
                len = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                wf(h, buf);
            }
        }

        /* ICALL trace */
        wf(h, "\r\n=== ICALL Trace ===\r\n");
        for (int j = 0; j < ICALL_TRACE_SIZE; j++) {
            uint32_t idx2 = (g_icall_trace_idx - ICALL_TRACE_SIZE + j) & (ICALL_TRACE_SIZE - 1);
            if (g_icall_trace[idx2]) {
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", j, g_icall_trace[idx2]);
                wf(h, buf);
            }
        }
        len = snprintf(buf, sizeof(buf), "Total indirect calls: %u\r\n", g_icall_count);
        wf(h, buf);

        CloseHandle(h);
    }

    /* Restore original bytes and call real NtTerminateProcess */
    DWORD oldProt;
    VirtualProtect((void*)g_real_NtTerminateProcess, 16, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy((void*)g_real_NtTerminateProcess, g_nttp_orig_bytes, 8);
    VirtualProtect((void*)g_real_NtTerminateProcess, 16, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)g_real_NtTerminateProcess, 16);

    g_real_NtTerminateProcess(hProcess, exitStatus);
}

static void install_terminate_hook(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    g_real_NtTerminateProcess = (PFN_NtTerminateProcess)
        GetProcAddress(ntdll, "NtTerminateProcess");
    if (!g_real_NtTerminateProcess) return;

    /* Save original bytes */
    memcpy(g_nttp_orig_bytes, (void*)g_real_NtTerminateProcess, 16);

    /* Overwrite first 5 bytes with JMP rel32 to our hook */
    DWORD oldProt;
    VirtualProtect((void*)g_real_NtTerminateProcess, 16, PAGE_EXECUTE_READWRITE, &oldProt);

    uint8_t* p = (uint8_t*)g_real_NtTerminateProcess;
    p[0] = 0xE9; /* JMP rel32 */
    uint32_t target = (uint32_t)(uintptr_t)&hook_NtTerminateProcess;
    uint32_t src = (uint32_t)(uintptr_t)p + 5;
    *(uint32_t*)(p + 1) = target - src;

    VirtualProtect((void*)g_real_NtTerminateProcess, 16, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)g_real_NtTerminateProcess, 16);

    printf("[*] NtTerminateProcess hook installed at %p\n", (void*)g_real_NtTerminateProcess);
}

FILE* g_trace_file = NULL;
char g_trace_ring[TRACE_RING_SIZE][TRACE_ENTRY_SIZE] = {{0}};
uint32_t g_trace_ring_idx = 0;

int main(int argc, char* argv[]) {
    g_blocktrace = getenv("XWA_BLOCKTRACE") ? 1 : 0;
    /* Record our own module's image range so LINK_OK can exclude it (see recomp_types.h). */
    { HMODULE _h = GetModuleHandleA(NULL);
      if (_h) { IMAGE_DOS_HEADER* _d = (IMAGE_DOS_HEADER*)_h;
                IMAGE_NT_HEADERS* _n = (IMAGE_NT_HEADERS*)((char*)_h + _d->e_lfanew);
                g_hostmod_lo = (uint32_t)(uintptr_t)_h;
                g_hostmod_hi = g_hostmod_lo + _n->OptionalHeader.SizeOfImage; } }
    setvbuf(stderr, NULL, _IONBF, 0); /* Force unbuffered stderr */
    /* Trace ring buffer is in-memory, dumped by watchdog thread */
    printf("=== X-Wing Alliance Static Recompilation ===\n");
    printf("=== Phase 2: Recompilation Infrastructure  ===\n\n");

    /* Default path to original binary for data loading */
    const char* data_file = NULL;
    if (argc > 1) {
        data_file = argv[1];
    }

    /* Install NtTerminateProcess hook FIRST (catches all exit paths) */
    install_terminate_hook();

    /* Hang watchdog (opt-in): periodically dumps the trace ring so a hang is diagnosable. */
    if (getenv("XWA_WATCHDOG")) {
        CreateThread(NULL, 0, watchdog_loop_thread, NULL, 0, NULL);
        printf("[*] hang watchdog started -> xwa_watchdog.log\n");
    }

    /* Install VEH crash handler */
    AddVectoredExceptionHandler(1, veh_handler);

    /* Install UEF (Unhandled Exception Filter) as backup crash catcher */
    SetUnhandledExceptionFilter(veh_handler);

    printf("[*] VEH + UEF crash handler installed\n");
    xwa_arm_watch();

    /* Set up memory layout */
    if (!setup_memory(data_file)) {
        fprintf(stderr, "FATAL: Memory setup failed\n");
        return 1;
    }
    printf("[*] Memory layout initialized\n");
    printf("    Region: %p (VA 0x%08X - 0x%08X)\n",
           g_region_alloc, XWA_REGION_START, XWA_REGION_END);
    printf("    Stack:  VA 0x%08X - 0x%08X (ESP = 0x%08X)\n",
           XWA_STACK_BASE, XWA_STACK_TOP, g_esp);
    printf("    Data:   VA 0x%08X - 0x%08X (extended to 0x%08X)\n",
           XWA_DATA_START, XWA_DATA_END, XWA_EXTENDED_END);
    printf("    Offset: %lld\n", (long long)g_mem_base);

    /* Register import bridges (maps IAT slots to bridge functions) */
    register_import_bridges();

    /* Initialize COM mock interfaces (DirectDraw, Direct3D, DirectInput, DirectSound) */
    {
        extern void com_mocks_init(void);
        com_mocks_init();
    }

    /* Increase Windows timer resolution to 1ms (from default 15.6ms).
     * Critical for GetTickCount precision and Sleep(1) accuracy.
     * The original game ran on Win98/2000 which had ~1ms timer resolution. */
    timeBeginPeriod(1);

    printf("\n[*] XWA recomp infrastructure ready.\n");
    printf("[*] Dispatch table: %u functions\n", recomp_dispatch_count);

    if (!data_file) {
        printf("[*] To run game: pass path to xwingalliance.exe as argument\n");
        cleanup_memory();
        return 0;
    }

    /*
     * Call WinMain directly, bypassing the original CRT startup.
     * The VC6 CRT startup (sub_0059CD60) initializes the C runtime heap,
     * stdio, SEH, etc. - but those are already provided by our real CRT.
     * The original CRT's heap metadata in .data points to addresses that
     * don't exist in our process, causing crashes.
     *
     * WinMain(hInstance, hPrevInstance=NULL, lpCmdLine, nCmdShow=SW_SHOWDEFAULT)
     * Args pushed right-to-left on simulated stack.
     */
    /* Mask ALL x87/SSE floating-point exceptions before entering the guest. The original
     * runs with control word 0x037F (every exception masked), so an invalid op or a divide
     * by zero quietly yields NaN/INF there. In this process they were being RAISED instead:
     * flight entry died with STATUS_FLOAT_INVALID_OPERATION (0xC0000090) at FLIGHT INIT in
     * 6 of 6 runs. Trapping is still available on demand via XWA_FPTRAP. */
    if (!getenv("XWA_FPTRAP")) {
        unsigned _fpcur = 0;
        _controlfp_s(&_fpcur, _MCW_EM, _MCW_EM);
        fprintf(stderr, "[FP] all FP exceptions masked (cw now 0x%X)\n", _fpcur);
        fflush(stderr);
    }

    /* XWA_HW3D: 0xB0C7BC is the MASTER hardware-3D switch. sub_00526D00 is literally
     * `return MEM32(0xB0C7BC)`, and sub_0050C640 stores that result into 0x77330C at
     * 0x0050C6E2; sub_00489310 then reads 0x77330C and, when it is 0, logs "RIGGED FOR
     * SOFTWARE RENDERING". So this one byte decides the whole renderer path. Setting it
     * BEFORE the guest starts lets the engine take the hardware route coherently, instead of
     * re-enabling 3D midway and leaving half-initialised globals (#452). */
    /* Dump the two string constants the hardware-3D selector compares against (#453). The image
     * is loaded by now, so these are readable here even though the guest routine may not run. */
    if (getenv("XWA_HWSTR")) {
        uint32_t addrs[2] = { 0x006012A0u, 0x006012A8u };
        for (int i = 0; i < 2; i++) {
            char b[64]; int k;
            for (k = 0; k < 63; k++) { uint8_t c = MEM8(addrs[i] + k);
                b[k] = (c >= 32 && c < 127) ? (char)c : 0; if (!c) break; }
            b[k] = 0;
            fprintf(stderr, "[HWSTR] 0x%06X = '%s'\n", addrs[i], b);
        }
        fflush(stderr);
    }
    if (getenv("XWA_HW3D")) {
        MEM8(0xB0C7BCu) = 1;
        fprintf(stderr, "[HW3D] master hardware-3D switch 0xB0C7BC = 1 (pre-guest)\n");
        fflush(stderr);
    }

    HINSTANCE hInst = GetModuleHandleA(NULL);
    LPSTR cmdLine = GetCommandLineA();

    /* Store command line string in mapped memory so game code can access it */
    uint32_t cmdline_va = XWA_DATA_END - 0x400;  /* use end of data region as scratch */
    strncpy((char*)ADDR(cmdline_va), cmdLine, 0x3FF);
    ((char*)ADDR(cmdline_va))[0x3FF] = '\0';

    g_esp_initial = g_esp;
    g_esp_min = g_esp;

    /* Disable VC6 small-block heap (SBH) - route all malloc to HeapAlloc.
     * We bypassed the CRT startup (_heap_init, __sbh_heap_init) which would
     * normally initialize the SBH lock table. Without it, _lock(9) tries to
     * lazily allocate a CRITICAL_SECTION via malloc, which re-enters the SBH
     * path and creates infinite recursion. Setting __sbh_threshold to 0 forces
     * _heap_alloc_base to use the HeapAlloc fallback for all sizes. */
    MEM32(0x60DC1C) = 0;  /* Disable SBH - force HeapAlloc for all sizes */

    /* Initialize CRT heap handle to our process heap */
    MEM32(0xB0E828) = (uint32_t)(uintptr_t)GetProcessHeap();

    /* Pre-initialize CRT lock table at 0x60B1C8 + locknum*4.
     * VC6 CRT _lock() lazily allocates CRITICAL_SECTION structs and
     * recursively calls _lock(0x11) to protect the allocation. Without
     * pre-initialized locks, this creates infinite recursion.
     * Lock 0x11 (heap lock) must be initialized first. */
    {
        #define CRT_MAX_LOCKS 36
        static CRITICAL_SECTION crt_locks[CRT_MAX_LOCKS];
        for (int i = 0; i < CRT_MAX_LOCKS; i++) {
            InitializeCriticalSection(&crt_locks[i]);
            MEM32(i * 4 + 0x60B1C8) = (uint32_t)(uintptr_t)&crt_locks[i];
        }
        printf("[*] Pre-initialized %d CRT locks\n", CRT_MAX_LOCKS);
    }

    /* Initialize the CRT ctype table pointers for the "C" locale.
     * ROOT-CAUSE FIX: _pctype (0x60ACE8) and its sibling (0x60ACEC) ship in
     * .data with a STALE baked-in value (0x039A124A) that the real CRT startup
     * would overwrite. Because we bypass that startup, every ctype lookup
     * (isspace/isdigit via `MEM8(MEM32(0x60ACE8) + c*2)`) dereferenced that
     * garbage and crashed — in atol/setlocale, _output (printf), _input
     * (scanf), etc. The CRT's C-locale path (sub_005A1560 @0x005A1629) points
     * both at the static ctype table at 0x60ACF2; replicate that here.
     * 0x60AEF4 (__mb_cur_max) is already 1 (single-byte) in .data. */
    MEM32(0x60ACE8) = 0x0060ACF2u;
    MEM32(0x60ACEC) = 0x0060ACF2u;
    MEM32(0x60AEF4) = 1;
    printf("[*] Initialized C-locale ctype table (_pctype -> 0x60ACF2)\n");

    /* Verify data section loaded correctly */
    printf("[*] Data check: 0x5FFEEC = \"%s\"\n", (char*)ADDR(0x5FFEEC));
    printf("[*] Data check: 0x5FFEE4 = \"%s\"\n", (char*)ADDR(0x5FFEE4));
    printf("[*] Data check: 0x631860 = \"%s\"\n", (char*)ADDR(0x631860));

    /* Note: DirectDraw/rendering function pointers in BSS (e.g. 0x80DB6C,
     * 0x7FFD70) are NULL until DirectX init. RECOMP_ICALL(0) handles this
     * as a no-op that returns 0 in eax. */

    printf("[*] Launching CRT startup (sub_0059CD60)...\n");
    printf("    (will call WinMain internally after CRT init)\n");
    fflush(stdout);

    /* Register trace dump for when program exits */
    xwa_pcring_watch();
    atexit(dump_trace_atexit);

    /* FLS callback: called during process exit even if atexit doesn't run.
     * This catches exit paths that bypass our ExitProcess bridge. */
    {
        DWORD flsIdx = FlsAlloc(NULL);
        if (flsIdx != FLS_OUT_OF_INDEXES) {
            /* Store a sentinel value so the FLS slot is "active" */
            FlsSetValue(flsIdx, (PVOID)1);
        }
    }

    /* Register a _onexit callback (MSVC-specific, runs during _exit too) */
    _onexit((_onexit_t)dump_trace_atexit);

    /* Watchdog: dumps the trace ring then TerminateProcess(42). It fired unconditionally at
     * 5 minutes, which silently killed long flight runs (the mission texture upload alone
     * takes ~4 min) and looked like the game quitting on its own. Configurable now:
     * XWA_WATCHDOG_MS=<ms>, and 0 disables it. */
    { const char* pr = getenv("XWA_PROFILE");
      if (pr) {
          DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                          &g_guest_thread, 0, FALSE, DUPLICATE_SAME_ACCESS);
          unsigned long ms = strtoul(pr, NULL, 0); if (!ms) ms = 50;
          CreateThread(NULL, 0, profiler_thread, (LPVOID)(uintptr_t)ms, 0, NULL);
          fprintf(stderr, "[*] sampling profiler every %lu ms\n", ms);
      } }
    { const char* wd = getenv("XWA_WATCHDOG_MS");
      unsigned long wd_ms = wd ? strtoul(wd, NULL, 0) : 300000;
      if (wd_ms) CreateThread(NULL, 0, watchdog_thread, (LPVOID)(uintptr_t)wd_ms, 0, NULL);
      else fprintf(stderr, "[*] watchdog disabled (XWA_WATCHDOG_MS=0)\n"); }

    /* Call the CRT entry point (WinMainCRTStartup / mainCRTStartup).
     * This handles all CRT initialization: _heap_init, _mtinit, _ioinit,
     * __initterm, then calls WinMain(GetModuleHandle(0), 0, GetCommandLineA(), SW_SHOWDEFAULT).
     * It may call ExitProcess() instead of returning. */
    /* Default: call WinMain (sub_0050A4A0) directly, bypassing the guest CRT
     * startup (sub_0059CD60). The full CRT startup crashes in its locale/env
     * init (atol on a garbage env pointer, sub_005A89A0) before ever reaching
     * WinMain. The CRT globals the game actually needs (SBH off, heap handle,
     * CRT lock table) are already initialized manually above, so the direct
     * path boots to the concourse. Set XWA_FULL_CRT=1 to run the guest CRT
     * startup instead (for debugging that path).
     * WinMain(hInstance, hPrevInstance=0, lpCmdLine, nCmdShow=SW_SHOWDEFAULT),
     * args pushed right-to-left; RECOMP_CALL pushes the return address. */
    int full_crt = getenv("XWA_FULL_CRT") ? 1 : 0;
    fprintf(stderr, "[*] Entering game via %s...\n",
            full_crt ? "sub_0059CD60 (full CRT startup)" : "sub_0050A4A0 (WinMain, direct)");
    fflush(stderr);

    /* Wrap in SEH to catch crashes that VEH might miss */
    {
        DWORD seh_code = 0;
        __try {
            if (full_crt) {
                PUSH32(g_esp, 0xDEAD0000u);        /* dummy return address */
                sub_0059CD60();
            } else {
                PUSH32(g_esp, 0xAu);                              /* nCmdShow = SW_SHOWDEFAULT */
                PUSH32(g_esp, cmdline_va);                        /* lpCmdLine */
                PUSH32(g_esp, 0u);                                /* hPrevInstance */
                PUSH32(g_esp, (uint32_t)(uintptr_t)hInst);        /* hInstance */
                PUSH32(g_esp, 0xDEAD0000u);                       /* return address */
                sub_0050A4A0();
            }
        } __except((seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
            /* Dump trace ring on any unhandled exception */
            char buf[512];
            DWORD written;
            HANDLE h = CreateFileA("xwa_seh_crash.log",
                GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                int len = snprintf(buf, sizeof(buf),
                    "=== SEH CRASH: Exception 0x%08lX ===\r\n"
                    "Total calls: %u, icalls: %u, depth: %u (max: %u)\r\n"
                    "EAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
                    "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n"
                    "trace_ring_idx: %u\r\n\r\n",
                    seh_code, g_total_calls, g_total_icalls, g_call_depth, g_call_depth_max,
                    g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi,
                    g_trace_ring_idx);
                WriteFile(h, buf, len, &written, NULL);

                wf(h, "=== Trace Ring ===\r\n");
                uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
                for (uint32_t i = start; i < g_trace_ring_idx; i++) {
                    uint32_t idx = i & (TRACE_RING_SIZE - 1);
                    if (g_trace_ring[idx][0]) {
                        len = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                        WriteFile(h, buf, len, &written, NULL);
                    }
                }

                wf(h, "\r\n=== ICALL Trace ===\r\n");
                for (int j = 0; j < ICALL_TRACE_SIZE; j++) {
                    uint32_t idx2 = (g_icall_trace_idx - ICALL_TRACE_SIZE + j) & (ICALL_TRACE_SIZE - 1);
                    if (g_icall_trace[idx2]) {
                        len = snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", j, g_icall_trace[idx2]);
                        WriteFile(h, buf, len, &written, NULL);
                    }
                }
                CloseHandle(h);
            }
            fprintf(stderr, "\n!!! SEH CRASH: Exception 0x%08lX\n", seh_code);
            { extern volatile unsigned g_lastblk;
              if (g_lastblk) fprintf(stderr, "!!! last instrumented block: L_%08X\n", g_lastblk); }
            fprintf(stderr, "Total calls: %u, depth: %u, trace_idx: %u\n",
                    g_total_calls, g_call_depth, g_trace_ring_idx);
            { extern volatile unsigned g_fgbase, g_fgtblptr, g_fgrec, g_fgro;
              if (g_fgbase) fprintf(stderr, "!!! FG walk: base=0x%08X tblptr=0x%08X %s\n",
                  g_fgbase, g_fgtblptr, (g_fgbase==g_fgtblptr)?"SAME":"DIFFERENT"); }
            { extern volatile unsigned g_obj, g_objro, g_objtag;
              if (g_obj) fprintf(stderr, "!!! walked obj: ecx=0x%08X ro=0x%08X type=0x%04X\n",
                  g_obj, g_objro, g_objtag); }
            { extern volatile unsigned g_edxcap, g_edxval;
              fprintf(stderr, "!!! slot read: edx=0x%08X value=0x%08X\n", g_edxcap, g_edxval); }

            { extern volatile unsigned g_s1, g_s2, g_s3, g_smark;
              if (g_smark == 0x5CA9u) fprintf(stderr, "!!! strscan: esi=0x%08X tblbase=0x%08X eax=%u\n", g_s1, g_s2, g_s3); }            { extern volatile unsigned g_cw[3], g_w1, g_w2;
              fprintf(stderr, "!!! init counts @fault: loader_457C20=%u sub_458DC0=%u builder_41EF60=%u | str_462BE0=%u str_464A20=%u\n",
                  g_cw[0], g_cw[1], g_cw[2], g_w1, g_w2); }
            { extern volatile unsigned g_ldrblk;
              if (g_ldrblk) fprintf(stderr, "!!! loader last block: L_%08X\n", g_ldrblk); }

            { extern volatile unsigned g_after1, g_after2, g_aftermark;
              if (g_aftermark == 0xA57Eu) fprintf(stderr, "!!! slots right after loader: [0]=0x%08X [1]=0x%08X\n", g_after1, g_after2);
              else fprintf(stderr, "!!! post-loader sample NEVER RAN\n"); }            fflush(stderr);

            { extern volatile unsigned g_strblk;
              if (g_strblk) fprintf(stderr, "!!! sub_00462BE0 last block: L_%08X\n", g_strblk); }        }

            { extern volatile unsigned g_al1,g_al2,g_al3,g_almark;
              if (g_almark == 0xA110u) fprintf(stderr, "!!! alloc blk RAN: ret=0x%08X sibling(0x68C898)=0x%08X size(0x5A9698)=%u\n", g_al1,g_al2,g_al3);
              else fprintf(stderr, "!!! alloc blk L_00463C21 NEVER RAN (branch skipped it)\n"); }    }

            { extern volatile unsigned g_g1,g_g2,g_g3,g_g4,g_gmark;
              if (g_gmark == 0x6C1Du) fprintf(stderr, "!!! GetCraftPointer: idxoff=0x%X (idx=%u) base=0x%08X fgfillbase=0x%08X %s ro=0x%08X\n",
                  g_g1, g_g1/0x27u, g_g2, g_g3, (g_g2==g_g3)?"SAME":"DIFFERENT", g_g4);
              else fprintf(stderr, "!!! GetCraftPointer capture NEVER RAN\n"); }

            { extern volatile unsigned g_scmark;
              fprintf(stderr, "!!! scene-render site 0x005110FB: %s\n", (g_scmark==0x5CE7u)?"REACHED":"NEVER REACHED"); }    fprintf(stderr, "[*] game entry returned! eax = 0x%08X\n", g_eax);

    { extern volatile unsigned g_fltblk;
      if (g_fltblk) fprintf(stderr, "[EXIT] sub_005710F0 last block: L_%08X\n", g_fltblk); fflush(stderr); }

    { extern volatile unsigned g_wb1,g_wb2,g_wbmark;
      if (g_wbmark == 0x0B1D) fprintf(stderr, "[WORLDBUILD] CALLED (pre=%u) returned=%d\n", g_wb1, (int)g_wb2-1);
      else fprintf(stderr, "[WORLDBUILD] call site NEVER REACHED\n"); fflush(stderr); }    { extern volatile unsigned g_scblk, g_sc[2];

    { extern volatile unsigned g_wbblk;
      if (g_wbblk) fprintf(stderr, "[WBBLK] sub_0050A7E0 last block: L_%08X\n", g_wbblk); fflush(stderr); }      fprintf(stderr, "[EXIT] sub_00564D10 calls=%u last block=L_%08X\n", g_sc[0], g_scblk); fflush(stderr); }

    { extern volatile unsigned g_sel,g_selmark;
      if (g_selmark==0x5E1E) fprintf(stderr, "[SELECTOR] MEM8(0xB0C7D6) = %u\n", g_sel);
      else fprintf(stderr, "[SELECTOR] site never reached\n"); fflush(stderr); }
    { extern volatile unsigned g_af1; fprintf(stderr, "[AFC0] sub_0049AFC0 entries = %u\n", g_af1); fflush(stderr); }

    { extern volatile unsigned g_afblk; if (g_afblk) fprintf(stderr, "[AFBLK] sub_0049AFC0 last block: L_%08X\n", g_afblk); fflush(stderr); }            { extern volatile unsigned g_p1,g_p2,g_p3,g_pmark;
              if (g_pmark==0x0BA1u) fprintf(stderr, "!!! palette call: edx=0x%08X *edx=0x%08X esi=0x%08X\n", g_p1,g_p2,g_p3);
              else fprintf(stderr, "!!! palette capture NEVER RAN\n"); }    fflush(stderr);

            { extern volatile unsigned g_r1,g_r2,g_rmark;
              if (g_rmark==0x00E5u) fprintf(stderr, "!!! resource slot: ecx=0x%X (idx=%u) entry=0x%08X\n", g_r1, g_r1/4u, g_r2); }    printf("[*] WinMain returned (eax = 0x%08X)\n", g_eax);

            { extern volatile unsigned g_rw[4], g_rwidx[4]; int _k;
              fprintf(stderr, "!!! registry writers:");
              for (_k=0;_k<4;_k++) fprintf(stderr, " [%d]=%u(lastidx=%u)", _k, g_rw[_k], g_rwidx[_k]/4u);
              fprintf(stderr, "\n"); }
            { extern volatile unsigned g_setup[4];
              fprintf(stderr, "!!! setup fns: 0050E5C0=%u 0050EC00=%u 0050FBE0=%u 0050FC50=%u | 7825E8=0x%X 773310=0x%X\n",
                  g_setup[0],g_setup[1],g_setup[2],g_setup[3], MEM32(0x7825E8u), MEM32(0x773310u)); }
            { extern volatile unsigned g_dd[2];
              fprintf(stderr, "!!! ddraw setup: sub_0050C640=%u sub_0050C6F0=%u\n", g_dd[0], g_dd[1]); }
            { extern volatile unsigned g_sd[4];
              fprintf(stderr, "!!! screen-shutdown callers: 52BC00=%u 53E340=%u 53E6C0=%u 53E760=%u\n",
                  g_sd[0],g_sd[1],g_sd[2],g_sd[3]); }
            { extern volatile unsigned g_fl[2], g_flmark;
              fprintf(stderr, "!!! flight sets 0x9F701E: mark=0x%X  @0x57136A=%u  @0x571540=%u | current 9F701E=%u\n",
                  g_flmark, g_fl[0], g_fl[1], MEM32(0x9F701Eu)); }
            { extern volatile unsigned g_sc[2];
              fprintf(stderr, "!!! screen-layer: sub_00564D10=%u sub_00574CE0=%u\n", g_sc[0], g_sc[1]); }
            { extern volatile unsigned g_scblk;
              if (g_scblk) fprintf(stderr, "!!! sub_00564D10 last block: L_%08X\n", g_scblk); }
            { extern volatile unsigned g_ctxblk;
              if (g_ctxblk) fprintf(stderr, "!!! sub_00441EE0 last block: L_%08X\n", g_ctxblk); }

            { extern volatile unsigned g_t1,g_t2,g_t3,g_t4,g_tmark;
              if (g_tmark==0x7E10u) fprintf(stderr, "!!! TEX flag: cfg(eax)=%d edi=%d -> idx=%d  table[0]=%u table[1]=%u  set=%u\n",
                  (int)g_t1,(int)g_t2,(int)g_t1>(int)g_t2?1:0, g_t3&0xFF, (g_t3>>8)&0xFF, g_t4);
              else fprintf(stderr, "!!! TEX capture NEVER RAN\n"); }    cleanup_memory();

            { extern volatile unsigned g_dv1,g_dv2,g_dv3,g_dvmark;
              if (g_dvmark==0x0DE7u) fprintf(stderr, "!!! device record: idx=%u rec=0x%08X dword0=0x%08X\n", g_dv1,g_dv2,g_dv3);
              else fprintf(stderr, "!!! device-record capture NEVER RAN\n"); }    return 0;
}
