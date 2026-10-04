/*
 * COM Mock Infrastructure for DirectX Interfaces
 *
 * Mock COM objects for DirectDraw, Direct3D, DirectInput, DirectSound.
 * Each interface gets a vtable filled with 0xBBxxxxxx marker addresses,
 * which are registered as import bridges so RECOMP_ICALL can dispatch them.
 *
 * COM methods are stdcall: callee pops args. Each bridge reads args from
 * the simulated stack (g_esp), sets g_eax to the return value, and
 * adjusts g_esp to pop ret addr + args.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>   /* getenv (heap_check gate) */

extern unsigned int g_total_calls;
extern unsigned int g_total_icalls;

static int g_heap_check_count = 0;
static int g_heap_corrupt = 0;
static void heap_check(const char* where) {
    /* HeapValidate walks EVERY block of EVERY process heap, and this ran on every single
     * COM_LOG call. Once the D3D path works the game allocates thousands of texture
     * surfaces, making this quadratic -- texture upload crawled at ~47 surfaces/sec.
     * It is a debug instrument for a corruption hunt, so make it opt-in. */
    static int on = -1;
    if (on < 0) on = getenv("XWA_HEAPCHECK") ? 1 : 0;
    if (!on) return;
    g_heap_check_count++;
    if (g_heap_corrupt) return;

    /* Check ALL heaps in the process */
    HANDLE heaps[32];
    DWORD nheaps = GetProcessHeaps(32, heaps);
    for (DWORD i = 0; i < nheaps && i < 32; i++) {
        if (!HeapValidate(heaps[i], 0, NULL)) {
            g_heap_corrupt = 1;
            char buf[256];
            int n = wsprintfA(buf, "[HEAP] CORRUPTION in heap %d/%d (0x%08X) at %s (check #%d, call #%u, icall #%u)\r\n",
                             i, nheaps, (unsigned int)(uintptr_t)heaps[i],
                             where, g_heap_check_count, g_total_calls, g_total_icalls);
            DWORD written;
            WriteFile(GetStdHandle(STD_ERROR_HANDLE), buf, n, &written, NULL);
            break;
        }
    }
}

/* Wrapper: check heap then fprintf */
#define COM_LOG(...) do { \
    heap_check("COM_LOG"); \
    if (!g_heap_corrupt) fprintf(stderr, __VA_ARGS__); \
} while(0)
#include <stdlib.h>
#include <string.h>
#include "recomp/recomp_types.h"
#include "com_mocks.h"
#include "d3d11_renderer.h"

/* Import bridge table (defined in main.c) */
extern recomp_dispatch_entry_t g_import_bridges[];
extern int g_import_bridge_count;

/* Dispatch lookup functions (defined in main.c / dispatch table) */
extern recomp_func_t recomp_lookup_manual(uint32_t va);
extern recomp_func_t recomp_lookup(uint32_t va);
extern recomp_func_t recomp_lookup_import(uint32_t va);
extern int recomp_native_call(uint32_t va);

/* Helper: dispatch an indirect call to a recompiled function.
 * The caller must have already pushed args + a dummy return address. */
void com_dispatch_callback(uint32_t va);
void com_dispatch_callback(uint32_t va) {
    recomp_func_t fn = recomp_lookup_manual(va);
    if (!fn) fn = recomp_lookup(va);
    if (!fn) fn = recomp_lookup_import(va);
    if (fn) {
        fn();
    } else if (!recomp_native_call(va)) {
        COM_LOG("[COM] WARNING: unresolved callback 0x%08X\n", va);
    }
}

/* Helper to register a COM vtable bridge */
static void register_bridge(uint32_t marker, recomp_func_t func) {
    int idx = g_import_bridge_count++;
    g_import_bridges[idx].address = marker;
    g_import_bridges[idx].func = func;
}

/* ============================================================
 * Mock Object Allocation
 *
 * COM objects are allocated from a DEDICATED heap created above
 * the extended BSS end (0x02000000+) to avoid heap metadata
 * corruption from game BSS writes.
 * ============================================================ */

static HANDLE g_com_heap = NULL;

static void* com_alloc(size_t size) {
    if (!g_com_heap) {
        g_com_heap = HeapCreate(0, 0x10000, 0);
        if (!g_com_heap) {
            COM_LOG("[COM] FATAL: failed to create COM heap\n");
            return NULL;
        }
        COM_LOG("[COM] Created dedicated COM heap at %p\n", (void*)g_com_heap);
    }
    return HeapAlloc(g_com_heap, HEAP_ZERO_MEMORY, size);
}

/* Allocate a vtable (array of uint32_t marker values) */
static uint32_t alloc_vtable(const uint32_t* markers, int count) {
    uint32_t* vtbl = (uint32_t*)com_alloc(count * 4);
    for (int i = 0; i < count; i++)
        vtbl[i] = markers[i];
    return (uint32_t)(uintptr_t)vtbl;
}

/* Allocate a mock COM object */
static mock_com_obj_t* alloc_mock(uint32_t tag, uint32_t vtable_addr) {
    mock_com_obj_t* obj = (mock_com_obj_t*)com_alloc(sizeof(mock_com_obj_t));
    obj->lpVtbl = vtable_addr;
    obj->refcount = 1;
    obj->tag = tag;
    return obj;
}

/* ============================================================
 * Marker Ranges
 *
 * 0xBB001000-0xBB00101F  IDirectDraw (32 slots)
 * 0xBB001020-0xBB00103F  IDirectDrawSurface (32 slots)
 * 0xBB001040-0xBB00105F  IDirectDrawPalette (16 slots)
 * 0xBB001060-0xBB00107F  IDirect3D (16 slots)
 * 0xBB001080-0xBB00109F  IDirect3DDevice (32 slots)
 * 0xBB0010A0-0xBB0010BF  IDirect3DViewport (32 slots)
 * 0xBB0010C0-0xBB0010DF  IDirect3DExecuteBuffer (16 slots)
 * 0xBB001100-0xBB00111F  IDirectInput (16 slots)
 * 0xBB001120-0xBB00113F  IDirectInputDevice (32 slots)
 * 0xBB001140-0xBB00115F  IDirectSound (16 slots)
 * 0xBB001160-0xBB00117F  IDirectSoundBuffer (32 slots)
 * 0xBB001180-0xBB00119F  IDirect3DTexture (16 slots)
 * ============================================================ */

#define MK_DD       0xBB001000
#define MK_DDS      0xBB001020
#define MK_DDP      0xBB001040
#define MK_D3D      0xBB001060
#define MK_D3DDEV   0xBB001080
#define MK_D3DVP    0xBB0010A0
#define MK_D3DEB    0xBB0010C0
#define MK_DI       0xBB001100
#define MK_DIDEV    0xBB001120
#define MK_DS       0xBB001140
#define MK_DSB      0xBB001160
#define MK_D3DTEX   0xBB001180
static uint32_t g_eb_data, g_eb_size;
static int g_eb_count;
uint32_t g_eb_obj[4];
#define MK_DPLAY    0xBB0011A0   /* IDirectPlay4 (64 slots) */

/* ============================================================
 * Forward declarations for all mock objects
 * ============================================================ */
static uint32_t g_ddraw_vtable_addr;
static uint32_t g_ddsurface_vtable_addr;
static uint32_t g_ddpalette_vtable_addr;
static uint32_t g_d3d_vtable_addr;
static uint32_t g_d3ddevice_vtable_addr;
static uint32_t g_d3dviewport_vtable_addr;
static uint32_t g_d3dexecbuf_vtable_addr;
static uint32_t g_dinput_vtable_addr;
static uint32_t g_didevice_vtable_addr;
static uint32_t g_dsound_vtable_addr;
static uint32_t g_dsbuffer_vtable_addr;
static uint32_t g_d3dtexture_vtable_addr;
static uint32_t g_dplay_vtable_addr;

/* ============================================================
 * DirectInput State Tracking
 * ============================================================ */

/* Device types stored in mock_com_obj_t.extra[2] */
#define DIDEV_TYPE_UNKNOWN   0
#define DIDEV_TYPE_KEYBOARD  1
#define DIDEV_TYPE_MOUSE     2
#define DIDEV_TYPE_JOYSTICK  3

/* VK-to-DIK scancode mapping table (built once) */
static uint8_t g_vk_to_dik[256];
static int g_vk_to_dik_initialized = 0;

static void init_vk_to_dik_table(void) {
    if (g_vk_to_dik_initialized) return;
    memset(g_vk_to_dik, 0, sizeof(g_vk_to_dik));
    for (int vk = 0; vk < 256; vk++) {
        UINT sc = MapVirtualKeyA(vk, 0 /* MAPVK_VK_TO_VSC */);
        if (sc > 0 && sc < 256)
            g_vk_to_dik[vk] = (uint8_t)sc;
    }
    g_vk_to_dik_initialized = 1;
}

/* Mouse state for relative movement tracking */
static POINT g_mouse_last_pos = { 0, 0 };
static int g_mouse_tracking = 0;
static LONG g_mouse_dx = 0;
static LONG g_mouse_dy = 0;

/* Pixel buffer for surfaces (640x480x2 = 614400 bytes).
 * SURFACE_BUF_SIZE is the *reported* size; the actual allocation adds a generous
 * guard margin (SURFACE_GUARD) so the game's direct surface writes (it caches the
 * pixel pointer at 0x6002BC and renders straight into it) can never overrun into
 * heap metadata if its stride math disagrees with ours. A sentinel at the guard
 * boundary lets us detect and measure any real overrun. */
#define SURFACE_BUF_SIZE (640 * 480 * 2)
#define SURFACE_GUARD    (4 * 1024 * 1024)
#define SURFACE_SENTINEL 0xA5
static uint8_t* g_surface_buffer = NULL;
static uint8_t* g_backbuf_buffer = NULL;

/* Allocate a surface backing store of `size` reported bytes + guard headroom,
 * stamping a sentinel byte across the guard region so overruns are detectable. */
static uint8_t* alloc_surface_buf(uint32_t size) {
    /* The 4MB guard exists for the FRAMEBUFFER-class surfaces: the game caches their pixel
     * pointer (0x6002BC) and renders straight into it, so a stride disagreement must not
     * reach heap metadata. Texture surfaces are never written that way -- and once the D3D
     * device actually works the game allocates hundreds of small mipmap surfaces (32x16,
     * 16x8, 8x64...). At 4MB of guard each that exhausted the heap by surface ~354, after
     * which HeapAlloc returned NULL and the game wrote through a null pixel pointer.
     * Scale the guard to the surface instead. */
    uint32_t guard = (size >= 256 * 1024) ? SURFACE_GUARD : (64 * 1024);
    uint8_t* p = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)size + guard);
    if (!p) {
        fprintf(stderr, "[COM] !! alloc_surface_buf FAILED for %u bytes (+%u guard)\n", size, guard);
        fflush(stderr);
        return NULL;
    }
    memset(p + size, SURFACE_SENTINEL, guard);
    return p;
}

/* Global mock objects (for cross-reference) */
static mock_com_obj_t* g_primary_surface = NULL;
static mock_com_obj_t* g_back_surface = NULL;
static mock_com_obj_t* g_main_offscreen = NULL; /* first fullscreen offscreen surface = BltFast source */

/* Stored display mode */
static uint32_t g_display_width = 640;
static uint32_t g_display_height = 480;
static uint32_t g_display_bpp = 16;

/* Captured HWND for D3D11 renderer */
HWND g_game_hwnd = NULL;   /* exported: the focus bridges need it (see imports.c) */

/* Texture handle counter (D3D5 texture handles are 1-based) */
static uint32_t g_next_texture_handle = 1;

/* ============================================================
 * Generic COM stubs by arg count (stdcall)
 * These are used for methods we don't need real logic for.
 * ============================================================ */

/* COM method: this + 0 real args = pop ret + 1 arg */
static void com_stub_1arg(void) { g_eax = 0; g_esp += 8; }
/* COM method: this + 1 real arg = pop ret + 2 args */
static void com_stub_2arg(void) { g_eax = 0; g_esp += 12; }
/* COM method: this + 2 real args = pop ret + 3 args */
static void com_stub_3arg(void) { g_eax = 0; g_esp += 16; }
/* COM method: this + 3 real args = pop ret + 4 args */
static void com_stub_4arg(void) { g_eax = 0; g_esp += 20; }
/* COM method: this + 4 real args = pop ret + 5 args */
static void com_stub_5arg(void) { g_eax = 0; g_esp += 24; }
/* COM method: this + 5 real args = pop ret + 6 args */
static void com_stub_6arg(void) { g_eax = 0; g_esp += 28; }
/* COM method: this + 6 real args = pop ret + 7 args */
static void com_stub_7arg(void) { g_eax = 0; g_esp += 32; }
/* COM method: this + 9 real args = pop ret + 10 args (IDirectPlay4::SendEx) */
static void com_stub_10arg(void) { g_eax = 0; g_esp += 44; }

/* ============================================================
 * IDirectDraw Methods
 *
 * Vtable layout (IDirectDrawVtbl):
 * [0]  QueryInterface       (this, riid, ppvObj) - 3 args
 * [1]  AddRef               (this) - 1 arg
 * [2]  Release              (this) - 1 arg
 * [3]  Compact              (this) - 1 arg
 * [4]  CreateClipper        (this, flags, ppClipper, pUnkOuter) - 4 args
 * [5]  CreatePalette        (this, flags, entries, ppPal, pUnkOuter) - 5 args
 * [6]  CreateSurface        (this, pDesc, ppSurf, pUnkOuter) - 4 args
 * [7]  DuplicateSurface     (this, pSrc, ppDest) - 3 args
 * [8]  EnumDisplayModes     (this, flags, pDesc, ctx, cb) - 5 args
 * [9]  EnumSurfaces         (this, flags, pDesc, ctx, cb) - 5 args
 * [10] FlipToGDISurface     (this) - 1 arg
 * [11] GetCaps              (this, pDriverCaps, pHELCaps) - 3 args
 * [12] GetDisplayMode       (this, pDesc) - 2 args
 * [13] GetFourCCCodes       (this, pNum, pCodes) - 3 args
 * [14] GetGDISurface        (this, ppSurf) - 2 args
 * [15] GetMonitorFrequency  (this, pFreq) - 2 args
 * [16] GetScanLine          (this, pLine) - 2 args
 * [17] GetVerticalBlankStatus (this, pIsInVB) - 2 args
 * [18] Initialize           (this, pGUID) - 2 args
 * [19] RestoreDisplayMode   (this) - 1 arg
 * [20] SetCooperativeLevel  (this, hwnd, flags) - 3 args
 * [21] SetDisplayMode       (this, w, h, bpp) - 4 args
 * [22] WaitForVerticalBlank (this, flags, hEvent) - 3 args
 * ============================================================ */

static void dd_QueryInterface(void) {
    /* this=esp+4, riid=esp+8, ppvObj=esp+12 */
    uint32_t riid_ptr = MEM32(g_esp + 8);
    uint32_t ppv = MEM32(g_esp + 12);

    /* Check if asking for IDirect3D (GUID starts with 0xBB140000 or real D3D GUID).
     * Real IID_IDirect3D = {3BBA0080-...}. We check first DWORD. */
    uint32_t guid_dw0 = MEM32(riid_ptr);
    { static int _c; if (_c < 6) { fprintf(stderr, "[D3DQI] IDirectDraw::QueryInterface guid_dw0=0x%08X\n", guid_dw0); fflush(stderr); _c++; } }
    COM_LOG("[COM] IDirectDraw::QueryInterface(riid_dw0=0x%08X, ppv=0x%08X)\n",
            guid_dw0, ppv);

    /* Return the correct interface per GUID. DirectDraw-family GUIDs (IDirectDraw/2/4/7:
     * B3A6F3E0, 9C59509A, 6C14DB05...) must return a DirectDraw object, NOT IDirect3D — the
     * old code returned IDirect3D for ANY QI, handing the game the wrong vtable. */
    uint32_t pThis = MEM32(g_esp + 4);
    if (guid_dw0 == 0x3BBA0080u /*IDirect3D*/ || guid_dw0 == 0x6C79BE71u /*IDirect3D2*/ ||
        guid_dw0 == 0xBB223240u /*IDirect3D3*/ || guid_dw0 == 0xBB223241u) {
        mock_com_obj_t* d3d = alloc_mock(MOCK_TAG_D3D, g_d3d_vtable_addr);
        MEM32(ppv) = (uint32_t)(uintptr_t)d3d;
        COM_LOG("[COM]   -> IDirect3D mock at 0x%08X\n", (uint32_t)(uintptr_t)d3d);
    } else {
        /* IDirectDraw2/4/7 (or IUnknown): return the same DirectDraw object. */
        MEM32(ppv) = pThis;
    }

    g_eax = 0; /* S_OK */
    g_esp += 16; /* pop ret + 3 args */
}

static void dd_AddRef(void) {
    uint32_t pThis = MEM32(g_esp + 4);
    mock_com_obj_t* obj = (mock_com_obj_t*)(uintptr_t)pThis;
    obj->refcount++;
    g_eax = obj->refcount;
    g_esp += 8;
}

static void dd_Release(void) {
    uint32_t pThis = MEM32(g_esp + 4);
    mock_com_obj_t* obj = (mock_com_obj_t*)(uintptr_t)pThis;
    if (obj->refcount > 0) obj->refcount--;
    g_eax = obj->refcount;
    g_esp += 8;
}

static mock_com_obj_t* create_mock_surface(uint8_t* pixbuf) {
    mock_com_obj_t* surf = alloc_mock(MOCK_TAG_DDSURFACE, g_ddsurface_vtable_addr);
    /* extra[0] = pixel buffer pointer */
    surf->extra[0] = (uint32_t)(uintptr_t)pixbuf;
    /* XWA_SURFSCAN: register every surface so we can ask the only question that matters --
     * is the engine drawing the ships into ANY buffer in memory? Static tracing keeps
     * mislabelling functions; this measures pixels directly. */
    { extern uint32_t g_surfreg[8192][5]; extern unsigned g_surfreg_n;
      if (g_surfreg_n < 8192) {
          /* store the ADDRESS of the extra[] array -- width/height are filled in AFTER this
           * point, so a snapshot here records 0x0 for every surface. */
          g_surfreg[g_surfreg_n][0] = (uint32_t)(uintptr_t)&surf->extra[0];
          g_surfreg_n++;
      } }
    /* extra[1] = width, extra[2] = height, extra[3] = bpp, extra[4] = pitch */
    surf->extra[1] = g_display_width;
    surf->extra[2] = g_display_height;
    surf->extra[3] = g_display_bpp;
    surf->extra[4] = g_display_width * (g_display_bpp / 8);
    return surf;
}

static void dd_CreateSurface(void) {
    /* this=esp+4, pDesc=esp+8, ppSurf=esp+12, pUnkOuter=esp+16 */
    uint32_t pDesc = MEM32(g_esp + 8);
    uint32_t ppSurf = MEM32(g_esp + 12);

    /* Read DDSURFACEDESC.dwFlags (offset +4) and ddsCaps.dwCaps (offset +104 in DDSURFACEDESC) */
    uint32_t flags = MEM32(pDesc + 4);
    uint32_t caps = MEM32(pDesc + 104);

    COM_LOG("[COM] IDirectDraw::CreateSurface(flags=0x%08X, caps=0x%08X, ppSurf=0x%08X)\n",
            flags, caps, ppSurf);

    /* Allocate surface pixel buffer if not done yet */
    if (!g_surface_buffer) {
        g_surface_buffer = alloc_surface_buf(SURFACE_BUF_SIZE);
        g_backbuf_buffer = alloc_surface_buf(SURFACE_BUF_SIZE);
    }

    /* Create primary or off-screen surface */
    mock_com_obj_t* surf;
    if (caps & 0x200) { /* DDSCAPS_PRIMARYSURFACE */
        surf = create_mock_surface(g_surface_buffer);
        g_primary_surface = surf;
        /* If flippable (caps & 0x8 = DDSCAPS_FLIP), also create back buffer */
        if (caps & 0x8) {
            g_back_surface = create_mock_surface(g_backbuf_buffer);
        }
    } else {
        /* Off-screen or texture surface */
        /* DDSURFACEDESC: dwHeight at offset 8, dwWidth at offset 12 */
        uint32_t h = MEM32(pDesc + 8);   /* dwHeight (offset 8) */
        uint32_t w = MEM32(pDesc + 12);  /* dwWidth (offset 12) */
        uint32_t bpp = 16;
        /* DDSD_HEIGHT=0x2, DDSD_WIDTH=0x4 */
        if (!(flags & 0x4) || w == 0) w = g_display_width;
        if (!(flags & 0x2) || h == 0) h = g_display_height;
        COM_LOG("[COM]   offscreen: w=%u h=%u\n", w, h);
        uint32_t size = w * h * (bpp / 8);
        uint8_t* buf = alloc_surface_buf(size);
        surf = create_mock_surface(buf);
        surf->extra[1] = w;
        surf->extra[2] = h;
        /* create_mock_surface() defaults extra[3] to g_display_bpp, which SetDisplayMode can
         * leave at 32 -- but this buffer is allocated at `bpp`. The mismatch made
         * GetSurfaceDesc/GetPixelFormat skip writing the RGB masks (they only filled them for
         * ==16), so the game read a 0 mask and sub_00451A30's `shr eax,1 / test al,1` bit-scan
         * span forever. Record the real bpp. */
        surf->extra[3] = bpp;
        surf->extra[4] = w * (bpp / 8);
        surf->extra[5] = caps;   /* remembered so Lock can report a texture pixel format */
    }

    MEM32(ppSurf) = (uint32_t)(uintptr_t)surf;

    /* Track the first fullscreen offscreen surface — this is the BltFast source.
     * Also fix the game's cached render buffer pointers (0x6000EC/0x6002BC/0x5FFDC0)
     * which point to stale 0xA0000 (legacy VGA mapping, silently fails on writes).
     * Must be done HERE, not in Lock, because the background CBM decode happens
     * during initialization before Lock is ever called. */
    if (!g_main_offscreen && !(caps & 0x200) && surf->extra[1] == g_display_width && surf->extra[2] == g_display_height) {
        g_main_offscreen = surf;
        uint32_t pixbuf = surf->extra[0];
        uint32_t old_val = MEM32(0x6002BC);
        MEM32(0x6000EC) = pixbuf;
        MEM32(0x6002BC) = pixbuf;
        MEM32(0x5FFDC0) = pixbuf;
        fprintf(stderr, "[COM] Fixed render buffer at CreateSurface: 0x6002BC 0x%08X -> 0x%08X\n", old_val, pixbuf);
    }

    /* Once the D3D path works the game creates thousands of mipmap surfaces; logging every
     * one drowns the log and slows the load. Log the first 64, then every 512th. */
    { static int _cs = 0; int _n = _cs++; if (_n < 64 || (_n % 512) == 0) fprintf(stderr, "[COM] CreateSurface #%d: surf=0x%08X buf=0x%08X w=%u h=%u caps=0x%X main=%d\n",
            _n, (uint32_t)(uintptr_t)surf, surf->extra[0], surf->extra[1], surf->extra[2], caps,
            (surf == g_main_offscreen)); }

    g_eax = 0; /* DD_OK */
    g_esp += 20; /* pop ret + 4 args */
}

static void dd_CreatePalette(void) {
    /* this=esp+4, flags=esp+8, entries=esp+12, ppPal=esp+16, pUnkOuter=esp+20 */
    uint32_t ppPal = MEM32(g_esp + 16);

    mock_com_obj_t* pal = alloc_mock(MOCK_TAG_DDPALETTE, g_ddpalette_vtable_addr);
    MEM32(ppPal) = (uint32_t)(uintptr_t)pal;
    COM_LOG("[COM] IDirectDraw::CreatePalette -> 0x%08X\n", (uint32_t)(uintptr_t)pal);

    g_eax = 0;
    g_esp += 24; /* pop ret + 5 args */
}

static void dd_SetCooperativeLevel(void) {
    /* this=esp+4, hwnd=esp+8, flags=esp+12 */
    uint32_t hwnd = MEM32(g_esp + 8);
    uint32_t flags = MEM32(g_esp + 12);
    COM_LOG("[COM] IDirectDraw::SetCooperativeLevel(hwnd=0x%08X, flags=0x%08X)\n",
            hwnd, flags);

    /* Capture HWND for D3D11 renderer */
    if (hwnd && !g_game_hwnd) {
        g_game_hwnd = (HWND)(uintptr_t)hwnd;
        COM_LOG("[COM] Captured game HWND: 0x%08X\n", hwnd);
    }

    g_eax = 0;
    g_esp += 16; /* pop ret + 3 args */
}

static void dd_SetDisplayMode(void) {
    /* IDirectDraw::SetDisplayMode(this, width, height, bpp) - 4 args */
    uint32_t w = MEM32(g_esp + 8);
    uint32_t h = MEM32(g_esp + 12);
    uint32_t bpp = MEM32(g_esp + 16);
    COM_LOG("[COM] IDirectDraw::SetDisplayMode(%ux%u@%ubpp)\n", w, h, bpp);
    g_display_width = w;
    g_display_height = h;
    g_display_bpp = bpp;

    /* Set game-internal display state globals.
     * These are normally set by sub_0053ED60 (DD init) which may not execute
     * correctly in recomp. The rendering code reads these to select bpp paths. */
    MEM32(0x9F700A) = bpp;   /* display BPP - used by all 2D blit functions */
    MEM32(0x9F7002) = bpp;   /* pitch divisor / bpp copy */
    MEM32(0x9F708E) = w - 1; /* display width - 1 (0x27F for 640) */
    MEM32(0x9F7096) = h - 1; /* display height - 1 (0x1DF for 480) */

    /* Initialize D3D11 renderer now that we have HWND and resolution */
    if (g_game_hwnd && !d3d11_is_initialized()) {
        d3d11_init((void*)g_game_hwnd, w, h);
    } else if (d3d11_is_initialized()) {
        /* Mode change (640x480 menus -> 800x600 flight): follow it, or the scene projects
         * outside the render target. */
        d3d11_resize(w, h);
    }

    g_eax = 0;
    g_esp += 20; /* pop ret + 4 args */
}

/* IDirectDraw2::GetAvailableVidMem(this, lpDDSCaps, lpdwTotal, lpdwFree) -- vtable [23].
 * The vtable used to stop at [22], so this call fell off the end and left the out-params
 * untouched. The game read 0/0 and logged "Texture Ram  Total: 0 bytes  Free: 0 bytes",
 * then declined to allocate texture surfaces -- leaving e.g. the font table's entries NULL,
 * which faulted the font remap in sub_00450B20. Report a healthy pool. */
static void dd_GetAvailableVidMem(void) {
    uint32_t pTotal = MEM32(g_esp + 12);
    uint32_t pFree  = MEM32(g_esp + 16);
    if (pTotal) MEM32(pTotal) = 0x04000000u;   /* 64 MB */
    if (pFree)  MEM32(pFree)  = 0x04000000u;
    COM_LOG("[COM] IDirectDraw::GetAvailableVidMem -> 64MB/64MB\n");
    g_eax = 0;
    g_esp += 20;   /* pop ret + 4 args */
}

static void dd_GetCaps(void) {
    /* this=esp+4, pDriverCaps=esp+8, pHELCaps=esp+12 */
    uint32_t pDrv = MEM32(g_esp + 8);
    uint32_t pHEL = MEM32(g_esp + 12);

    /* Fill DDCAPS minimally - dwSize at offset 0, dwCaps at offset 4 */
    if (pDrv) {
        uint32_t size = MEM32(pDrv); /* caller sets dwSize */
        if (size > 0) {
            /* DDCAPS_BLT (0x40) | DDCAPS_BLTSTRETCH (0x200) | DDCAPS_COLORKEY (0x400) */
            MEM32(pDrv + 4) = 0x640;
            /* DDCAPS (DX6): dwVidMemTotal @0x3C, dwVidMemFree @0x40. Report 128MB so the game's
             * video-memory sufficiency check for 800x600 flight surfaces passes (was 0 -> "Not
             * Enough Memory"). */
            MEM32(pDrv + 0x3C) = 0x08000000u;
            MEM32(pDrv + 0x40) = 0x08000000u;
        }
    }
    if (pHEL) {
        uint32_t size = MEM32(pHEL);
        if (size > 0) {
            MEM32(pHEL + 4) = 0x640;
            MEM32(pHEL + 0x3C) = 0x08000000u;
            MEM32(pHEL + 0x40) = 0x08000000u;
        }
    }

    g_eax = 0;
    g_esp += 16; /* pop ret + 3 args */
}

static void dd_GetDisplayMode(void) {
    /* this=esp+4, pDesc=esp+8 */
    uint32_t pDesc = MEM32(g_esp + 8);
    if (pDesc) {
        /* DDSURFACEDESC: dwWidth=+8, dwHeight=+12, lPitch=+16,
         * ddpfPixelFormat.dwRGBBitCount=+84 (offset 0x54) */
        MEM32(pDesc + 4) = 0x1006; /* DDSD_WIDTH|DDSD_HEIGHT|DDSD_PIXELFORMAT|DDSD_PITCH */
        MEM32(pDesc + 8) = g_display_width;
        MEM32(pDesc + 12) = g_display_height;
        MEM32(pDesc + 16) = g_display_width * (g_display_bpp / 8);
        /* DDPIXELFORMAT starts at offset 72 (0x48) in DDSURFACEDESC */
        MEM32(pDesc + 72) = 32; /* dwSize of DDPIXELFORMAT */
        MEM32(pDesc + 76) = 0x40; /* DDPF_RGB */
        MEM32(pDesc + 84) = g_display_bpp;
        if (g_display_bpp == 16) {
            /* 5-6-5 RGB */
            MEM32(pDesc + 88) = 0xF800; /* dwRBitMask */
            MEM32(pDesc + 92) = 0x07E0; /* dwGBitMask */
            MEM32(pDesc + 96) = 0x001F; /* dwBBitMask */
        }
    }
    g_eax = 0;
    g_esp += 12; /* pop ret + 2 args */
}

static void dd_EnumDisplayModes(void) {
    /* this=esp+4, flags=esp+8, pDesc=esp+12, ctx=esp+16, cb=esp+20 */
    uint32_t ctx = MEM32(g_esp + 16);
    uint32_t cb  = MEM32(g_esp + 20);

    COM_LOG("[COM] IDirectDraw::EnumDisplayModes(cb=0x%08X)\n", cb);

    /* #329: the game matches its requested mode against the table this enumeration builds
     * (sub_00598089 over 0xB0D8A0). Enumerating only 640x480 meant flight's 800x600 never
     * matched, so the Z/Tex/HW flags came back 0 and the render context was refused with
     * "Essential Hardware Feature NOT Supported". Enumerate the real mode list. */
    if (cb != 0) {
        static const struct { uint32_t w, h, bpp; } modes[] = {
            { 640, 480, 8 }, { 640, 480, 16 }, { 800, 600, 8 }, { 800, 600, 16 },
            { 1024, 768, 8 }, { 1024, 768, 16 }, { 1280, 1024, 16 },
        };
        uint32_t save_esp = g_esp;
        uint32_t desc_va = 0x00B0F000; /* scratch area in BSS */
        for (unsigned m = 0; m < sizeof(modes)/sizeof(modes[0]); m++) {
            uint32_t w = modes[m].w, h = modes[m].h, bpp = modes[m].bpp;
            uint8_t desc[108];
            memset(desc, 0, sizeof(desc));
            *(uint32_t*)(desc + 0)  = 108;              /* dwSize */
            *(uint32_t*)(desc + 4)  = 0x1006;           /* CAPS|HEIGHT|WIDTH|PITCH */
            *(uint32_t*)(desc + 8)  = h;                /* dwHeight */
            *(uint32_t*)(desc + 12) = w;                /* dwWidth  */
            *(uint32_t*)(desc + 16) = w * (bpp / 8);    /* lPitch   */
            *(uint32_t*)(desc + 72) = 32;               /* DDPIXELFORMAT.dwSize */
            *(uint32_t*)(desc + 76) = (bpp == 8) ? 0x20u : 0x40u; /* PALETTEINDEXED8 : RGB */
            *(uint32_t*)(desc + 84) = bpp;              /* dwRGBBitCount */
            if (bpp == 16) {
                *(uint32_t*)(desc + 88) = 0xF800;
                *(uint32_t*)(desc + 92) = 0x07E0;
                *(uint32_t*)(desc + 96) = 0x001F;
            }
            memcpy((void*)(uintptr_t)desc_va, desc, sizeof(desc));
            PUSH32(g_esp, ctx);
            PUSH32(g_esp, desc_va);
            PUSH32(g_esp, 0xDEAD0099u);
            com_dispatch_callback(cb);
            g_esp = save_esp;
        }
        COM_LOG("[COM] EnumDisplayModes: enumerated %u modes\n", (unsigned)(sizeof(modes)/sizeof(modes[0])));
    }

    g_eax = 0;
    g_esp += 24; /* pop ret + 5 args */
}

/* ============================================================
 * IDirectDrawSurface Methods
 *
 * Surface sanity: surfaces reached via forced/partial flight init can carry
 * uninitialized dims or stale buffer pointers. surf_buf_ok() returns the buffer
 * pointer only if it is plausibly valid; the Blt/BltFast paths bail otherwise so
 * a bad surface can never corrupt the heap (which the CRT detects as a clean abort).
 * [0]  QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3]  AddAttachedSurface (2) [4] AddOverlayDirtyRect (2)
 * [5]  Blt (5) [6] BltBatch (3) [7] BltFast (5)
 * [8]  DeleteAttachedSurface (3) [9] EnumAttachedSurfaces (3)
 * [10] EnumOverlayZOrders (4) [11] Flip (3)
 * [12] GetAttachedSurface (3) [13] GetBltStatus (2)
 * [14] GetCaps (2) [15] GetClipper (2) [16] GetColorKey (3)
 * [17] GetDC (2) [18] GetFlipStatus (2)
 * [19] GetOverlayPosition (3) [20] GetPalette (2)
 * [21] GetPixelFormat (2) [22] GetSurfaceDesc (2)
 * [23] Initialize (3) [24] IsLost (1)
 * [25] Lock (5) [26] ReleaseDC (2)
 * [27] Restore (1) [28] SetClipper (2)
 * [29] SetColorKey (3) [30] SetOverlayPosition (3)
 * [31] SetPalette (2) [32] Unlock (2)
 * ============================================================ */

/* Return the surface's pixel buffer iff dims+pitch+pointer are all plausible. */
static uint8_t* surf_buf_ok(mock_com_obj_t* s) {
    if (!s) return NULL;
    uintptr_t buf = (uintptr_t)s->extra[0];
    uint32_t w = s->extra[1], h = s->extra[2], pitch = s->extra[4];
    if (buf < 0x10000 || buf > 0x7F000000) return NULL;     /* null/garbage pointer */
    if (w == 0 || h == 0 || w > 16384 || h > 16384) return NULL;
    if (pitch == 0 || pitch > 0x100000) return NULL;
    return (uint8_t*)buf;
}

static void dds_QueryInterface(void) {
    /* this=esp+4, riid=esp+8, ppvObj=esp+12 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t riid_ptr = MEM32(g_esp + 8);
    uint32_t ppv = MEM32(g_esp + 12);

    /* Check GUID to determine what interface is requested.
     * IID_IDirect3DTexture  = {2CDCD9E0-...} (first DWORD = 0x2CDCD9E0)
     * IID_IDirect3DTexture2 = {93281502-...} (first DWORD = 0x93281502)
     * We treat any QI from a surface as a texture interface request. */
    uint32_t guid_dw0 = MEM32(riid_ptr);
    { static int _c; if (_c < 8) { fprintf(stderr, "[SURFQI] IDirectDrawSurface::QueryInterface guid_dw0=0x%08X\n", guid_dw0); fflush(stderr); _c++; } }
    COM_LOG("[COM] IDirectDrawSurface::QueryInterface(riid_dw0=0x%08X)\n", guid_dw0);

    /* XWA_D3DCAPS: DX6 creates the 3D device by QI-ing the back buffer for a DEVICE guid
     * (IID_IDirect3DHALDevice etc). Returning a TEXTURE vtable for that made every later
     * device call land on the wrong slot -- the game's own log showed EnumTextureFormats
     * arriving as "IDirectInput::EnumDevices" and then "Error: no texture formats found",
     * which failed sub_0059453F and cleared the session flag 0x77330C, disabling the whole
     * hardware render path. Dispatch on the guid instead. (0 = the all-zero guid our own
     * EnumDevices used to hand out; treat it as the HAL device.) */
    int want_device = getenv("XWA_D3DCAPS") && (
        guid_dw0 == 0x00000000u ||   /* our legacy zero guid */
        guid_dw0 == 0x84E63DE0u ||   /* IID_IDirect3DHALDevice */
        guid_dw0 == 0xA4665C60u ||   /* IID_IDirect3DRGBDevice */
        guid_dw0 == 0xF2086B20u ||   /* IID_IDirect3DRampDevice */
        guid_dw0 == 0x881949A1u);    /* IID_IDirect3DMMXDevice */
    if (want_device) {
        uint32_t dev = com_ensure_d3d_device();
        MEM32(ppv) = dev;
        COM_LOG("[COM]   -> IDirect3DDevice mock at 0x%08X (guid_dw0=0x%08X)\n", dev, guid_dw0);
        g_eax = 0;
        g_esp += 16;
        return;
    }

    /* Create an IDirect3DTexture mock that points back to this surface */
    mock_com_obj_t* tex = alloc_mock(MOCK_TAG_D3D, g_d3dtexture_vtable_addr);
    tex->extra[0] = pThis; /* Back-pointer to the surface */
    tex->extra[1] = 0;     /* Texture handle (assigned on GetHandle) */
    MEM32(ppv) = (uint32_t)(uintptr_t)tex;

    g_eax = 0; /* S_OK */
    g_esp += 16; /* pop ret + 3 args */
}

static void dds_Release(void) {
    uint32_t pThis = MEM32(g_esp + 4);
    mock_com_obj_t* obj = (mock_com_obj_t*)(uintptr_t)pThis;
    if (obj->refcount > 0) obj->refcount--;
    g_eax = obj->refcount;
    g_esp += 8;
}

static void dds_GetAttachedSurface(void) {
    /* this=esp+4, pCaps=esp+8, ppSurf=esp+12 */
    uint32_t ppSurf = MEM32(g_esp + 12);

    /* Return the back buffer if this is the primary */
    if (g_back_surface) {
        MEM32(ppSurf) = (uint32_t)(uintptr_t)g_back_surface;
    } else {
        /* Return self as fallback */
        MEM32(ppSurf) = MEM32(g_esp + 4);
    }

    g_eax = 0;
    g_esp += 16; /* pop ret + 3 args */
}

static void dds_Lock(void) {
    /* this=esp+4, pDestRect=esp+8, pDesc=esp+12, flags=esp+16, hEvent=esp+20 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pDesc = MEM32(g_esp + 12);
    { static int _lc; if (_lc < 30) { const char* stype = (pThis == (uint32_t)(uintptr_t)g_primary_surface) ? "PRIMARY" : (pThis == (uint32_t)(uintptr_t)g_back_surface) ? "BACK" : "OFFSCREEN"; fprintf(stderr, "[COM] dds_Lock #%d (this=0x%08X [%s], desc=0x%08X)\n", _lc, pThis, stype, pDesc); _lc++; } }

    mock_com_obj_t* surf = (mock_com_obj_t*)(uintptr_t)pThis;
    uint32_t pixbuf = surf->extra[0];
    uint32_t width  = surf->extra[1];
    uint32_t height = surf->extra[2];
    uint32_t bpp    = surf->extra[3];
    uint32_t pitch  = surf->extra[4];

    if (pDesc) {
        /* Fill DDSURFACEDESC with surface info */
        /* dwHeight at offset 8, dwWidth at offset 12 */
        MEM32(pDesc + 4) = 0x100F; /* DDSD_PITCH|DDSD_WIDTH|DDSD_HEIGHT|DDSD_LPSURFACE|DDSD_PIXELFORMAT */
        MEM32(pDesc + 8) = height;
        MEM32(pDesc + 12) = width;
        MEM32(pDesc + 16) = pitch;
        MEM32(pDesc + 36) = pixbuf;  /* lpSurface at offset 36 (0x24) */
        /* The flags above advertise DDSD_PIXELFORMAT but ddpfPixelFormat (+0x48) was never
         * written, so the game read dwRGBAlphaBitMask (+0x64) as 0. sub_00451A30 scans that
         * mask for its lowest set bit with `shr eax,1 / test al,1 / je` -- a zero mask shifts
         * to zero and loops FOREVER. That single hang was ~52% of all runtime and starved the
         * flight frame loop (8 frames in 480s). Texture surfaces report ARGB1555 so the alpha
         * scan terminates; everything else reports RGB565. */
        uint32_t pf = pDesc + 0x48;
        int is_tex = (surf->extra[5] & 0x1000u) != 0;   /* DDSCAPS_TEXTURE */
        MEM32(pf + 0x00) = 32;                                  /* dwSize */
        MEM32(pf + 0x04) = is_tex ? (0x40u | 0x01u) : 0x40u;    /* DDPF_RGB [| DDPF_ALPHAPIXELS] */
        MEM32(pf + 0x08) = 0;                                   /* dwFourCC */
        MEM32(pf + 0x0C) = bpp ? bpp : 16;                      /* dwRGBBitCount */
        if (is_tex) {   /* ARGB1555 */
            MEM32(pf + 0x10) = 0x7C00; MEM32(pf + 0x14) = 0x03E0;
            MEM32(pf + 0x18) = 0x001F; MEM32(pf + 0x1C) = 0x8000;
        } else {        /* RGB565 */
            MEM32(pf + 0x10) = 0xF800; MEM32(pf + 0x14) = 0x07E0;
            MEM32(pf + 0x18) = 0x001F; MEM32(pf + 0x1C) = 0;
        }
    }

    /* Fix game's cached render buffer: the game stores the surface pointer at
     * 0x6000EC/0x6002BC during DD init, pointing to stale/invalid memory (0xA0000).
     * Update these globals to our actual surface buffer so the RLE drawing code
     * writes to the same memory that BltFast reads from.
     * Only update when locking the MAIN offscreen surface (the BltFast source). */
    if (g_main_offscreen && pThis == (uint32_t)(uintptr_t)g_main_offscreen) {
        uint32_t old_6002BC = MEM32(0x6002BC);
        if (old_6002BC != pixbuf) {
            MEM32(0x6000EC) = pixbuf;
            MEM32(0x6002BC) = pixbuf;
            MEM32(0x5FFDC0) = pixbuf;
            { static int _fix; if (_fix < 5) {
                fprintf(stderr, "[COM] Fixed render buffer: 0x6002BC 0x%08X -> 0x%08X\n", old_6002BC, pixbuf);
                _fix++;
            } }
        }
    }

    { static int _ll; if (_ll < 30) { fprintf(stderr, "[COM]   Lock -> lpSurface=0x%08X w=%u h=%u pitch=%u (0x6002BC=0x%08X)\n", pixbuf, width, height, pitch, MEM32(0x6002BC)); _ll++; } }

    g_eax = 0; /* DD_OK */
    g_esp += 24; /* pop ret + 5 args */
}

static void dds_Unlock(void) {
    /* this=esp+4, pRect=esp+8 */
    uint32_t pThis = MEM32(g_esp + 4);
    { static int _uc; if (_uc < 40) {
        mock_com_obj_t* surf = (mock_com_obj_t*)(uintptr_t)pThis;
        if (surf && surf->extra[0]) {
            uint8_t* buf = (uint8_t*)(uintptr_t)surf->extra[0];
            uint32_t total = surf->extra[1] * surf->extra[2] * 2;
            int nz = 0; uint32_t first_nz_off = 0;
            for (uint32_t i = 0; i < total; i++) {
                if (buf[i]) { nz = 1; first_nz_off = i; break; }
            }
            const char* stype = (pThis == (uint32_t)(uintptr_t)g_primary_surface) ? "PRIMARY" :
                                (pThis == (uint32_t)(uintptr_t)g_back_surface) ? "BACK" : "OFFSCREEN";
            fprintf(stderr, "[COM] dds_Unlock(%s 0x%08X) w=%u h=%u nonzero=%d first_nz_off=%u\n",
                    stype, pThis, surf->extra[1], surf->extra[2], nz, first_nz_off);
        }
        _uc++;
    } }
    g_eax = 0;
    g_esp += 12;
}

static void dds_GetSurfaceDesc(void) {
    /* this=esp+4, pDesc=esp+8 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pDesc = MEM32(g_esp + 8);

    mock_com_obj_t* surf = (mock_com_obj_t*)(uintptr_t)pThis;
    if (pDesc) {
        MEM32(pDesc + 4) = 0x1006; /* flags */
        /* dwHeight at offset 8, dwWidth at offset 12 */
        MEM32(pDesc + 8) = surf->extra[2]; /* height */
        MEM32(pDesc + 12) = surf->extra[1]; /* width */
        MEM32(pDesc + 16) = surf->extra[4]; /* pitch */
        MEM32(pDesc + 72) = 32;  /* DDPIXELFORMAT.dwSize */
        MEM32(pDesc + 76) = 0x40;  /* DDPF_RGB */
        uint32_t _bpp = surf->extra[3] ? surf->extra[3] : 16;
        MEM32(pDesc + 84) = _bpp;
        if (_bpp == 32) { MEM32(pDesc + 88) = 0x00FF0000; MEM32(pDesc + 92) = 0x0000FF00; MEM32(pDesc + 96) = 0x000000FF; }
        else            { MEM32(pDesc + 88) = 0xF800;     MEM32(pDesc + 92) = 0x07E0;     MEM32(pDesc + 96) = 0x001F; }
    }

    g_eax = 0;
    g_esp += 12;
}

/* Scan a surface buffer's guard region; report the first/furthest sentinel byte
 * that was overwritten (i.e. how far past the reported size the game wrote). */
static void check_sentinel(const char* name, uint8_t* buf, uint32_t reported) {
    if (!buf) return;
    uint8_t* g = buf + reported;
    uint32_t furthest = 0;
    for (uint32_t i = 0; i < SURFACE_GUARD; i++) if (g[i] != SURFACE_SENTINEL) furthest = i + 1;
    if (furthest) {
        static int _warned = 0;
        if (_warned < 8) { fprintf(stderr, "[GUARD] %s OVERRUN: wrote %u bytes past reported %u (guard=%u)\n",
            name, furthest, reported, SURFACE_GUARD); fflush(stderr); _warned++; }
    }
}

static void dds_Flip(void) {
    /* this=esp+4, pSurf=esp+8, flags=esp+12 */
    static int _flip_count = 0;
    _flip_count++;
    if (g_surface_buffer) check_sentinel("primary", g_surface_buffer, SURFACE_BUF_SIZE);
    if (g_backbuf_buffer) check_sentinel("backbuf", g_backbuf_buffer, SURFACE_BUF_SIZE);
    if (d3d11_is_initialized()) {
        /* Upload the back buffer 2D surface before presenting */
        if (g_back_surface && g_back_surface->extra[0]) {
            if (_flip_count <= 25 || (_flip_count % 100 == 0)) {
                uint8_t* buf = (uint8_t*)(uintptr_t)g_back_surface->extra[0];
                uint32_t sz = g_back_surface->extra[1] * g_back_surface->extra[2] * 2;
                uint32_t nz_count = 0;
                for (uint32_t i = 0; i < sz; i++) { if (buf[i]) nz_count++; }
                fprintf(stderr, "[COM] dds_Flip #%d: back_buf=0x%X %ux%u nz=%u/%u this=0x%X | 7B1CE8=0x%X 7B1CE0=0x%X\n",
                    _flip_count, g_back_surface->extra[0], g_back_surface->extra[1],
                    g_back_surface->extra[2], nz_count, sz,
                    MEM32(g_esp + 4), MEM32(0x7B1CE8), MEM32(0x7B1CE0));

              { extern volatile unsigned g_csblk; static unsigned _lc;
                if (getenv("XWA_CSTRACE") && g_csblk != _lc) { _lc = g_csblk;
                  fprintf(stderr, "[CS] sub_0053B500 block L_%08X\n", g_csblk); fflush(stderr); } }
              { extern volatile unsigned g_scblk, g_sc[2];
                static unsigned _last; if (g_scblk != _last) { _last = g_scblk;
                  fprintf(stderr, "[LIVE] sub_00564D10 calls=%u block=L_%08X\n", g_sc[0], g_scblk); fflush(stderr); } }                fflush(stderr);
            }
            d3d11_upload_surface(
                (uint8_t*)(uintptr_t)g_back_surface->extra[0],
                g_back_surface->extra[1],
                g_back_surface->extra[2],
                g_back_surface->extra[4],
                g_back_surface->extra[3]
            );
            /* Dump frames to BMP for debugging. Fire early (flip 25) and re-dump
             * every 25 flips (overwrite) so we always have a recent frame even if
             * the run exits early. Handles both 16bpp (565) and 32bpp (XRGB). */
            /* Dump the FULLEST frame seen per resolution (track max nonzero) so the dump reflects
             * actual rendered content, not a black transitional frame. */
            { static uint32_t _maxnz_640 = 0, _maxnz_800 = 0;
              uint32_t _w0 = g_back_surface->extra[1], _h0 = g_back_surface->extra[2];
              uint32_t _bpp0 = g_back_surface->extra[3], _pitch0 = g_back_surface->extra[4];
              uint8_t* _b0 = (uint8_t*)(uintptr_t)g_back_surface->extra[0];
              uint32_t _bytes = _pitch0 * _h0, _nz = 0, _i;
              for (_i = 0; _i < _bytes; _i += 4) { if (_b0[_i] | _b0[_i+1] | _b0[_i+2]) _nz++; }
              /* XWA_SHOTS: capture one screenshot per game screen (frame_shot_<name>.bmp), keeping the
               * richest frame seen for each. Reads the active screen callback from game state. */
              const char* _shot = NULL;
              if (getenv("XWA_SHOTS")) {
                  uint32_t _cb = MEM32(0xA1C8D5u + 0x850u * MEM32(0xA1C089u));
                  static uint32_t _snz[8]; static const uint32_t _scb[8] =
                      {0x005397D0,0x0055FF30,0x0053B500,0x005438B0,0x005316B0,0x005710F0,0x00559B50,0x0049E600};
                  static const char* _snm[8] =
                      {"concourse","barracks","combatsim","skirmish","loading","flightinit","optionsmenu","flight"};
                  for (int _k=0;_k<8;_k++) if (_scb[_k]==_cb) {
                      if (_nz > _snz[_k] + 200) { _snz[_k] = _nz; _shot = _snm[_k]; }
                      break;
                  }
                  /* Once the 3D flight frame (sub_004F2070) has rendered at all, force a dump
                   * of EVERY subsequent flip to frame_shot_flight.bmp. The screen-cb match and
                   * the richest-frame heuristic both lose to the briefing, which is far denser
                   * than a single flight frame, so the flight frame never reached disk. */
    { static int _once; if (!_once && g_eb_obj[1]) { _once = 1;
        uint32_t tgt = g_eb_obj[1], hits = 0;
        for (uint32_t a = 0x00600000u; a < 0x00B00000u; a += 4)
            if (MEM32(a) == tgt) { fprintf(stderr, "[EB2PTR] EB#2 obj 0x%08X stored at guest 0x%06X\n", tgt, a);
                                   if (++hits >= 8) break; }
        if (!hits) fprintf(stderr, "[EB2PTR] EB#2 pointer 0x%08X NOT stored in guest globals\n", tgt);
        fflush(stderr); } }
                  { extern unsigned g_rcount[8]; if (g_rcount[0] > 0) _shot = "flight"; }
                  if (!_shot) goto _skip_dump;
              } else {
                  uint32_t* _mx = (_w0 >= 700) ? &_maxnz_800 : &_maxnz_640;
                  static int _dumped0 = 0; _dumped0++; if (_nz > *_mx + 200) { *_mx = _nz; } else { goto _skip_dump; }
              }
              static int _dumped = 0; _dumped++;
              (void)_bpp0;
              { uint32_t w = g_back_surface->extra[1], h = g_back_surface->extra[2];
                uint32_t pitch = g_back_surface->extra[4];
                uint32_t bpp = g_back_surface->extra[3];
                uint8_t* px = (uint8_t*)(uintptr_t)g_back_surface->extra[0];
                char _dpath[96];
                if (_shot) snprintf(_dpath, sizeof(_dpath), "D:\\recomp\\pc\\xwa\\frame_shot_%s.bmp", _shot);
                else snprintf(_dpath, sizeof(_dpath), "D:\\recomp\\pc\\xwa\\frame_%ux%u.bmp", w, h);
                FILE* fp = fopen(_dpath, "wb");
                if (fp) {
                    uint32_t row32 = w * 3; if (row32 % 4) row32 += 4 - (row32 % 4);
                    uint32_t img_size = row32 * h;
                    uint8_t hdr[54] = {0};
                    hdr[0]='B'; hdr[1]='M';
                    *(uint32_t*)(hdr+2) = 54 + img_size;
                    *(uint32_t*)(hdr+10) = 54;
                    *(uint32_t*)(hdr+14) = 40;
                    *(int32_t*)(hdr+18) = (int32_t)w;
                    *(int32_t*)(hdr+22) = -(int32_t)h; /* top-down */
                    *(uint16_t*)(hdr+26) = 1;
                    *(uint16_t*)(hdr+28) = 24;
                    *(uint32_t*)(hdr+34) = img_size;
                    fwrite(hdr, 1, 54, fp);
                    uint8_t* row = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, row32);
                    for (uint32_t y = 0; y < h; y++) {
                        memset(row, 0, row32);
                        if (bpp == 32) {
                            uint8_t* sp = px + y * pitch;   /* B,G,R,X per pixel */
                            for (uint32_t x = 0; x < w; x++) {
                                row[x*3+0] = sp[x*4+0]; row[x*3+1] = sp[x*4+1]; row[x*3+2] = sp[x*4+2];
                            }
                        } else {
                            uint16_t* sp = (uint16_t*)(px + y * pitch);
                            for (uint32_t x = 0; x < w; x++) {
                                uint16_t c = sp[x];
                                row[x*3+0] = (uint8_t)((c & 0x1F) * 255 / 31);
                                row[x*3+1] = (uint8_t)(((c >> 5) & 0x3F) * 255 / 63);
                                row[x*3+2] = (uint8_t)(((c >> 11) & 0x1F) * 255 / 31);
                            }
                        }
                        fwrite(row, 1, row32, fp);
                    }
                    HeapFree(GetProcessHeap(), 0, row);
                    fclose(fp);
                    fprintf(stderr, "[DUMP] Wrote frame %d to frame_dump.bmp (%ux%u %ubpp)\n", _dumped, w, h, bpp);
                }
              } }
              _skip_dump: ;
            /* NOTE: Do NOT clear the back buffer after upload.
             * The game does incremental drawing - it redraws only the parts
             * that changed each frame, relying on the back buffer retaining
             * previous content (as real DirectDraw Flip swaps front/back). */
        }
        d3d11_present();
    }
    g_eax = 0;
    g_esp += 16;
}

static void dds_Blt(void) {
    if (getenv("XWA_BLTLOG")) { { fprintf(stderr, "[BLT] enter\n"); fflush(stderr); } }
    /* this=esp+4, pDestRect=esp+8, pSrcSurf=esp+12, pSrcRect=esp+16, flags=esp+20, pBltFx=esp+24 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pDestRect = MEM32(g_esp + 8);
    uint32_t pSrcSurf = MEM32(g_esp + 12);
    uint32_t pSrcRect = MEM32(g_esp + 16);
    uint32_t dwFlags = MEM32(g_esp + 20);
    uint32_t pBltFx = MEM32(g_esp + 24);

    mock_com_obj_t* dst = (mock_com_obj_t*)(uintptr_t)pThis;
    mock_com_obj_t* src = pSrcSurf ? (mock_com_obj_t*)(uintptr_t)pSrcSurf : NULL;

    { static int _bc; if (_bc < 10) { fprintf(stderr, "[COM] dds_Blt(dst=0x%08X, src=0x%08X, flags=0x%08X, bltfx=0x%08X)\n", pThis, pSrcSurf, dwFlags, pBltFx); _bc++; } }

    if (!src && dst && dst->extra[0] && (dwFlags & 0x400) && pBltFx) {
        /* DDBLT_COLORFILL (0x400): fill destination with solid color */
        /* DDBLTFX.dwFillColor is at offset 80 */
        uint32_t fillColor = MEM32(pBltFx + 80);
        uint32_t dstW = dst->extra[1], dstH = dst->extra[2];
        uint32_t dstPitch = dst->extra[4];
        uint32_t bpp = dst->extra[3] / 8;
        if (bpp == 0) bpp = 2;
        uint8_t* dstBuf = (uint8_t*)(uintptr_t)dst->extra[0];

        /* Determine fill region from pDestRect (RECT: left, top, right, bottom) */
        uint32_t x0 = 0, y0 = 0, x1 = dstW, y1 = dstH;
        if (pDestRect) {
            x0 = MEM32(pDestRect + 0);
            y0 = MEM32(pDestRect + 4);
            x1 = MEM32(pDestRect + 8);
            y1 = MEM32(pDestRect + 12);
        }
        /* Hardening: surfaces reached via forced-flight may carry garbage dims or
         * a stale buffer pointer. Bail unless dims+pitch+pointer are all sane. */
        if (!surf_buf_ok(dst)) {
            { static int _cfx; if (_cfx < 10) { fprintf(stderr, "[COM]   ColorFill SKIP (bad surf W=%u H=%u pitch=%u buf=0x%08X)\n", dstW, dstH, dstPitch, dst->extra[0]); _cfx++; } }
            g_eax = 0; { if (getenv("XWA_BLTLOG")) { { fprintf(stderr, "[BLT] exit\n"); fflush(stderr);} } } g_esp += 28; return;
        }
        if (x0 > dstW) x0 = dstW;
        if (y0 > dstH) y0 = dstH;
        if (x1 > dstW) x1 = dstW;
        if (y1 > dstH) y1 = dstH;
        if (x1 < x0) x1 = x0;
        if (y1 < y0) y1 = y0;

        { static int _cf; if (_cf < 5) { fprintf(stderr, "[COM]   ColorFill: color=0x%04X rect=(%u,%u)-(%u,%u) W=%u H=%u pitch=%u\n", fillColor, x0, y0, x1, y1, dstW, dstH, dstPitch); _cf++; } }

        if (bpp == 2) {
            uint16_t fill16 = (uint16_t)fillColor;
            for (uint32_t y = y0; y < y1; y++) {
                uint16_t* row = (uint16_t*)(dstBuf + y * dstPitch);
                for (uint32_t x = x0; x < x1; x++) {
                    row[x] = fill16;
                }
            }
        } else {
            /* Generic byte fill for other bpp */
            for (uint32_t y = y0; y < y1; y++) {
                memset(dstBuf + y * dstPitch + x0 * bpp, (uint8_t)fillColor, (x1 - x0) * bpp);
            }
        }
    } else if (src && dst && src->extra[0] && dst->extra[0]) {
        /* Source-to-destination surface copy */
        uint32_t srcW = src->extra[1], srcH = src->extra[2], srcPitch = src->extra[4];
        uint32_t dstW = dst->extra[1], dstH = dst->extra[2], dstPitch = dst->extra[4];
        uint32_t copyW = srcW < dstW ? srcW : dstW;
        uint32_t copyH = srcH < dstH ? srcH : dstH;
        uint32_t bpp = src->extra[3] / 8;
        if (bpp == 0) bpp = 2;
        uint32_t rowBytes = copyW * bpp;
        uint8_t* srcBuf = (uint8_t*)(uintptr_t)src->extra[0];
        uint8_t* dstBuf = (uint8_t*)(uintptr_t)dst->extra[0];
        /* Hardening: never copy with garbage dims/pitches (forced-flight surfaces). */
        if (copyW > 16384 || copyH > 16384 || srcPitch == 0 || dstPitch == 0 ||
            srcPitch > 0x100000 || dstPitch > 0x100000 || rowBytes > srcPitch || rowBytes > dstPitch) {
            { static int _cpx; if (_cpx < 10) { fprintf(stderr, "[COM]   Blt-copy SKIP (bad dims cW=%u cH=%u sp=%u dp=%u)\n", copyW, copyH, srcPitch, dstPitch); _cpx++; } }
            g_eax = 0; { if (getenv("XWA_BLTLOG")) { { fprintf(stderr, "[BLT] exit\n"); fflush(stderr);} } } g_esp += 28; return;
        }
        for (uint32_t y = 0; y < copyH; y++) {
            memcpy(dstBuf + y * dstPitch, srcBuf + y * srcPitch, rowBytes);
        }
    }
    g_eax = 0;
    { if (getenv("XWA_BLTLOG")) { { fprintf(stderr, "[BLT] exit\n"); fflush(stderr);} } } g_esp += 28; /* pop ret + 6 args */
}

static void dds_SetColorKey(void) {
    /* this=esp+4, dwFlags=esp+8, lpDDColorKey=esp+12 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t dwFlags = MEM32(g_esp + 8);
    uint32_t pCK = MEM32(g_esp + 12);
    mock_com_obj_t* surf = (mock_com_obj_t*)(uintptr_t)pThis;
    if (surf && pCK) {
        uint32_t ckLow = MEM32(pCK + 0);
        uint32_t ckHigh = MEM32(pCK + 4);
        if (dwFlags & 0x8) { /* DDCKEY_SRCBLT */
            surf->extra[5] = ckLow;   /* source color key low */
            surf->extra[6] = 1;       /* source color key valid */
        }
        if (dwFlags & 0x2) { /* DDCKEY_DESTBLT */
            surf->extra[7] = ckLow;   /* dest color key low */
            surf->extra[8] = 1;       /* dest color key valid */
        }
        { static int _ck; if (_ck < 20) { fprintf(stderr, "[COM] SetColorKey(surf=0x%08X, flags=0x%X, low=0x%04X, high=0x%04X)\n", pThis, dwFlags, ckLow, ckHigh); _ck++; } }
    }
    g_eax = 0;
    { if (getenv("XWA_BLTLOG")) { { fprintf(stderr, "[BLT] exit\n"); fflush(stderr);} } } g_esp += 16; /* pop ret + 3 args */
}

static void dds_BltFast(void) {
    /* this=esp+4, x=esp+8, y=esp+12, pSrcSurf=esp+16, pSrcRect=esp+20, dwTrans=esp+24 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t dstX = MEM32(g_esp + 8);
    uint32_t dstY = MEM32(g_esp + 12);
    uint32_t pSrcSurf = MEM32(g_esp + 16);
    uint32_t pSrcRect = MEM32(g_esp + 20);
    uint32_t dwTrans = MEM32(g_esp + 24);

    mock_com_obj_t* dst = (mock_com_obj_t*)(uintptr_t)pThis;
    mock_com_obj_t* src = pSrcSurf ? (mock_com_obj_t*)(uintptr_t)pSrcSurf : NULL;

    { static int _bf; if (_bf < 200) {
        fprintf(stderr, "[COM] dds_BltFast(dst=0x%08X[buf=0x%08X], x=%u, y=%u, src=0x%08X[buf=0x%08X %ux%u], dwTrans=0x%X, 0x6002BC=0x%08X)\n",
            pThis, dst ? dst->extra[0] : 0, dstX, dstY,
            pSrcSurf, src ? src->extra[0] : 0,
            src ? src->extra[1] : 0, src ? src->extra[2] : 0,
            dwTrans, MEM32(0x6002BC)); _bf++;
    } }
    /* RCTX-BLIT (#150 disambiguation): for any large 3D-scene source blit, log the render context 0x7B1CE8.
     * If the CONCOURSE (which renders 3D) blits with 0x7B1CE8==0, then sub_0059453F/0x7B1CE8 is a RED HERRING
     * and the flight-black cause is the empty scene object-list, not the D3D device-init. */
    if (getenv("XWA_RCTXBLIT") && src && src->extra[1] >= 320) {
        static int _rcb; if (_rcb < 16) { uint8_t* fb2 = surf_buf_ok(src); uint32_t nz2 = 0;
            if (fb2) { uint32_t b2 = src->extra[4] * src->extra[2], k2; for (k2 = 0; k2 < b2; k2 += 4) if (fb2[k2]|fb2[k2+1]|fb2[k2+2]) nz2++; }
            fprintf(stderr, "[RCTX-BLIT] src=%ux%u dst=(%u,%u) nz=%u 7B1CE8=0x%X 7B1CE0=0x%X 7B1CE4=%u\n",
                src->extra[1], src->extra[2], dstX, dstY, nz2, MEM32(0x7B1CE8), MEM32(0x7B1CE0), MEM32(0x7B1CE4)); fflush(stderr); _rcb++; } }
    /* Dump the FLIGHT VIEW source buffer (800x600, blitted at cockpit offset 80,60) so we can see
     * whether the 3D scene renders geometry. Track max-nonzero so we keep the fullest flight frame. */
    if (src && src->extra[1] == 800 && src->extra[2] == 600 && dstX == 80 && dstY == 60) {
        uint8_t* fb = surf_buf_ok(src);
        if (fb) {
            uint32_t w = 800, h = 600, pitch = src->extra[4], bpp = src->extra[3];
            uint32_t nz = 0, i, bytes = pitch * h;
            for (i = 0; i < bytes; i += 2) { if (fb[i] | fb[i+1]) nz++; }
            { static int _nl; if (_nl < 15) { fprintf(stderr, "[FLTNZ] flight-src blit nz=%u/%u %ubpp pitch=%u\n", nz, w*h, bpp, pitch); fflush(stderr); _nl++; } }
            { const char* _rc = getenv("XWA_RENDCOUNT");
              if (_rc) { static int _p; if (_p < 12) { _p++;
                extern unsigned g_rcount[8]; extern const char* const g_rcount_name[8];
                fprintf(stderr, "[RENDCOUNT]");
                for (int _i = 0; _i < 8; _i++) fprintf(stderr, "  %s=%u", g_rcount_name[_i], g_rcount[_i]);
                fprintf(stderr, "\n"); fflush(stderr); } } }
            /* XWA_SNAP=N: dump the flight state after the Nth flight-view blit. This is the only
             * reliable "we are really in flight" hook -- 0x0049E600 is a `xor eax,eax; ret` stub in
             * the real binary (NOT the frame callback), and sub_005710F0 never returns to the pump
             * once flight starts, so the ui-driver never gets a chance to fire. */
            { const char* _sn = getenv("XWA_SNAP");
              if (_sn) { static int _blits = 0, _done = 0; int _want = atoi(_sn); if (_want <= 0) _want = 5;
                if (!_done && ++_blits >= _want) { _done = 1;
                    extern void xwa_snap_flight(uint32_t, uint32_t); xwa_snap_flight(0x005710F0, 0); } } }
            static uint32_t _maxnz_flt = 0;
            if (nz > _maxnz_flt + 50 || (_maxnz_flt == 0 && nz > 0)) {
                _maxnz_flt = nz;
                FILE* fp = fopen("D:\\recomp\\pc\\xwa\\frame_flight.bmp", "wb");
                if (fp) {
                    uint32_t row32 = w * 3; if (row32 % 4) row32 += 4 - (row32 % 4);
                    uint32_t img_size = row32 * h; uint8_t hdr[54] = {0};
                    hdr[0]='B'; hdr[1]='M'; *(uint32_t*)(hdr+2)=54+img_size; *(uint32_t*)(hdr+10)=54;
                    *(uint32_t*)(hdr+14)=40; *(int32_t*)(hdr+18)=(int32_t)w; *(int32_t*)(hdr+22)=-(int32_t)h;
                    *(uint16_t*)(hdr+26)=1; *(uint16_t*)(hdr+28)=24; *(uint32_t*)(hdr+34)=img_size;
                    fwrite(hdr,1,54,fp);
                    uint8_t* row = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, row32);
                    for (uint32_t y = 0; y < h; y++) {
                        memset(row, 0, row32);
                        if (bpp == 32) { uint8_t* sp = fb + y*pitch;
                            for (uint32_t x=0;x<w;x++){ row[x*3]=sp[x*4]; row[x*3+1]=sp[x*4+1]; row[x*3+2]=sp[x*4+2]; } }
                        else { uint16_t* sp = (uint16_t*)(fb + y*pitch);
                            for (uint32_t x=0;x<w;x++){ uint16_t c=sp[x];
                                row[x*3]=(uint8_t)((c&0x1F)*255/31); row[x*3+1]=(uint8_t)(((c>>5)&0x3F)*255/63); row[x*3+2]=(uint8_t)(((c>>11)&0x1F)*255/31); } }
                        fwrite(row,1,row32,fp);
                    }
                    HeapFree(GetProcessHeap(),0,row); fclose(fp);
                    fprintf(stderr, "[FLTDUMP] wrote frame_flight.bmp 800x600 %ubpp nz=%u/%u\n", bpp, nz, w*h); fflush(stderr);
                }
            }
        }
    }
    /* Copy src rect to dst at (dstX, dstY) with optional source color keying */
    uint8_t* srcBuf = surf_buf_ok(src);
    uint8_t* dstBuf = surf_buf_ok(dst);
    if (srcBuf && dstBuf) {
        uint32_t srcX = 0, srcY = 0, srcW = src->extra[1], srcH = src->extra[2];
        if (pSrcRect) {
            srcX = MEM32(pSrcRect + 0); /* left */
            srcY = MEM32(pSrcRect + 4); /* top */
            srcW = MEM32(pSrcRect + 8) - srcX; /* right - left */
            srcH = MEM32(pSrcRect + 12) - srcY; /* bottom - top */
        }
        uint32_t dstW = dst->extra[1], dstH = dst->extra[2];
        uint32_t srcPitch = src->extra[4], dstPitch = dst->extra[4];
        uint32_t bpp = src->extra[3] / 8;
        if (bpp == 0) bpp = 2;
        /* Clip to destination bounds. Guard against unsigned underflow when the
         * blit origin lies outside the destination (dstX>dstW / dstY>dstH). */
        if (dstX >= dstW || dstY >= dstH) { g_eax = 0; g_esp += 28; return; }
        if (srcX >= src->extra[1] || srcY >= src->extra[2]) { g_eax = 0; g_esp += 28; return; }
        if (dstX + srcW > dstW) srcW = dstW - dstX;
        if (dstY + srcH > dstH) srcH = dstH - dstY;
        if (srcX + srcW > src->extra[1]) srcW = src->extra[1] - srcX;
        if (srcY + srcH > src->extra[2]) srcH = src->extra[2] - srcY;
        if (srcW > 16384 || srcH > 16384) { g_eax = 0; g_esp += 28; return; }

        /* DDBLTFAST_SRCCOLORKEY = 0x08 */
        int use_src_ck = (dwTrans & 0x08) && src->extra[6];
        uint16_t ck16 = (uint16_t)src->extra[5];

        if (use_src_ck && bpp == 2) {
            /* Per-pixel color key test for 16bpp */
            for (uint32_t y = 0; y < srcH; y++) {
                uint16_t* sp = (uint16_t*)(srcBuf + (srcY + y) * srcPitch + srcX * 2);
                uint16_t* dp = (uint16_t*)(dstBuf + (dstY + y) * dstPitch + dstX * 2);
                for (uint32_t x = 0; x < srcW; x++) {
                    if (sp[x] != ck16)
                        dp[x] = sp[x];
                }
            }
        } else {
            /* No color keying - fast memcpy path */
            uint32_t rowBytes = srcW * bpp;
            for (uint32_t y = 0; y < srcH; y++) {
                memcpy(dstBuf + (dstY + y) * dstPitch + dstX * bpp,
                       srcBuf + (srcY + y) * srcPitch + srcX * bpp,
                       rowBytes);
            }
        }
    }
    g_eax = 0;
    g_esp += 28; /* pop ret + 6 args */
}

static void dds_GetPixelFormat(void) {
    /* this=esp+4, pFormat=esp+8 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pFmt = MEM32(g_esp + 8);
    mock_com_obj_t* surf = (mock_com_obj_t*)(uintptr_t)pThis;
    if (pFmt) {
        MEM32(pFmt + 0) = 32; /* dwSize */
        MEM32(pFmt + 4) = 0x40; /* DDPF_RGB */
        uint32_t _bpp = surf->extra[3] ? surf->extra[3] : 16;
        MEM32(pFmt + 12) = _bpp;
        if (_bpp == 32) { MEM32(pFmt + 16) = 0x00FF0000; MEM32(pFmt + 20) = 0x0000FF00; MEM32(pFmt + 24) = 0x000000FF; }
        else            { MEM32(pFmt + 16) = 0xF800;     MEM32(pFmt + 20) = 0x07E0;     MEM32(pFmt + 24) = 0x001F; }
    }
    g_eax = 0;
    g_esp += 12;
}

static void dds_IsLost(void) {
    /* this=esp+4 */
    g_eax = 0; /* not lost */
    g_esp += 8;
}

static void dds_Restore(void) {
    /* this=esp+4 */
    g_eax = 0;
    g_esp += 8;
}

/* Track the DC-to-surface mapping for ReleaseDC */
#define MAX_SURFACE_DCS 4
static struct {
    HDC hdc;
    HDC memdc;
    HBITMAP dib;
    void* dib_bits;
    mock_com_obj_t* surf;
} g_surface_dcs[MAX_SURFACE_DCS];

static void dds_GetDC(void) {
    /* this=esp+4, phDC=esp+8 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t phDC = MEM32(g_esp + 8);
    mock_com_obj_t* surf = (mock_com_obj_t*)(uintptr_t)pThis;

    if (!surf || !surf->extra[0] || !surf->extra[1] || !surf->extra[2]) {
        if (phDC) MEM32(phDC) = 0;
        g_eax = 0x80004005u; /* E_FAIL */
        g_esp += 12;
        return;
    }

    uint32_t w = surf->extra[1];
    uint32_t h = surf->extra[2];
    uint32_t bpp = surf->extra[3] ? surf->extra[3] : 16;

    /* Create a memory DC with a 16-bit RGB565 DIB section */
    HDC screenDC = GetDC(NULL);
    HDC memDC = CreateCompatibleDC(screenDC);
    ReleaseDC(NULL, screenDC);

    /* Set up BITMAPINFO for RGB565 */
    struct {
        BITMAPINFOHEADER bmiHeader;
        DWORD masks[3]; /* BI_BITFIELDS: R, G, B masks */
    } bmi;
    memset(&bmi, 0, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = (LONG)w;
    bmi.bmiHeader.biHeight = -(LONG)h; /* top-down */
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 16;
    bmi.bmiHeader.biCompression = BI_BITFIELDS;
    bmi.masks[0] = 0xF800; /* R */
    bmi.masks[1] = 0x07E0; /* G */
    bmi.masks[2] = 0x001F; /* B */

    void* dibBits = NULL;
    HBITMAP hDib = CreateDIBSection(memDC, (BITMAPINFO*)&bmi, DIB_RGB_COLORS, &dibBits, NULL, 0);
    if (!hDib || !dibBits) {
        DeleteDC(memDC);
        if (phDC) MEM32(phDC) = 0;
        g_eax = 0x80004005u;
        g_esp += 12;
        return;
    }
    SelectObject(memDC, hDib);

    /* Copy current surface pixels into the DIB so GDI sees current content */
    uint32_t pitch = surf->extra[4] ? surf->extra[4] : w * 2;
    uint32_t dib_pitch = (w * 2 + 3) & ~3; /* DIB rows are DWORD-aligned */
    uint8_t* src = (uint8_t*)(uintptr_t)surf->extra[0];
    uint8_t* dst = (uint8_t*)dibBits;
    for (uint32_t y = 0; y < h; y++) {
        memcpy(dst + y * dib_pitch, src + y * pitch, w * 2);
    }

    /* Store the mapping for ReleaseDC */
    for (int i = 0; i < MAX_SURFACE_DCS; i++) {
        if (!g_surface_dcs[i].hdc) {
            g_surface_dcs[i].hdc = memDC;
            g_surface_dcs[i].memdc = memDC;
            g_surface_dcs[i].dib = hDib;
            g_surface_dcs[i].dib_bits = dibBits;
            g_surface_dcs[i].surf = surf;
            break;
        }
    }

    if (phDC) MEM32(phDC) = (uint32_t)(uintptr_t)memDC;
    fprintf(stderr, "[COM] dds_GetDC(surf=0x%X %ux%u) -> DC=0x%X\n",
            pThis, w, h, (uint32_t)(uintptr_t)memDC);
    g_eax = 0;
    g_esp += 12;
}

static void dds_ReleaseDC(void) {
    /* this=esp+4, hDC=esp+8 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t hdc_val = MEM32(g_esp + 8);
    HDC hdc = (HDC)(uintptr_t)hdc_val;

    { static int _rc; if (_rc < 5) { fprintf(stderr, "[COM] dds_ReleaseDC(surf=0x%X hdc=0x%X)\n", pThis, hdc_val); _rc++; } }

    /* Find the mapping and copy DIB bits back to surface */
    int found = 0;
    for (int i = 0; i < MAX_SURFACE_DCS; i++) {
        if (g_surface_dcs[i].hdc == hdc) {
            found = 1;
            mock_com_obj_t* surf = g_surface_dcs[i].surf;
            if (surf && surf->extra[0]) {
                uint32_t w = surf->extra[1];
                uint32_t h = surf->extra[2];
                uint32_t pitch = surf->extra[4] ? surf->extra[4] : w * 2;
                uint32_t dib_pitch = (w * 2 + 3) & ~3;
                uint8_t* dst = (uint8_t*)(uintptr_t)surf->extra[0];
                uint8_t* src = (uint8_t*)g_surface_dcs[i].dib_bits;
                for (uint32_t y = 0; y < h; y++) {
                    memcpy(dst + y * pitch, src + y * dib_pitch, w * 2);
                }
                /* Font rendering: game renders text to surface 0x9F702E via GetDC
                 * but reads pixels from surface 0x9F7036 via Lock. Copy DIB bits
                 * to the paired surface so pixel readback finds the rendered text. */
                uint32_t surf702E = MEM32(0x9F702E);
                uint32_t surf7036 = MEM32(0x9F7036);
                if (pThis == surf702E && surf7036 && surf7036 != surf702E) {
                    mock_com_obj_t* paired = (mock_com_obj_t*)(uintptr_t)surf7036;
                    if (paired->extra[0] && paired->extra[1] == w && paired->extra[2] == h) {
                        uint32_t ppitch = paired->extra[4] ? paired->extra[4] : w * 2;
                        uint8_t* pdst = (uint8_t*)(uintptr_t)paired->extra[0];
                        /* Count non-zero pixels in DIB to verify GDI rendered text */
                        int nz = 0;
                        for (uint32_t y2 = 0; y2 < h && !nz; y2++)
                            for (uint32_t x2 = 0; x2 < w && !nz; x2++)
                                if (((uint16_t*)(src + y2 * dib_pitch))[x2]) nz = 1;
                        { static int _pc; if (_pc < 5) {
                            fprintf(stderr, "[COM] ReleaseDC paired copy: surf=0x%X→0x%X %ux%u dib_has_pixels=%d\n",
                                pThis, surf7036, w, h, nz);
                            fflush(stderr); _pc++;
                        } }
                        for (uint32_t y = 0; y < h; y++) {
                            memcpy(pdst + y * ppitch, src + y * dib_pitch, w * 2);
                        }
                    } else {
                        static int _pf; if (_pf < 3) {
                            fprintf(stderr, "[COM] ReleaseDC paired SKIP: paired->extra[0]=0x%X dims=%ux%u vs %ux%u\n",
                                paired->extra[0], paired->extra[1], paired->extra[2], w, h);
                            fflush(stderr); _pf++;
                        }
                    }
                }
            }
            DeleteObject(g_surface_dcs[i].dib);
            DeleteDC(g_surface_dcs[i].memdc);
            memset(&g_surface_dcs[i], 0, sizeof(g_surface_dcs[i]));
            break;
        }
    }
    if (!found) {
        /* Fallback: just delete the DC directly */
        static int _warn; if (_warn < 5) { fprintf(stderr, "[COM] dds_ReleaseDC: DC 0x%X not tracked, deleting directly\n", hdc_val); _warn++; }
        DeleteDC(hdc);
    }

    g_eax = 0;
    g_esp += 12;
}

static void dds_SetPalette(void) {
    /* this=esp+4, pPalette=esp+8 */
    g_eax = 0;
    g_esp += 12;
}

/* ============================================================
 * IDirectDrawPalette Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] GetCaps (2) [4] GetEntries (5) [5] Initialize (3)
 * [6] SetEntries (5)
 * ============================================================ */

static void ddp_SetEntries(void) {
    /* this=esp+4, flags=esp+8, start=esp+12, count=esp+16, entries=esp+20 */
    g_eax = 0;
    g_esp += 24;
}

static void ddp_GetEntries(void) {
    /* this=esp+4, flags=esp+8, start=esp+12, count=esp+16, entries=esp+20 */
    g_eax = 0;
    g_esp += 24;
}

/* ============================================================
 * IDirect3D Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] Initialize (1)
 * [4] EnumDevices (3)
 * [5] CreateLight (3)
 * [6] CreateMaterial (3)
 * [7] CreateViewport (3)
 * [8] FindDevice (3)
 * ============================================================ */

static void d3d_EnumDevices(void) {
    /* this=esp+4, callback=esp+8, ctx=esp+12 */
    uint32_t cb = MEM32(g_esp + 8);
    uint32_t ctx = MEM32(g_esp + 12);

    COM_LOG("[COM] IDirect3D::EnumDevices(cb=0x%08X, ctx=0x%08X)\n", cb, ctx);

    /* Call callback with a dummy device description.
     * Callback signature: HRESULT CALLBACK(GUID*, char* desc, char* name,
     *                     D3DDEVICEDESC* halDesc, D3DDEVICEDESC* helDesc, void* ctx)
     * That's 6 args, stdcall. */
    if (cb != 0) {
        /* We'll put dummy data in scratch area */
        uint32_t scratch = 0x00B0F200;
        memset((void*)(uintptr_t)scratch, 0, 0x400);

        /* GUID at scratch+0 (16 bytes) - just zeros */
        uint32_t guid_va = scratch;
        /* desc string at scratch+16 */
        uint32_t desc_va = scratch + 16;
        /* XWA gates its HARDWARE-3D path on a strcmp of the device name against "3dfx" / "voodoo"
         * (constants at 0x006012A0 / 0x006012A8; a match sets the master switch 0xB0C7BC = 1 at
         * 0x00520671, which flows into 0x77330C and decides software vs hardware -- #453).
         * "Mock Direct3D HAL" matched neither, so the engine always chose software. */
        strcpy((char*)(uintptr_t)desc_va, "3dfx Voodoo Graphics");
        /* name string at scratch+64 */
        uint32_t name_va = scratch + 64;
        strcpy((char*)(uintptr_t)name_va, "3dfx voodoo");
        /* D3DDEVICEDESC for HAL at scratch+128 (size=0xFC, 252 bytes). The game's enum callback
         * (sub_005991CC) rejects a device unless desc+8 (dcmColorModel) is non-zero, and it needs a
         * 16-bit render/z-buffer depth to run flight. Fill the required caps so the device is accepted. */
        uint32_t hal_desc_va = scratch + 128;
        MEM32(hal_desc_va) = 252;          /* dwSize */
        MEM32(hal_desc_va + 4) = 0x1F;      /* dwFlags */
        MEM32(hal_desc_va + 8) = 2;         /* dcmColorModel = D3DCOLOR_RGB (the accept gate) */
        MEM32(hal_desc_va + 0xC) = 0xFFFF;  /* dwDevCaps - broad */
        /* D3DDEVICEDESC layout (DX6, 0xFC bytes): dpcLineCaps at +0x2C, dpcTriCaps at +0x64
         * (D3DPRIMCAPS is 0x38 each), dwDeviceRenderBitDepth at +0x9C, dwDeviceZBufferBitDepth
         * at +0xA0. The old +0x24/+0x28 landed inside dtcTransformCaps/bClipping, which is why
         * the game's own enum log read back "|Non-Z|" and "0bpp". */
        MEM32(hal_desc_va + 0x24) = 0x400;  /* (kept: harmless legacy write) */
        MEM32(hal_desc_va + 0x28) = 0x400;
        if (getenv("XWA_D3DCAPS")) {
            MEM32(hal_desc_va + 0x64) = 0x38;        /* dpcTriCaps.dwSize */
            MEM32(hal_desc_va + 0x64 + 0x08) = 0x3FF; /* dwRasterCaps */
            MEM32(hal_desc_va + 0x64 + 0x0C) = 0xFF;  /* dwZCmpCaps */
            MEM32(hal_desc_va + 0x64 + 0x10) = 0x1FFF;/* dwSrcBlendCaps */
            MEM32(hal_desc_va + 0x64 + 0x14) = 0x1FFF;/* dwDestBlendCaps */
            MEM32(hal_desc_va + 0x64 + 0x18) = 0xFF;  /* dwAlphaCmpCaps */
            MEM32(hal_desc_va + 0x64 + 0x1C) = 0x3FFF;/* dwShadeCaps */
            MEM32(hal_desc_va + 0x64 + 0x20) = 0x4FFF; /* #328: widen dwTextureCaps (was 0x0F) -- Tex flag still 0 */
            MEM32(hal_desc_va + 0x64 + 0x24) = 0x3F;  /* dwTextureFilterCaps */
            MEM32(hal_desc_va + 0x64 + 0x28) = 0xFF;  /* dwTextureBlendCaps */
            MEM32(hal_desc_va + 0x64 + 0x2C) = 0x1F;  /* dwTextureAddressCaps */
            MEM32(hal_desc_va + 0x2C) = 0x38;         /* dpcLineCaps.dwSize */
            MEM32(hal_desc_va + 0x2C + 0x08) = 0x3FF;  /* line dwRasterCaps */
            MEM32(hal_desc_va + 0x2C + 0x0C) = 0xFF;   /* line dwZCmpCaps */
            MEM32(hal_desc_va + 0x2C + 0x20) = 0x4FFF; /* line dwTextureCaps */
            MEM32(hal_desc_va + 0x2C + 0x24) = 0x3F;   /* line dwTextureFilterCaps */
            MEM32(hal_desc_va + 0x2C + 0x28) = 0xFF;   /* line dwTextureBlendCaps */
            MEM32(hal_desc_va + 0x9C) = 0x400;        /* dwDeviceRenderBitDepth = DDBD_16 */
            MEM32(hal_desc_va + 0xA0) = 0x400;        /* dwDeviceZBufferBitDepth = DDBD_16 */
            MEM32(hal_desc_va + 0xA4) = 0x10000;      /* dwMaxBufferSize */
            MEM32(hal_desc_va + 0xA8) = 0x400;        /* dwMaxVertexCount */
            MEM32(hal_desc_va + 0xB4) = 256;          /* dwMaxTextureWidth */
            MEM32(hal_desc_va + 0xB8) = 256;          /* dwMaxTextureHeight */
        }
        /* D3DDEVICEDESC for HEL at scratch+384 */
        uint32_t hel_desc_va = scratch + 384;
        MEM32(hel_desc_va) = 252;
        MEM32(hel_desc_va + 4) = 0x1F;
        MEM32(hel_desc_va + 8) = 2;
        MEM32(hel_desc_va + 0xC) = 0xFFFF;
        MEM32(hel_desc_va + 0x24) = 0x400;
        MEM32(hel_desc_va + 0x28) = 0x400;
        if (getenv("XWA_D3DCAPS")) {
            for (uint32_t _o = 0; _o < 0x38; _o += 4) MEM32(hel_desc_va + 0x64 + _o) = MEM32(hal_desc_va + 0x64 + _o);
            MEM32(hel_desc_va + 0x2C) = 0x38;
            MEM32(hel_desc_va + 0x9C) = 0x400;
            MEM32(hel_desc_va + 0xA0) = 0x400;
            MEM32(hel_desc_va + 0xA4) = 0x10000;
            MEM32(hel_desc_va + 0xA8) = 0x400;
            MEM32(hel_desc_va + 0xB4) = 256;
            MEM32(hel_desc_va + 0xB8) = 256;
            /* Hand out IID_IDirect3DHALDevice so the surface QI below can recognise it. */
            MEM32(guid_va + 0) = 0x84E63DE0u; MEM32(guid_va + 4) = 0x11CF46AAu;
            MEM32(guid_va + 8) = 0x0000816Fu; MEM32(guid_va + 12) = 0x6E1520C0u;
        }

        uint32_t save_esp = g_esp;
        PUSH32(g_esp, ctx);
        PUSH32(g_esp, hel_desc_va);
        PUSH32(g_esp, hal_desc_va);
        PUSH32(g_esp, name_va);
        PUSH32(g_esp, desc_va);
        PUSH32(g_esp, guid_va);
        PUSH32(g_esp, 0xDEAD0098u);
        com_dispatch_callback(cb);
        g_esp = save_esp;
    }

    g_eax = 0;
    g_esp += 16; /* pop ret + 3 args */
}

static void d3d_CreateViewport(void) {
    /* this=esp+4, ppViewport=esp+8, pUnkOuter=esp+12 */
    uint32_t ppVP = MEM32(g_esp + 8);
    mock_com_obj_t* vp = alloc_mock(MOCK_TAG_D3DVIEWPORT, g_d3dviewport_vtable_addr);
    MEM32(ppVP) = (uint32_t)(uintptr_t)vp;
    COM_LOG("[COM] IDirect3D::CreateViewport -> 0x%08X\n", (uint32_t)(uintptr_t)vp);
    g_eax = 0;
    g_esp += 16;
}

static void d3d_CreateLight(void) {
    /* this=esp+4, ppLight=esp+8, pUnkOuter=esp+12 */
    /* Just return a non-null dummy value */
    uint32_t ppLight = MEM32(g_esp + 8);
    void* dummy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
    MEM32(ppLight) = (uint32_t)(uintptr_t)dummy;
    g_eax = 0;
    g_esp += 16;
}

static void d3d_CreateMaterial(void) {
    /* this=esp+4, ppMat=esp+8, pUnkOuter=esp+12 */
    uint32_t ppMat = MEM32(g_esp + 8);
    void* dummy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
    MEM32(ppMat) = (uint32_t)(uintptr_t)dummy;
    g_eax = 0;
    g_esp += 16;
}

/* ============================================================
 * IDirect3DDevice Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] Initialize (3)
 * [4] GetCaps (3) [5] SwapTextureHandles (3)
 * [6] CreateExecuteBuffer (4) [7] GetStats (2)
 * [8] Execute (4) [9] AddViewport (2) [10] DeleteViewport (2)
 * [11] NextViewport (4) [12] Pick (5) [13] GetPickRecords (3)
 * [14] EnumTextureFormats (3) [15] CreateMatrix (2) [16] SetMatrix (3)
 * [17] GetMatrix (3) [18] DeleteMatrix (2)
 * [19] BeginScene (1) [20] EndScene (1)
 * [21] GetDirect3D (2)
 * ============================================================ */

static void d3ddev_CreateExecuteBuffer(void) {
    /* this=esp+4, pDesc=esp+8, ppEB=esp+12, pUnkOuter=esp+16 */
    uint32_t pDesc = MEM32(g_esp + 8);
    uint32_t ppEB = MEM32(g_esp + 12);

    /* Read requested buffer size from D3DEXECUTEBUFFERDESC */
    uint32_t bufsize = MEM32(pDesc + 8); /* dwBufferSize at offset 8 */
    if (bufsize == 0) bufsize = 65536;

    { static int _eb; _eb++; g_eb_count = _eb;
      fprintf(stderr, "[EBOBJ] CreateExecuteBuffer #%d size=%u\n", _eb, bufsize); fflush(stderr); }
    { static int _c; if (_c < 4) { fprintf(stderr, "[D3DINIT] CreateExecuteBuffer(size=%u) — 3D render pipeline set up\n", bufsize); fflush(stderr); _c++; } }
    mock_com_obj_t* eb = alloc_mock(MOCK_TAG_D3DEXECBUF, g_d3dexecbuf_vtable_addr);
    /* Allocate actual buffer for execute buffer data */
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufsize);
    eb->extra[0] = (uint32_t)(uintptr_t)buf;
    eb->extra[1] = bufsize;
    MEM32(ppEB) = (uint32_t)(uintptr_t)eb;
    if (g_eb_count >= 1 && g_eb_count <= 4) g_eb_obj[g_eb_count-1] = (uint32_t)(uintptr_t)eb;
    /* EB#2 is created and then never Locked (#428). The guest must keep its pointer somewhere
     * in order to use it later -- find that slot so we can grep for the code that reads it.
     * Scan a moment later (at the next Execute) once the caller has had time to store it. */

    COM_LOG("[COM] IDirect3DDevice::CreateExecuteBuffer(size=%u) -> 0x%08X\n",
            bufsize, (uint32_t)(uintptr_t)eb);
    g_eax = 0;
    g_esp += 20;
}

static void d3ddev_AddViewport(void) {
    /* this=esp+4, pViewport=esp+8 */
    g_eax = 0;
    g_esp += 12;
}

static void d3ddev_EnumTextureFormats(void) {
    /* this=esp+4, callback=esp+8, ctx=esp+12 */
    uint32_t cb = MEM32(g_esp + 8);
    uint32_t ctx = MEM32(g_esp + 12);
    COM_LOG("[COM] IDirect3DDevice::EnumTextureFormats(cb=0x%08X)\n", cb);

    /* The callback takes a full DDSURFACEDESC (dwSize 0x6C), whose DDPIXELFORMAT lives at
     * +0x48 -- NOT a bare DDPIXELFORMAT. Writing the format at +0 meant the game read zeros
     * at +0x48 and reported "Error: no texture formats found", which failed device creation.
     * Enumerate what XWA actually looks for: RGB565, ARGB1555 and 8-bit palettized.
     * (Its own diagnostics mention "16-bit hicolor textures" and "8-bit palettized textures
     * for textures with no alpha".) Callback returns 0 to continue, non-zero to stop. */
    if (cb != 0) {
        static const uint32_t fmts[][6] = {
            /* flags,      bpp, R,      G,      B,      A */
            { 0x40,        16,  0xF800, 0x07E0, 0x001F, 0 },          /* RGB565 */
            { 0x40 | 0x01, 16,  0x7C00, 0x03E0, 0x001F, 0x8000 },     /* ARGB1555 */
            { 0x20,         8,  0,      0,      0,      0 },          /* PALETTEINDEXED8 */
        };
        for (int fi = 0; fi < 3; fi++) {
            uint32_t scratch = 0x00B0F600;
            memset((void*)(uintptr_t)scratch, 0, 0x6C);
            MEM32(scratch + 0x00) = 0x6C;          /* DDSURFACEDESC.dwSize */
            MEM32(scratch + 0x04) = 0x1000;        /* DDSD_PIXELFORMAT */
            uint32_t pf = scratch + 0x48;          /* ddpfPixelFormat */
            MEM32(pf + 0x00) = 32;                 /* DDPIXELFORMAT.dwSize */
            MEM32(pf + 0x04) = fmts[fi][0];        /* dwFlags */
            MEM32(pf + 0x0C) = fmts[fi][1];        /* dwRGBBitCount */
            MEM32(pf + 0x10) = fmts[fi][2];
            MEM32(pf + 0x14) = fmts[fi][3];
            MEM32(pf + 0x18) = fmts[fi][4];
            MEM32(pf + 0x1C) = fmts[fi][5];
            if (!getenv("XWA_D3DCAPS")) {          /* legacy shape, kept for the default build */
                memset((void*)(uintptr_t)scratch, 0, 64);
                MEM32(scratch + 0) = 32; MEM32(scratch + 4) = 0x40; MEM32(scratch + 12) = 16;
                MEM32(scratch + 16) = 0xF800; MEM32(scratch + 20) = 0x07E0; MEM32(scratch + 24) = 0x001F;
            }
            uint32_t save_esp = g_esp;
            PUSH32(g_esp, ctx);
            PUSH32(g_esp, scratch);
            PUSH32(g_esp, 0xDEAD0097u);
            com_dispatch_callback(cb);
            g_esp = save_esp;
            if (!getenv("XWA_D3DCAPS") || g_eax != 0) break;   /* D3DENUMRET_CANCEL */
        }
    }

    g_eax = 0;
    g_esp += 16;
}

static void d3ddev_GetCaps(void) {
    /* this=esp+4, pHalCaps=esp+8, pHelCaps=esp+12 */
    uint32_t pHal = MEM32(g_esp + 8);
    uint32_t pHel = MEM32(g_esp + 12);
    /* Leave caps mostly zeroed - minimal D3D1-era device */
    if (pHal) MEM32(pHal) = 252; /* dwSize */
    if (pHel) MEM32(pHel) = 252;
    g_eax = 0;
    g_esp += 16;
}

static void d3ddev_BeginScene(void) {
    { static int _c; if (_c < 4) { fprintf(stderr, "[D3DSCENE] BeginScene called\n"); fflush(stderr); _c++; } }
    d3d11_begin_scene();
    g_eax = 0;
    g_esp += 8;
}

static void d3ddev_EndScene(void) {
    d3d11_end_scene();
    g_eax = 0;
    g_esp += 8;
}

/* Expose a mock IDirect3DDevice object (guest address) for force-launch flight rendering.
 * The game's device-create (sub_0059453F) is skipped under force-launch, leaving the device
 * interface global 0x7B15BC null; main.c points it here at flight-init so the 3D execute-buffer
 * render path (sub_00597F9F -> device->Execute) reaches d3ddev_Execute -> d3d11 instead of crashing. */
uint32_t com_ensure_d3d_device(void) {
    static mock_com_obj_t* dev = NULL;
    if (!dev && g_d3ddevice_vtable_addr) dev = alloc_mock(MOCK_TAG_D3D, g_d3ddevice_vtable_addr);
    return dev ? (uint32_t)(uintptr_t)dev : 0;
}

static void d3ddev_Execute(void) {
    /* XWA_EBWHO2: identify the GUEST function that submits. At bridge entry MEM32(g_esp) is
     * the return address into guest code, which pins down who fills the execute buffer. */
    if (getenv("XWA_EBWHO2")) { static int _n; if (_n < 6) { _n++;
        fprintf(stderr, "[EBWHO2] Execute called from guest ret=0x%08X\n", MEM32(g_esp)); fflush(stderr); } }
    { extern unsigned g_rcount[8]; g_rcount[7]++; }
    /* this=esp+4, pEB=esp+8, pViewport=esp+12, flags=esp+16 */
    uint32_t pEB = MEM32(g_esp + 8);
    fprintf(stderr, "[EBOBJ] Execute pEB=0x%08X\n", pEB); fflush(stderr);
    { static int _c; if (_c < 8) { uint32_t vc = 0; if (pEB) { mock_com_obj_t* e=(mock_com_obj_t*)(uintptr_t)pEB; vc=e->extra[3]; }
        fprintf(stderr, "[D3DEXEC] IDirect3DDevice::Execute called: pEB=0x%X vertexCount=%u\n", pEB, vc); fflush(stderr); _c++; } }

    if (pEB && d3d11_is_initialized()) {
        mock_com_obj_t* eb = (mock_com_obj_t*)(uintptr_t)pEB;
        uint8_t* buffer_data = (uint8_t*)(uintptr_t)eb->extra[0];
        /* Execute data stored in extra[2..6]:
         * extra[2] = dwVertexOffset, extra[3] = dwVertexCount
         * extra[4] = dwInstructionOffset, extra[5] = dwInstructionLength */
        uint32_t vertex_offset = eb->extra[2];
        uint32_t vertex_count = eb->extra[3];
        uint32_t inst_offset = eb->extra[4];
        uint32_t inst_length = eb->extra[5];

        if (buffer_data && vertex_count > 0 && inst_length > 0) {
            d3d11_execute(buffer_data, vertex_offset, vertex_count, inst_offset, inst_length);
        }
    }

    g_eax = 0;
    g_esp += 20;
}

static void d3ddev_CreateMatrix(void) {
    /* this=esp+4, pHandle=esp+8 */
    uint32_t pHandle = MEM32(g_esp + 8);
    static uint32_t next_matrix = 1;
    if (pHandle) MEM32(pHandle) = next_matrix++;
    g_eax = 0;
    g_esp += 12;
}

static void d3ddev_SetMatrix(void) {
    /* this=esp+4, handle=esp+8, pMatrix=esp+12 */
    g_eax = 0;
    g_esp += 16;
}

static void d3ddev_GetMatrix(void) {
    /* this=esp+4, handle=esp+8, pMatrix=esp+12 */
    g_eax = 0;
    g_esp += 16;
}

static void d3ddev_DeleteMatrix(void) {
    /* this=esp+4, handle=esp+8 */
    g_eax = 0;
    g_esp += 12;
}

static void d3ddev_GetDirect3D(void) {
    /* this=esp+4, ppD3D=esp+8 */
    uint32_t ppD3D = MEM32(g_esp + 8);
    mock_com_obj_t* d3d = alloc_mock(MOCK_TAG_D3D, g_d3d_vtable_addr);
    MEM32(ppD3D) = (uint32_t)(uintptr_t)d3d;
    g_eax = 0;
    g_esp += 12;
}

/* ============================================================
 * IDirect3DViewport Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] Initialize (2) [4] GetViewport (2) [5] SetViewport (2)
 * [6] TransformVertices (5) [7] LightElements (3)
 * [8] SetBackground (2) [9] GetBackground (3)
 * [10] SetBackgroundDepth (2) [11] GetBackgroundDepth (2)
 * [12] Clear (5) [13] AddLight (2) [14] DeleteLight (2)
 * [15] NextLight (4)
 * ============================================================ */

static void d3dvp_SetViewport(void) {
    /* this=esp+4, pData=esp+8 */
    /* D3DVIEWPORT structure:
     * +0  dwSize, +4 dwX, +8 dwY, +12 dwWidth, +16 dwHeight
     * +20 dvScaleX, +24 dvScaleY, +28 dvMaxX, +32 dvMaxY
     * +36 dvMinZ, +40 dvMaxZ */
    uint32_t pData = MEM32(g_esp + 8);
    if (pData && d3d11_is_initialized()) {
        uint32_t x = MEM32(pData + 4);
        uint32_t y = MEM32(pData + 8);
        uint32_t w = MEM32(pData + 12);
        uint32_t h = MEM32(pData + 16);
        d3d11_set_viewport(x, y, w, h);
    }
    g_eax = 0;
    g_esp += 12;
}

static void d3dvp_Clear(void) {
    /* this=esp+4, count=esp+8, pRects=esp+12, flags=esp+16 */
    g_eax = 0;
    g_esp += 20; /* pop ret + 4 args */
}

/* ============================================================
 * IDirect3DExecuteBuffer Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] Initialize (3) [4] Lock (2) [5] Unlock (1)
 * [6] SetExecuteData (2) [7] GetExecuteData (2)
 * [8] Validate (5) [9] Optimize (2)
 * ============================================================ */

static void d3deb_Lock(void) {
    /* XWA_EBWHO2: identify the GUEST function that submits. At bridge entry MEM32(g_esp) is
     * the return address into guest code, which pins down who fills the execute buffer. */
    if (getenv("XWA_EBWHO2")) { static int _n; if (_n < 6) { _n++;
        fprintf(stderr, "[EBWHO2] Lock called from guest ret=0x%08X\n", MEM32(g_esp)); fflush(stderr); } }
    /* this=esp+4, pDesc=esp+8 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pDesc = MEM32(g_esp + 8);
    mock_com_obj_t* eb = (mock_com_obj_t*)(uintptr_t)pThis;

    if (pDesc) {
        /* D3DEXECUTEBUFFERDESC: dwSize=+0, dwFlags=+4, dwCaps=+8,
         * dwBufferSize=+12, lpData=+16 */
        MEM32(pDesc + 0) = 24; /* dwSize */
        /* D3DDEB_BUFSIZE(1) | D3DDEB_CAPS(2) | D3DDEB_LPDATA(4). LPDATA was MISSING: without it
         * the caller has no reason to treat lpData as valid, which fits the observed symptom
         * (execute buffer created, never filled: SetExecuteData once with vCount=0). */
        MEM32(pDesc + 4) = 0x7;
        g_eb_data = eb->extra[0]; g_eb_size = eb->extra[1];
        fprintf(stderr, "[EBOBJ] Lock this=0x%08X\n", pThis); fflush(stderr);
        /* Identify the guest code that locks the buffer: it holds lpData transiently (it is
         * never stored to any guest global -- scanned 0x600000-0xB00000, not found) and it is
         * the intended vertex writer, since the 208 instruction bytes DO get written. */
        { extern volatile unsigned g_lastblk;
          fprintf(stderr, "[EBWHO] Lock called with last guest block L_%08X\n", g_lastblk);
          fflush(stderr); }
        { static unsigned _n; _n++; if (_n <= 6 || (_n % 500) == 0) {
            fprintf(stderr, "[D3DLOCK] execute-buffer Lock #%u -> lpData=0x%08X size=%u\n",
                    _n, eb->extra[0], eb->extra[1]); fflush(stderr); } }
        MEM32(pDesc + 12) = eb->extra[1]; /* dwBufferSize */
        MEM32(pDesc + 16) = eb->extra[0]; /* lpData */
    }
    g_eax = 0;
    g_esp += 12;
}

static void d3deb_Unlock(void) {
    g_eax = 0;
    g_esp += 8;
}

static void d3deb_SetExecuteData(void) {
    /* this=esp+4, pData=esp+8 */
    /* D3DEXECUTEDATA structure:
     * +0  dwSize
     * +4  dwVertexOffset
     * +8  dwVertexCount
     * +12 dwInstructionOffset
     * +16 dwInstructionLength
     * +20 dwHVertexOffset
     * +24 dwStatus
     */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pData = MEM32(g_esp + 8);
    mock_com_obj_t* eb = (mock_com_obj_t*)(uintptr_t)pThis;
    fprintf(stderr, "[EBOBJ] SetExecuteData this=0x%08X\n", pThis); fflush(stderr);

    if (pData) {
        eb->extra[2] = MEM32(pData + 4);  /* dwVertexOffset */
        eb->extra[3] = MEM32(pData + 8);  /* dwVertexCount */
        eb->extra[4] = MEM32(pData + 12); /* dwInstructionOffset */
        eb->extra[5] = MEM32(pData + 16); /* dwInstructionLength */
        /* Did the guest actually WRITE anything into the locked buffer? If the region is
         * untouched beyond the instruction bytes, the vertex emitter never ran; if it holds
         * data but dwVertexCount is 0, the bug is in whoever fills D3DEXECUTEDATA. */
        if (g_eb_data && g_eb_size) {
            const uint8_t* b = (const uint8_t*)(uintptr_t)g_eb_data;
            uint32_t nz = 0, last = 0;
            for (uint32_t i = 0; i < g_eb_size; i++) if (b[i]) { nz++; last = i; }
            /* Find WHICH guest global holds the locked buffer pointer: whoever stores lpData
             * is the intended vertex writer. Scan the guest data range for the value. */
            { uint32_t found = 0;
              for (uint32_t a = 0x00600000u; a < 0x00B00000u; a += 4) {
                  if (MEM32(a) == g_eb_data) {
                      fprintf(stderr, "[EBPTR] lpData 0x%08X stored at guest global 0x%06X\n",
                              g_eb_data, a);
                      if (++found >= 8) break;
                  }
              }
              if (!found) fprintf(stderr, "[EBPTR] lpData not found in 0x600000-0xB00000\n");
              fflush(stderr); }
            fprintf(stderr, "[EBSCAN] buffer non-zero bytes=%u lastOffset=%u (size=%u)\n",
                    nz, last, g_eb_size); fflush(stderr);
        }
        { static unsigned _n; _n++;
          if (_n <= 10 || (_n % 500) == 0)
              fprintf(stderr, "[D3DSED] #%u vOff=%u vCount=%u iOff=%u iLen=%u\n",
                      _n, eb->extra[2], eb->extra[3], eb->extra[4], eb->extra[5]);
          fflush(stderr); }
    } else { static int _z; if (_z<3){_z++; fprintf(stderr, "[D3DSED] called with NULL pData\n"); fflush(stderr);} }

    g_eax = 0;
    g_esp += 12;
}

/* ============================================================
 * IDirect3DTexture Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] Initialize (3) [4] GetHandle (3) [5] PaletteChanged (3)
 * [6] Load (2) [7] Unload (1)
 * ============================================================ */

static void d3dtex_GetHandle(void) {
    /* this=esp+4, pDevice=esp+8, pHandle=esp+12 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pHandle = MEM32(g_esp + 12);

    mock_com_obj_t* tex_obj = (mock_com_obj_t*)(uintptr_t)pThis;
    /* extra[0] = pointer to the underlying surface mock */
    mock_com_obj_t* surf = (mock_com_obj_t*)(uintptr_t)tex_obj->extra[0];

    /* Assign a texture handle if not already assigned */
    uint32_t handle = tex_obj->extra[1];
    if (handle == 0) {
        handle = g_next_texture_handle++;
        tex_obj->extra[1] = handle;

        /* Register with D3D11 renderer */
        if (surf && surf->extra[0]) {
            d3d11_register_texture(handle,
                (uint8_t*)(uintptr_t)surf->extra[0],  /* pixels */
                surf->extra[1],   /* width */
                surf->extra[2],   /* height */
                surf->extra[4],   /* pitch */
                surf->extra[3]    /* bpp */
            );
        }
        COM_LOG("[COM] IDirect3DTexture::GetHandle -> %u (surf=0x%08X, %ux%u)\n",
                handle, (uint32_t)(uintptr_t)surf,
                surf ? surf->extra[1] : 0, surf ? surf->extra[2] : 0);
    }

    if (pHandle) MEM32(pHandle) = handle;
    g_eax = 0;
    g_esp += 16; /* pop ret + 3 args */
}

static void d3dtex_Load(void) {
    /* this=esp+4, pSrcTexture=esp+8 */
    /* Copy texture data from source to this texture */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pSrc = MEM32(g_esp + 8);
    mock_com_obj_t* dst_tex = (mock_com_obj_t*)(uintptr_t)pThis;
    mock_com_obj_t* src_tex = (mock_com_obj_t*)(uintptr_t)pSrc;
    /* Only act on our own texture mocks. After the hangar exit the game has been seen handing a
     * stale texture record here (freed and reused heap), and reading its extra[] faulted. A real
     * driver would reject a bad interface with DDERR_INVALIDOBJECT rather than copy from it. */
    {   extern int xwa_readable(uint32_t, uint32_t);
        if (!dst_tex || !src_tex || !xwa_readable(pThis, sizeof(mock_com_obj_t)) ||
            !xwa_readable(pSrc, sizeof(mock_com_obj_t)) ||
            dst_tex->tag != MOCK_TAG_D3D || src_tex->tag != MOCK_TAG_D3D) {
            static int _n; if (_n < 3) { _n++;
                fprintf(stderr, "[COM] IDirect3DTexture::Load: not a texture mock (this=0x%08X src=0x%08X) -> DDERR_INVALIDOBJECT\n", pThis, pSrc); fflush(stderr); }
            g_eax = 0x88760082u;   /* DDERR_INVALIDOBJECT */
            g_esp += 12;
            return;
        }
    }

    if (dst_tex && src_tex) {
        mock_com_obj_t* dst_surf = (mock_com_obj_t*)(uintptr_t)dst_tex->extra[0];
        mock_com_obj_t* src_surf = (mock_com_obj_t*)(uintptr_t)src_tex->extra[0];
        if (dst_surf && src_surf && dst_surf->extra[0] && src_surf->extra[0]) {
            uint32_t w = dst_surf->extra[1];
            uint32_t h = dst_surf->extra[2];
            uint32_t pitch = dst_surf->extra[4];
            uint32_t src_pitch = src_surf->extra[4];
            uint32_t src_h = src_surf->extra[2];
            uint32_t copy_h = (h < src_h) ? h : src_h;
            uint32_t copy_pitch = (pitch < src_pitch) ? pitch : src_pitch;
            for (uint32_t y = 0; y < copy_h; y++) {
                memcpy((void*)(uintptr_t)(dst_surf->extra[0] + y * pitch),
                       (void*)(uintptr_t)(src_surf->extra[0] + y * src_pitch),
                       copy_pitch);
            }

            /* Invalidate D3D11 texture so it gets re-uploaded */
            uint32_t handle = dst_tex->extra[1];
            if (handle > 0) {
                d3d11_invalidate_texture(handle);
            }
        }
    }

    g_eax = 0;
    g_esp += 12;
}

/* ============================================================
 * IDirectInput Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] CreateDevice (4) [4] EnumDevices (4)
 * [5] GetDeviceStatus (2) [6] RunControlPanel (3)
 * [7] Initialize (3)
 * ============================================================ */

static void di_CreateDevice(void) {
    /* this=esp+4, rguid=esp+8, ppDevice=esp+12, pUnkOuter=esp+16 */
    uint32_t rguid = MEM32(g_esp + 8);
    uint32_t ppDev = MEM32(g_esp + 12);
    mock_com_obj_t* dev = alloc_mock(MOCK_TAG_DIDEVICE, g_didevice_vtable_addr);

    /* Identify device type from GUID.
     * GUID_SysKeyboard: {6F1D2B61-D5A0-11CF-BFC7-444553540000}
     * GUID_SysMouse:    {6F1D2B60-D5A0-11CF-BFC7-444553540000} */
    uint32_t dev_type = DIDEV_TYPE_UNKNOWN;
    if (rguid) {
        uint32_t guid_data1 = MEM32(rguid);
        if (guid_data1 == 0x6F1D2B61)
            dev_type = DIDEV_TYPE_KEYBOARD;
        else if (guid_data1 == 0x6F1D2B60)
            dev_type = DIDEV_TYPE_MOUSE;
        else
            dev_type = DIDEV_TYPE_JOYSTICK; /* assume joystick for any other GUID */
    }
    dev->extra[2] = dev_type;

    MEM32(ppDev) = (uint32_t)(uintptr_t)dev;
    COM_LOG("[COM] IDirectInput::CreateDevice(type=%u) -> 0x%08X\n", dev_type, (uint32_t)(uintptr_t)dev);
    g_eax = 0;
    g_esp += 20;
}

static void di_EnumDevices(void) {
    /* this=esp+4, devType=esp+8, callback=esp+12, ctx=esp+16 */
    uint32_t devType = MEM32(g_esp + 8);
    uint32_t cb = MEM32(g_esp + 12);
    uint32_t ctx = MEM32(g_esp + 16);
    COM_LOG("[COM] IDirectInput::EnumDevices(type=%u, cb=0x%08X)\n", devType, cb);

    /* Call callback with a keyboard device instance.
     * DIDEVICEINSTANCE: dwSize=+0, guidInstance=+4, guidProduct=+20,
     * dwDevType=+36, tszInstanceName=+40, tszProductName=+302 */
    if (cb != 0) {
        uint32_t scratch = 0x00B0F800;
        memset((void*)(uintptr_t)scratch, 0, 0x400);
        MEM32(scratch + 0) = 560; /* sizeof(DIDEVICEINSTANCEA) */
        MEM32(scratch + 36) = 0x12; /* DI8DEVTYPE_KEYBOARD | DIDEVTYPEKEYBOARD_PCENH */
        strcpy((char*)(uintptr_t)(scratch + 40), "Keyboard");
        strcpy((char*)(uintptr_t)(scratch + 302), "Mock Keyboard");

        uint32_t save_esp = g_esp;
        PUSH32(g_esp, ctx);
        PUSH32(g_esp, scratch);
        PUSH32(g_esp, 0xDEAD0096u);
        com_dispatch_callback(cb);
        g_esp = save_esp;
    }

    g_eax = 0;
    g_esp += 24; /* pop ret + 5 args (this, devType, callback, ctx, dwFlags) */
}

/* ============================================================
 * IDirectInputDevice Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] GetCapabilities (2) [4] EnumObjects (4) [5] GetProperty (3)
 * [6] SetProperty (3) [7] Acquire (1) [8] Unacquire (1)
 * [9] GetDeviceState (3) [10] GetDeviceData (5) [11] SetDataFormat (2)
 * [12] SetEventNotification (2) [13] SetCooperativeLevel (3)
 * [14] GetObjectInfo (4) [15] GetDeviceInfo (2)
 * [16] RunControlPanel (3) [17] Initialize (4)
 * ============================================================ */

static void didev_GetDeviceState(void) {
    /* this=esp+4, cbData=esp+8, lpvData=esp+12 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t cbData = MEM32(g_esp + 8);
    uint32_t lpvData = MEM32(g_esp + 12);

    if (!lpvData || cbData == 0) {
        g_eax = 0;
        g_esp += 16;
        return;
    }

    /* Zero-fill first, then populate with real data */
    memset((void*)(uintptr_t)lpvData, 0, cbData);

    /* Determine device type from the mock object */
    mock_com_obj_t* dev = (mock_com_obj_t*)(uintptr_t)pThis;
    uint32_t dev_type = dev->extra[2];

    if (dev_type == DIDEV_TYPE_KEYBOARD && cbData >= 256) {
        /* Fill 256-byte DirectInput keyboard state.
         * DIK scancodes = hardware scan codes. 0x80 = pressed. */
        init_vk_to_dik_table();
        BYTE vk_state[256];
        /* Same focus rule as the mouse below: do not read the real keyboard while the game window
         * is in the background, or whatever the person at the machine types leaks into the game.
         * The synthetic XWA_SENDKEY path further down is unaffected -- it writes the state array
         * itself, which is what a scripted run needs. XWA_REALMOUSE=1 also restores this. */
        int kbd_owns_input;
        {   static int _kf = -1;
            if (_kf < 0) _kf = getenv("XWA_REALMOUSE") ? 1 : 0;
            kbd_owns_input = _kf || (g_game_hwnd && GetForegroundWindow() == g_game_hwnd);
        }
        if (kbd_owns_input && GetKeyboardState(vk_state)) {
            uint8_t* di_state = (uint8_t*)(uintptr_t)lpvData;
            for (int vk = 0; vk < 256; vk++) {
                if (vk_state[vk] & 0x80) {
                    uint8_t dik = g_vk_to_dik[vk];
                    if (dik > 0)
                        di_state[dik] = 0x80;
                }
            }
        }
        /* XWA_SENDKEY also drives the UNBUFFERED path: screens that poll GetDeviceState
         * (rather than GetDeviceData) see nothing headlessly, since GetKeyboardState
         * reports a real, idle keyboard. Hold the synthetic key down for a few polls at
         * the same cadence so either input style can be answered. */
        { const char* _k = getenv("XWA_SENDKEY");
          if (_k) {
            static uint32_t _n; _n++;
            { extern int g_in_flight; static int _gif = -1;
              if (_gif < 0) _gif = getenv("XWA_KEYINFLIGHT") ? 1 : 0;
              if (_gif && !g_in_flight) _n = 0; }
            const char* _a = getenv("XWA_KEYAFTER"); const char* _e = getenv("XWA_KEYEVERY");
            uint32_t _after = _a ? (uint32_t)strtoul(_a,NULL,0) : 400u;
            uint32_t _every = _e ? (uint32_t)strtoul(_e,NULL,0) : 120u;
            uint32_t _sc = (uint32_t)strtoul(_k, NULL, 0) & 0xFFu;
            if (_n > _after && _sc && ((_n - _after) % _every) < 4u) {
                ((uint8_t*)(uintptr_t)lpvData)[_sc] = 0x80;
                { static int _p; if (_p < 4) { _p++;
                    fprintf(stderr, "[KEY] state-array hold 0x%02X (poll %u)\n", _sc, _n); fflush(stderr); } }
            }
          } }
    } else if (dev_type == DIDEV_TYPE_MOUSE && cbData >= 16) {
        /* DIMOUSESTATE: lX(4), lY(4), lZ(4), rgbButtons[4]
         *
         * GetCursorPos and GetAsyncKeyState are MACHINE-WIDE: they report the physical pointer and
         * buttons whether or not this window has focus. A scripted run in a background window was
         * therefore fed whatever the person at the keyboard was doing -- their mouse motion became
         * view/menu movement and their clicks became game clicks, which derails the automated
         * frontend navigation and looks exactly like a nondeterministic engine bug. Only sample the
         * real device while the game window is actually the foreground window; otherwise report a
         * still, unclicked mouse. XWA_REALMOUSE=1 restores the old always-sample behaviour. */
        int owns_input;
        {   static int _force = -1;
            if (_force < 0) _force = getenv("XWA_REALMOUSE") ? 1 : 0;
            owns_input = _force || (g_game_hwnd && GetForegroundWindow() == g_game_hwnd);
        }
        int32_t* state = (int32_t*)(uintptr_t)lpvData;
        uint8_t* buttons = (uint8_t*)(uintptr_t)(lpvData + 12);
        state[0] = 0; state[1] = 0; state[2] = 0;
        if (!owns_input) {
            /* Drop the tracking origin too, so regaining focus does not deliver one huge delta
             * built from wherever the pointer wandered while we were in the background. */
            g_mouse_tracking = 0;
        } else {
            POINT cur;
            GetCursorPos(&cur);
            if (g_mouse_tracking) {
                state[0] = (int32_t)(cur.x - g_mouse_last_pos.x);   /* lX - relative X */
                state[1] = (int32_t)(cur.y - g_mouse_last_pos.y);   /* lY - relative Y */
            }
            g_mouse_last_pos = cur;
            g_mouse_tracking = 1;
            if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) buttons[0] = 0x80;
            if (GetAsyncKeyState(VK_RBUTTON) & 0x8000) buttons[1] = 0x80;
            if (GetAsyncKeyState(VK_MBUTTON) & 0x8000) buttons[2] = 0x80;
        }
    }
    /* For joystick/unknown: leave zeroed (centered, no buttons) */

    g_eax = 0;  /* DI_OK */
    g_esp += 16;
}

static void didev_GetDeviceData(void) {
    { extern int g_in_flight; static unsigned c, cf;
      if (getenv("XWA_INPUTDBG")) { c++; if (g_in_flight) cf++;
        if (c == 1 || cf == 1 || (cf && (cf % 500) == 0))
          { fprintf(stderr, "[INPUTDBG] DI_GetDeviceData calls=%u inflight=%u\n", c, cf); fflush(stderr); } } }

    /* this=esp+4, cbObjData=esp+8, rgdod=esp+12, pdwItems=esp+16, flags=esp+20 */
    uint32_t pdwItems = MEM32(g_esp + 16);
    /* No data available.
     * Returning DI_OK(0) with 0 items HANGS the game: sub_0042B740 (the input poll reached
     * from the render driver sub_00433850 and from the flight loop at 0x00510CB7) does
     *     GetDeviceData;  if (hr < 0) exit;  if (*pdwItems == 0) goto poll_again;
     * at 0x0042B7AD/0x0042B7B5 -- so it busy-waits until at least one item arrives and never
     * returns. The loop only terminates on a NEGATIVE HRESULT or a non-zero item count.
     * DIERR_NOTACQUIRED is both negative and truthful for a mock device that is never
     * really acquired, and it is NOT DIERR_INPUTLOST (0x8007001E), which the caller handles
     * by re-acquiring and looping again. */
    /* Buffered keyboard events, kept in a queue so DIGDD_PEEK (flags bit 0) can look without
     * consuming. The game's kbhit (sub_0042B520) PEEKs and its getch (sub_0042B740) then reads the
     * same event -- this is how the in-flight hangar menu (sub_0045C680) gets ENTER. Without a
     * queue, kbhit swallowed the press and getch returned 0, so no menu item could be picked by a
     * script OR by a person: real keys never reached this path at all before.
     * DIDEVICEOBJECTDATA = {dwOfs (DIK scancode), dwData (0x80 down / 0 up), dwTimeStamp, dwSequence}.
     *
     * XWA_SENDKEY=<scancode>: queue a press+release every XWA_KEYEVERY calls after XWA_KEYAFTER
     * calls (XWA_KEYINFLIGHT=1 counts flight calls only). DIK_RETURN = 0x1C. */
    {   static uint8_t q_sc[64], q_dn[64]; static unsigned q_head, q_tail, seq;
        static uint8_t prev[256];
        mock_com_obj_t* dev = (mock_com_obj_t*)(uintptr_t)MEM32(g_esp + 4);
        uint32_t rgdod = MEM32(g_esp + 12), cb = MEM32(g_esp + 8), flags = MEM32(g_esp + 20);
        #define Q_PUSH(sc, dn) do { if (q_tail - q_head < 64u) { q_sc[q_tail & 63] = (uint8_t)(sc); \
                                    q_dn[q_tail & 63] = (uint8_t)(dn); q_tail++; } } while (0)
        if (dev->extra[2] == DIDEV_TYPE_KEYBOARD) {
            /* Real key edges, under the same focus rule as GetDeviceState. */
            static int _kf = -1; BYTE vk_state[256]; uint8_t now[256]; int vk, k;
            if (_kf < 0) _kf = getenv("XWA_REALMOUSE") ? 1 : 0;
            memset(now, 0, sizeof now);
            if ((_kf || (g_game_hwnd && GetForegroundWindow() == g_game_hwnd)) && GetKeyboardState(vk_state)) {
                init_vk_to_dik_table();
                for (vk = 0; vk < 256; vk++)
                    if ((vk_state[vk] & 0x80) && g_vk_to_dik[vk]) now[g_vk_to_dik[vk]] = 0x80;
            }
            for (k = 1; k < 256; k++) if (now[k] != prev[k]) Q_PUSH(k, now[k]);
            memcpy(prev, now, sizeof prev);
        }
        {   const char* _k = getenv("XWA_SENDKEY");
            if (_k) {
                static uint32_t _n; _n++;
                { extern int g_in_flight; static int _gif = -1;
                  if (_gif < 0) _gif = getenv("XWA_KEYINFLIGHT") ? 1 : 0;
                  if (_gif && !g_in_flight) _n = 0; }
                const char* _a = getenv("XWA_KEYAFTER"); const char* _e = getenv("XWA_KEYEVERY");
                uint32_t _after = _a ? (uint32_t)strtoul(_a,NULL,0) : 400u;
                uint32_t _every = _e ? (uint32_t)strtoul(_e,NULL,0) : 120u;
                if (_every < 2u) _every = 2u;
                if (_n > _after && (_n - _after) % _every == 0) {
                    uint32_t _sc = (uint32_t)strtoul(_k, NULL, 0) & 0xFFu;
                    Q_PUSH(_sc, 0x80); Q_PUSH(_sc, 0);
                    { static int _p; if (_p < 6) { _p++;
                        fprintf(stderr, "[KEY] queued scancode 0x%02X press+release (call %u)\n", _sc, _n); fflush(stderr); } }
                }
            } }
        #undef Q_PUSH
        if (q_head != q_tail && rgdod && cb >= 16 && pdwItems && MEM32(pdwItems) >= 1) {
            MEM32(rgdod + 0) = q_sc[q_head & 63];
            MEM32(rgdod + 4) = q_dn[q_head & 63];
            MEM32(rgdod + 8) = GetTickCount();
            MEM32(rgdod + 12) = ++seq;
            MEM32(pdwItems) = 1;
            if (!(flags & 1u)) q_head++;   /* DIGDD_PEEK leaves it queued */
            g_eax = 0; g_esp += 24; return;
        }
    }
    if (pdwItems) MEM32(pdwItems) = 0;
    g_eax = 0x8007001Cu;   /* DIERR_NOTACQUIRED */
    g_esp += 24;
}

static void didev_GetCapabilities(void) {
    /* this=esp+4, pCaps=esp+8 */
    uint32_t pCaps = MEM32(g_esp + 8);
    if (pCaps) {
        /* DIDEVCAPS: dwSize=+0, dwFlags=+4, dwDevType=+8 */
        MEM32(pCaps + 4) = 0; /* no special flags */
        MEM32(pCaps + 8) = 0x12; /* keyboard */
    }
    g_eax = 0;
    g_esp += 12;
}

static void didev_EnumObjects(void) {
    /* this=esp+4, callback=esp+8, ctx=esp+12, flags=esp+16 */
    /* Don't enumerate any objects for now */
    g_eax = 0;
    g_esp += 20;
}

/* ============================================================
 * IDirectSound Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] CreateSoundBuffer (4) [4] GetCaps (2)
 * [5] DuplicateSoundBuffer (3) [6] SetCooperativeLevel (3)
 * [7] Compact (1) [8] GetSpeakerConfig (2)
 * [9] SetSpeakerConfig (2) [10] Initialize (2)
 * ============================================================ */

static void ds_CreateSoundBuffer(void) {
    /* this=esp+4, pDesc=esp+8, ppBuf=esp+12, pUnkOuter=esp+16 */
    uint32_t ppBuf = MEM32(g_esp + 12);
    mock_com_obj_t* buf = alloc_mock(MOCK_TAG_DSBUFFER, g_dsbuffer_vtable_addr);

    /* Allocate a small audio buffer (32KB default) */
    uint32_t pDesc = MEM32(g_esp + 8);
    uint32_t bufsize = 32768;
    if (pDesc) {
        uint32_t desc_bufsize = MEM32(pDesc + 12); /* dwBufferBytes at offset 12 */
        if (desc_bufsize > 0) bufsize = desc_bufsize;
    }
    uint8_t* abuf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufsize);
    buf->extra[0] = (uint32_t)(uintptr_t)abuf;
    buf->extra[1] = bufsize;

    MEM32(ppBuf) = (uint32_t)(uintptr_t)buf;
    COM_LOG("[COM] IDirectSound::CreateSoundBuffer(size=%u) -> 0x%08X\n",
            bufsize, (uint32_t)(uintptr_t)buf);
    g_eax = 0;
    g_esp += 20;
}

/* IDirectSound::DuplicateSoundBuffer(this, pOriginal, ppDuplicate). The prior stub returned S_OK but
 * left *ppDuplicate NULL, so callers (per-craft engine-sound setup) dereferenced null and crashed.
 * Return a real mock DSB, mirroring CreateSoundBuffer. */
static void ds_DuplicateSoundBuffer(void) {
    /* this=esp+4, pOriginal=esp+8, ppDuplicate=esp+12 */
    uint32_t ppDup = MEM32(g_esp + 12);
    /* Real DirectSound has a finite voice pool, and XWA's per-craft sound setup duplicates
     * buffers until the device refuses. An always-succeeding mock therefore never terminates:
     * measured 9930 unique duplicates in one cockpit-setup run and still climbing, which is
     * what stalls flight entry. Refuse past a hardware-plausible limit with DSERR_ALLOCATED.
     * ponytail: flat global cap, make it per-original if a real pool ever matters. */
    { static uint32_t _dups; const char* _e = getenv("XWA_DSVOICES");
      uint32_t _cap = _e ? (uint32_t)strtoul(_e, NULL, 0) : 64u;
      if (++_dups > _cap) {
          if (ppDup) MEM32(ppDup) = 0;
          if (_dups == _cap + 1) { fprintf(stderr, "[COM] DuplicateSoundBuffer: voice cap %u reached -> DSERR_ALLOCATED\n", _cap); fflush(stderr); }
          g_eax = 0x8878000Au;   /* DSERR_ALLOCATED */
          g_esp += 16;
          return;
      } }
    mock_com_obj_t* buf = alloc_mock(MOCK_TAG_DSBUFFER, g_dsbuffer_vtable_addr);
    uint8_t* abuf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32768);
    buf->extra[0] = (uint32_t)(uintptr_t)abuf;
    buf->extra[1] = 32768;
    if (ppDup) MEM32(ppDup) = (uint32_t)(uintptr_t)buf;
    COM_LOG("[COM] IDirectSound::DuplicateSoundBuffer -> 0x%08X\n", (uint32_t)(uintptr_t)buf);
    g_eax = 0;
    g_esp += 16;
}

static void ds_SetCooperativeLevel(void) {
    /* this=esp+4, hwnd=esp+8, level=esp+12 */
    g_eax = 0;
    g_esp += 16;
}

/* ============================================================
 * IDirectSoundBuffer Methods
 *
 * [0] QueryInterface (3) [1] AddRef (1) [2] Release (1)
 * [3] GetCaps (2) [4] GetCurrentPosition (3) [5] GetFormat (4)
 * [6] GetVolume (2) [7] GetPan (2) [8] GetFrequency (2)
 * [9] GetStatus (2) [10] Initialize (3) [11] Lock (8)
 * [12] Play (4) [13] SetCurrentPosition (2)
 * [14] SetFormat (2) [15] SetVolume (2) [16] SetPan (2)
 * [17] SetFrequency (2) [18] Stop (1) [19] Unlock (5)
 * [20] Restore (1)
 * ============================================================ */

static void dsb_Lock(void) {
    /* this=esp+4, offset=esp+8, bytes=esp+12,
     * ppAudioPtr1=esp+16, pAudioBytes1=esp+20,
     * ppAudioPtr2=esp+24, pAudioBytes2=esp+28, flags=esp+32 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t offset = MEM32(g_esp + 8);
    uint32_t bytes = MEM32(g_esp + 12);
    uint32_t ppAP1 = MEM32(g_esp + 16);
    uint32_t pAB1  = MEM32(g_esp + 20);
    uint32_t ppAP2 = MEM32(g_esp + 24);
    uint32_t pAB2  = MEM32(g_esp + 28);

    mock_com_obj_t* buf = (mock_com_obj_t*)(uintptr_t)pThis;
    uint32_t abuf = buf->extra[0];
    uint32_t bufsize = buf->extra[1];

    if (bytes > bufsize) bytes = bufsize;
    if (ppAP1) MEM32(ppAP1) = abuf + (offset % bufsize);
    if (pAB1)  MEM32(pAB1) = bytes;
    if (ppAP2) MEM32(ppAP2) = 0;
    if (pAB2)  MEM32(pAB2) = 0;

    g_eax = 0;
    g_esp += 36; /* pop ret + 8 args */
}

static void dsb_Unlock(void) {
    /* this=esp+4, pAP1=esp+8, AB1=esp+12, pAP2=esp+16, AB2=esp+20 */
    g_eax = 0;
    g_esp += 24;
}

static void dsb_Play(void) {
    /* this=esp+4, reserved1=esp+8, reserved2=esp+12, flags=esp+16 */
    g_eax = 0;
    g_esp += 20;
}

static void dsb_Stop(void) {
    g_eax = 0;
    g_esp += 8;
}

static void dsb_GetStatus(void) {
    /* this=esp+4, pStatus=esp+8 */
    uint32_t pStatus = MEM32(g_esp + 8);
    if (pStatus) MEM32(pStatus) = 0; /* not playing */
    g_eax = 0;
    g_esp += 12;
}

static void dsb_GetCurrentPosition(void) {
    /* this=esp+4, pPlay=esp+8, pWrite=esp+12 */
    uint32_t pPlay = MEM32(g_esp + 8);
    uint32_t pWrite = MEM32(g_esp + 12);
    if (pPlay) MEM32(pPlay) = 0;
    if (pWrite) MEM32(pWrite) = 0;
    g_eax = 0;
    g_esp += 16;
}

static void dsb_SetFormat(void) {
    /* this=esp+4, pFormat=esp+8 */
    g_eax = 0;
    g_esp += 12;
}

static void dsb_GetCaps(void) {
    /* this=esp+4, pCaps=esp+8 */
    uint32_t pCaps = MEM32(g_esp + 8);
    if (pCaps) {
        /* DSBCAPS: dwSize=+0, dwFlags=+4, dwBufferBytes=+8 */
        uint32_t pThis = MEM32(g_esp + 4);
        mock_com_obj_t* buf = (mock_com_obj_t*)(uintptr_t)pThis;
        MEM32(pCaps + 8) = buf->extra[1]; /* buffer size */
    }
    g_eax = 0;
    g_esp += 12;
}

/* IDirectDraw::GetVerticalBlankStatus - always report in VBlank.
 * The original game used this to wait for VSync before Flip.
 * Without real DDraw, always return TRUE so the game doesn't spin forever. */
static void dd_GetVerticalBlankStatus(void) {
    uint32_t pIsInVB = MEM32(g_esp + 8);
    if (pIsInVB) MEM32(pIsInVB) = 1;  /* TRUE: in vertical blank */
    g_eax = 0;  /* DD_OK */
    g_esp += 12;
}

/* ============================================================
 * Vtable Construction and Bridge Registration
 * ============================================================ */

/* ============================================================
 * IDirectPlay4 loopback mock
 *
 * XWA routes EVEN SINGLE-PLAYER mission-load + game-state through a DirectPlay
 * loopback session: sub_52CEE0 only sends the "load mission" message when the
 * session object (dword_A21449) is non-null, and that object comes from
 * DirectPlayCreate / CoCreateInstance(CLSID_DirectPlay, IID_IDirectPlay4).
 * Stubbing DirectPlay to fail (fine for the frontend) silently blocks ALL in-
 * flight gameplay. The actual message bytes travel through the game's own local
 * buffers (sub_52CF50 -> unk_A219DA/unk_A21BE6), NOT DirectPlay — so this mock
 * only needs to (a) exist so the gate opens and (b) succeed at session setup.
 * Every method returns DP_OK; QueryInterface returns self; Receive reports no
 * messages so any DP receive loop terminates.
 * Vtable = IDirectPlay4 layout (IDirectPlay/2/3/4 superset, 53 methods).
 * ============================================================ */
static void dplay_QueryInterface(void) {  /* (this, riid, ppv) */
    uint32_t self = MEM32(g_esp + 4), ppv = MEM32(g_esp + 12);
    if (ppv) MEM32(ppv) = self;   /* hand back the same object for any DP iface */
    g_eax = 0;
    g_esp += 16;
}
/* ---- DirectPlay single-player LOOPBACK message queue (XWA_DPLOOP) ----
 * XWA routes SP mission-load + game-state over a loopback DirectPlay session:
 * the game serializes an outgoing message (sub_52CF50 -> body @0xA21BE5, length
 * @0xA21DE5) and later polls Receive to get it back. The old stub returned
 * NOMESSAGES, so the mission-load message was never delivered and no world
 * objects spawned (objcount=0). This queue captures each send and replays it. */
#define DP_Q_CAP 64
static struct { uint8_t data[0x400]; uint32_t len; } g_dp_q[DP_Q_CAP];
static uint32_t g_dp_q_head, g_dp_q_tail;   /* tail=next write, head=next read */
static int g_dploop = -1;
int g_dp_active = 0;   /* set by the UI driver only during mission-load screens, so the
                        * loopback doesn't replay unrelated startup/frontend messages */
static void dp_enqueue(uint32_t lpData, uint32_t len);
void com_dplay_log_send(uint32_t len);
/* ponytail (XWA_DPLOOP): sub_0052CEE0 serializes an outgoing DP message via sub_0052CF50
 * into body buffer 0xA219D9 with byte-length at 0xA21BD9. Capture it here (called at the
 * end of sub_0052CEE0) and queue it so dplay_Receive can loop it back to the game's own
 * message-dispatch — which is what spawns world objects on the mission-setup command. */
void com_dplay_capture_send(void) {
    uint32_t len = MEM32(0xA21BD9u);
    if (len == 0 || len > 0x400) return;
    { static int _c; if (_c < 12) { fprintf(stderr, "[DPLOOP] capture@52CEE0: len=%u hdr=0x%02X 0x%02X 0x%02X\n",
        len, MEM8(0xA219D9u), MEM8(0xA219DAu), MEM8(0xA219DBu)); fflush(stderr); _c++; } }
    dp_enqueue(0xA219D9u, len);
}
/* Enqueue a sent message (lpData/len are guest addresses/size) for loopback. */
static void dp_enqueue(uint32_t lpData, uint32_t len) {
    if (g_dploop < 0) g_dploop = getenv("XWA_DPLOOP") ? 1 : 0;
    if (!g_dploop || !g_dp_active) return;
    if (!lpData || len == 0 || len > 0x400) return;
    { static int _c; if (_c < 16) { fprintf(stderr, "[DPLOOP] Send captured: len=%u data=0x%X hdr=0x%02X\n",
        len, lpData, MEM8(lpData)); fflush(stderr); _c++; } }
    uint32_t slot = g_dp_q_tail % DP_Q_CAP;
    for (uint32_t i = 0; i < len; i++) g_dp_q[slot].data[i] = MEM8(lpData + i);
    g_dp_q[slot].len = len;
    g_dp_q_tail++;
    if (g_dp_q_tail - g_dp_q_head > DP_Q_CAP) g_dp_q_head = g_dp_q_tail - DP_Q_CAP;
}
/* IDirectPlay4::Send(this, idFrom, idTo, dwFlags, lpData, dwDataSize) — 6 args */
/* Call counters for the DirectPlay surface, so "does the game use DP in flight?" is measured rather
 * than inferred from crash-dump markers. Index: 0 Send, 1 SendEx, 2 Receive, 3 GetMessageCount,
 * 4 Open, 5 CreatePlayer, 6 Receive-delivered. */
unsigned g_dpcnt[8];

static void dplay_Send(void) {
    g_dpcnt[0]++;
    com_dplay_log_send(MEM32(g_esp + 0x18));
    dp_enqueue(MEM32(g_esp + 0x14), MEM32(g_esp + 0x18));
    g_eax = 0; g_esp += 28;
}
/* IDirectPlay4::SendEx(this, idFrom, idTo, dwFlags, lpData, dwDataSize, prio, timeout, ctx, msgid) — 10 args */
static void dplay_SendEx(void) {
    g_dpcnt[1]++;
    com_dplay_log_send(MEM32(g_esp + 0x18));
    dp_enqueue(MEM32(g_esp + 0x14), MEM32(g_esp + 0x18));
    g_eax = 0; g_esp += 44;
}
static void dplay_Receive(void) {  /* (this, lpidFrom, lpidTo, flags, lpData, lpdwSize) */
    g_dpcnt[2]++;
    if (g_dploop < 0) g_dploop = getenv("XWA_DPLOOP") ? 1 : 0;
    if (g_dploop < 0) g_dploop = getenv("XWA_DPLOOP") ? 1 : 0;
    if (g_dploop && g_dp_active && g_dp_q_head != g_dp_q_tail) {
        uint32_t lpData = MEM32(g_esp + 0x14);
        uint32_t lpSize = MEM32(g_esp + 0x18);
        struct { uint8_t data[0x400]; uint32_t len; } *m = &g_dp_q[g_dp_q_head % DP_Q_CAP];
        uint32_t n = m->len; if (n > 0x200) n = 0x200;
        if (lpData) for (uint32_t i = 0; i < n; i++) MEM8(lpData + i) = m->data[i];
        if (lpSize) MEM32(lpSize) = n;
        g_dp_q_head++;
        if (MEM32(g_esp + 8))  MEM32(MEM32(g_esp + 8))  = 1; /* lpidFrom = peer 1 */
        if (MEM32(g_esp + 0xC)) MEM32(MEM32(g_esp + 0xC)) = 1; /* lpidTo = self 1 */
        g_eax = 0;                 /* DP_OK — message delivered */
        g_esp += 28;
        return;
    }
    g_eax = 0x88770014u;           /* DPERR_NOMESSAGES */
    g_esp += 28;
}
static void dplay_GetMessageCount(void) {  /* (this, idPlayer, lpdwCount) */
    uint32_t pCount = MEM32(g_esp + 12);
    /* Report the ACTUAL queue depth. Returning 0 unconditionally means a caller that checks the
     * count before receiving never calls Receive, so queued loopback messages are never delivered. */
    uint32_t depth = (g_dploop > 0 && g_dp_active) ? (uint32_t)(g_dp_q_tail - g_dp_q_head) : 0u;
    g_dpcnt[3]++;
    if (pCount) MEM32(pCount) = depth;
    g_eax = 0;
    g_esp += 16;
}
/* ponytail (#39): IDirectPlay4::CreatePlayer — the stub returned DP_OK but left the OUT player-id
 * unset, so the game never had a valid local player and never generated per-FG object-create
 * messages. Assign a real DPID so the game treats itself as a joined player/host. */
static uint32_t g_dp_next_pid = 1;
static void dplay_CreatePlayer(void) {  /* (this, lpidPlayer, lpName, hEvent, lpData, dwSize, dwFlags) */
    uint32_t lpid = MEM32(g_esp + 8);
    uint32_t pid = g_dp_next_pid++;
    if (lpid) MEM32(lpid) = pid;
    { static int _c; if (_c < 8) { fprintf(stderr, "[DP] CreatePlayer -> pid=%u (lpid=0x%X flags=0x%X)\n",
        pid, lpid, MEM32(g_esp + 0x1C)); fflush(stderr); _c++; } }
    g_eax = 0; g_esp += 32;
}
static void dplay_Open(void) {  /* (this, lpsd, dwFlags) */
    { static int _c; if (_c < 6) { fprintf(stderr, "[DP] Open(flags=0x%X)\n", MEM32(g_esp + 0xC)); fflush(stderr); _c++; } }
    g_eax = 0; g_esp += 16;
}
/* #60: session-setup method logging to capture the real DirectPlay handshake. */
static void dplay_EnumConnections(void) { /* (this, lpguidApp, lpEnumCb, lpCtx, dwFlags) — 5 */
    fprintf(stderr, "[DP] EnumConnections(guidApp=0x%X cb=0x%X ctx=0x%X flags=0x%X)\n",
        MEM32(g_esp+8), MEM32(g_esp+0xC), MEM32(g_esp+0x10), MEM32(g_esp+0x14)); fflush(stderr);
    g_eax = 0; g_esp += 24;
}
static void dplay_InitializeConnection(void) { /* (this, lpConnection, dwFlags) — 3 */
    fprintf(stderr, "[DP] InitializeConnection(lpConn=0x%X flags=0x%X)\n", MEM32(g_esp+8), MEM32(g_esp+0xC)); fflush(stderr);
    g_eax = 0; g_esp += 16;
}
static void dplay_EnumSessions(void) { /* (this, lpsd, dwTimeout, lpEnumCb, lpCtx, dwFlags) — 6 */
    fprintf(stderr, "[DP] EnumSessions(lpsd=0x%X timeout=%u cb=0x%X flags=0x%X)\n",
        MEM32(g_esp+8), MEM32(g_esp+0xC), MEM32(g_esp+0x10), MEM32(g_esp+0x18)); fflush(stderr);
    g_eax = 0; g_esp += 28;
}
static void dplay_GetCaps_dp(void) { /* (this, lpDPCaps, dwFlags) — 3 */
    fprintf(stderr, "[DP] GetCaps(lpCaps=0x%X flags=0x%X)\n", MEM32(g_esp+8), MEM32(g_esp+0xC)); fflush(stderr);
    g_eax = 0; g_esp += 16;
}
static void dplay_Close_dp(void) { /* (this) — 1 */
    fprintf(stderr, "[DP] Close()\n"); fflush(stderr);
    g_eax = 0; g_esp += 8;
}
void com_dplay_log_send(uint32_t len);
/* Dump the current BACK surface to a BMP on demand. The flight frame renders but the
 * process exits before any Flip, so the flip-time capture never sees it. */
void com_dump_back(const char* name);
void com_dump_back(const char* name) {
    if (!g_back_surface) return;
    uint32_t w = g_back_surface->extra[1], h = g_back_surface->extra[2];
    uint32_t bpp = g_back_surface->extra[3], pitch = g_back_surface->extra[4];
    uint8_t* px = (uint8_t*)(uintptr_t)g_back_surface->extra[0];
    if (!px || !w || !h) return;
    char path[128]; snprintf(path, sizeof(path), "D:\\recomp\\pc\\xwa\\frame_%s.bmp", name);
    FILE* fp = fopen(path, "wb"); if (!fp) return;
    uint32_t rowsz = w * 3, pad = (4 - (rowsz & 3)) & 3, imgsz = (rowsz + pad) * h;
    uint8_t hdr[54]; memset(hdr, 0, 54);
    hdr[0]=66; hdr[1]=77; *(uint32_t*)(hdr+2)=54+imgsz; *(uint32_t*)(hdr+10)=54;
    *(uint32_t*)(hdr+14)=40; *(int32_t*)(hdr+18)=(int32_t)w; *(int32_t*)(hdr+22)=-(int32_t)h;
    *(uint16_t*)(hdr+26)=1; *(uint16_t*)(hdr+28)=24; *(uint32_t*)(hdr+34)=imgsz;
    fwrite(hdr,1,54,fp);
    uint8_t* row = (uint8_t*)malloc(rowsz + pad); memset(row, 0, rowsz + pad);
    for (uint32_t y = 0; y < h; y++) {
        uint8_t* src = px + (size_t)y * pitch;
        for (uint32_t x = 0; x < w; x++) {
            uint8_t r,g,b;
            if (bpp == 16) { uint16_t v = ((uint16_t*)src)[x];
                r = (uint8_t)(((v >> 11) & 0x1F) << 3); g = (uint8_t)(((v >> 5) & 0x3F) << 2); b = (uint8_t)((v & 0x1F) << 3); }
            else { b = src[x*4+0]; g = src[x*4+1]; r = src[x*4+2]; }
            row[x*3+0]=b; row[x*3+1]=g; row[x*3+2]=r;
        }
        fwrite(row,1,rowsz+pad,fp);
    }
    free(row); fclose(fp);
    fprintf(stderr, "[DUMP] wrote %s (%ux%u bpp=%u)\n", path, w, h, bpp); fflush(stderr);
}
void com_dplay_log_send(uint32_t len) {
    static int _c; if (_c < 20) { fprintf(stderr, "[DP] Send len=%u g_dp_active=%d\n", len, g_dp_active); fflush(stderr); _c++; }
}

/* Allocate a mock IDirectPlay4 object; returns its guest address (0 if vtable
 * not yet built). Used by the DirectPlayCreate bridge + CoCreateInstance. */
uint32_t com_alloc_dplay_object(void) {
    if (!g_dplay_vtable_addr) return 0;
    mock_com_obj_t* dp = alloc_mock(MOCK_TAG_DPLAY, g_dplay_vtable_addr);
    return (uint32_t)(uintptr_t)dp;
}

void com_mocks_init(void) {
    COM_LOG("[COM] Initializing COM mock interfaces...\n");
    int bridges_before = g_import_bridge_count;

    /* ---- IDirectDraw (23 methods) ---- */
    {
        uint32_t markers[24];
        recomp_func_t funcs[24];
        for (int i = 0; i < 24; i++) markers[i] = MK_DD + i;

        funcs[0]  = dd_QueryInterface;     /* [0]  QueryInterface (3) */
        funcs[1]  = dd_AddRef;             /* [1]  AddRef (1) */
        funcs[2]  = dd_Release;            /* [2]  Release (1) */
        funcs[3]  = com_stub_1arg;         /* [3]  Compact (1) */
        funcs[4]  = com_stub_4arg;         /* [4]  CreateClipper (4) */
        funcs[5]  = dd_CreatePalette;      /* [5]  CreatePalette (5) */
        funcs[6]  = dd_CreateSurface;      /* [6]  CreateSurface (4) */
        funcs[7]  = com_stub_3arg;         /* [7]  DuplicateSurface (3) */
        funcs[8]  = dd_EnumDisplayModes;   /* [8]  EnumDisplayModes (5) */
        funcs[9]  = com_stub_5arg;         /* [9]  EnumSurfaces (5) */
        funcs[10] = com_stub_1arg;         /* [10] FlipToGDISurface (1) */
        funcs[11] = dd_GetCaps;            /* [11] GetCaps (3) */
        funcs[12] = dd_GetDisplayMode;     /* [12] GetDisplayMode (2) */
        funcs[13] = com_stub_3arg;         /* [13] GetFourCCCodes (3) */
        funcs[14] = com_stub_2arg;         /* [14] GetGDISurface (2) */
        funcs[15] = com_stub_2arg;         /* [15] GetMonitorFrequency (2) */
        funcs[16] = com_stub_2arg;         /* [16] GetScanLine (2) */
        funcs[17] = dd_GetVerticalBlankStatus; /* [17] GetVerticalBlankStatus (2) */
        funcs[18] = com_stub_2arg;         /* [18] Initialize (2) */
        funcs[19] = com_stub_1arg;         /* [19] RestoreDisplayMode (1) */
        funcs[20] = dd_SetCooperativeLevel;/* [20] SetCooperativeLevel (3) */
        funcs[21] = dd_SetDisplayMode;     /* [21] SetDisplayMode (4) */
        funcs[22] = com_stub_3arg;         /* [22] WaitForVerticalBlank (3) */
        funcs[23] = dd_GetAvailableVidMem; /* [23] GetAvailableVidMem (5) -- IDirectDraw2+ */

        g_ddraw_vtable_addr = alloc_vtable(markers, 24);
        for (int i = 0; i < 24; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirectDrawSurface (33 methods: 0-32 to be safe) ---- */
    {
        #define DDS_METHODS 33
        uint32_t markers[DDS_METHODS];
        recomp_func_t funcs[DDS_METHODS];
        for (int i = 0; i < DDS_METHODS; i++) markers[i] = MK_DDS + i;

        funcs[0]  = dds_QueryInterface;      /* [0]  QueryInterface */
        funcs[1]  = dd_AddRef;              /* [1]  AddRef */
        funcs[2]  = dds_Release;            /* [2]  Release */
        funcs[3]  = com_stub_2arg;          /* [3]  AddAttachedSurface */
        funcs[4]  = com_stub_2arg;          /* [4]  AddOverlayDirtyRect */
        funcs[5]  = dds_Blt;               /* [5]  Blt (5) */
        funcs[6]  = com_stub_3arg;          /* [6]  BltBatch */
        funcs[7]  = dds_BltFast;           /* [7]  BltFast (5) */
        funcs[8]  = com_stub_3arg;          /* [8]  DeleteAttachedSurface */
        funcs[9]  = com_stub_3arg;          /* [9]  EnumAttachedSurfaces */
        funcs[10] = com_stub_4arg;          /* [10] EnumOverlayZOrders */
        funcs[11] = dds_Flip;              /* [11] Flip (3) */
        funcs[12] = dds_GetAttachedSurface;/* [12] GetAttachedSurface (3) */
        funcs[13] = com_stub_2arg;          /* [13] GetBltStatus */
        funcs[14] = com_stub_2arg;          /* [14] GetCaps */
        funcs[15] = com_stub_2arg;          /* [15] GetClipper */
        funcs[16] = com_stub_3arg;          /* [16] GetColorKey */
        funcs[17] = dds_GetDC;             /* [17] GetDC (2) */
        funcs[18] = com_stub_2arg;          /* [18] GetFlipStatus */
        funcs[19] = com_stub_3arg;          /* [19] GetOverlayPosition */
        funcs[20] = com_stub_2arg;          /* [20] GetPalette */
        funcs[21] = dds_GetPixelFormat;    /* [21] GetPixelFormat (2) */
        funcs[22] = dds_GetSurfaceDesc;    /* [22] GetSurfaceDesc (2) */
        funcs[23] = com_stub_3arg;          /* [23] Initialize */
        funcs[24] = dds_IsLost;            /* [24] IsLost (1) */
        funcs[25] = dds_Lock;              /* [25] Lock (5) */
        funcs[26] = dds_ReleaseDC;         /* [26] ReleaseDC (2) */
        funcs[27] = dds_Restore;           /* [27] Restore (1) */
        funcs[28] = com_stub_2arg;          /* [28] SetClipper */
        funcs[29] = dds_SetColorKey;         /* [29] SetColorKey */
        funcs[30] = com_stub_3arg;          /* [30] SetOverlayPosition */
        funcs[31] = dds_SetPalette;        /* [31] SetPalette (2) */
        funcs[32] = dds_Unlock;            /* [32] Unlock (2) */

        g_ddsurface_vtable_addr = alloc_vtable(markers, DDS_METHODS);
        for (int i = 0; i < DDS_METHODS; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirectDrawPalette (7 methods) ---- */
    {
        uint32_t markers[7];
        recomp_func_t funcs[7];
        for (int i = 0; i < 7; i++) markers[i] = MK_DDP + i;

        funcs[0] = com_stub_3arg;   /* QueryInterface */
        funcs[1] = dd_AddRef;       /* AddRef */
        funcs[2] = dd_Release;      /* Release */
        funcs[3] = com_stub_2arg;   /* GetCaps */
        funcs[4] = ddp_GetEntries;  /* GetEntries (5) */
        funcs[5] = com_stub_3arg;   /* Initialize */
        funcs[6] = ddp_SetEntries;  /* SetEntries (5) */

        g_ddpalette_vtable_addr = alloc_vtable(markers, 7);
        for (int i = 0; i < 7; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirect3D (9 methods) ---- */
    {
        uint32_t markers[9];
        recomp_func_t funcs[9];
        for (int i = 0; i < 9; i++) markers[i] = MK_D3D + i;

        funcs[0] = com_stub_3arg;       /* QueryInterface */
        funcs[1] = dd_AddRef;           /* AddRef */
        funcs[2] = dd_Release;          /* Release */
        funcs[3] = com_stub_1arg;       /* Initialize */
        funcs[4] = d3d_EnumDevices;     /* EnumDevices (3) */
        funcs[5] = d3d_CreateLight;     /* CreateLight (3) */
        funcs[6] = d3d_CreateMaterial;  /* CreateMaterial (3) */
        funcs[7] = d3d_CreateViewport;  /* CreateViewport (3) */
        funcs[8] = com_stub_3arg;       /* FindDevice */

        g_d3d_vtable_addr = alloc_vtable(markers, 9);
        for (int i = 0; i < 9; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirect3DDevice (22 methods) ---- */
    {
        uint32_t markers[22];
        recomp_func_t funcs[22];
        for (int i = 0; i < 22; i++) markers[i] = MK_D3DDEV + i;

        funcs[0]  = com_stub_3arg;           /* QueryInterface */
        funcs[1]  = dd_AddRef;               /* AddRef */
        funcs[2]  = dd_Release;              /* Release */
        funcs[3]  = com_stub_3arg;           /* Initialize */
        funcs[4]  = d3ddev_GetCaps;          /* GetCaps (3) */
        funcs[5]  = com_stub_3arg;           /* SwapTextureHandles */
        funcs[6]  = d3ddev_CreateExecuteBuffer;/* CreateExecuteBuffer (4) */
        funcs[7]  = com_stub_2arg;           /* GetStats */
        funcs[8]  = d3ddev_Execute;          /* Execute (4) */
        funcs[9]  = d3ddev_AddViewport;      /* AddViewport (2) */
        funcs[10] = com_stub_2arg;           /* DeleteViewport */
        funcs[11] = com_stub_4arg;           /* NextViewport */
        funcs[12] = com_stub_5arg;           /* Pick */
        funcs[13] = com_stub_3arg;           /* GetPickRecords */
        funcs[14] = d3ddev_EnumTextureFormats;/* EnumTextureFormats (3) */
        funcs[15] = d3ddev_CreateMatrix;     /* CreateMatrix (2) */
        funcs[16] = d3ddev_SetMatrix;        /* SetMatrix (3) */
        funcs[17] = d3ddev_GetMatrix;        /* GetMatrix (3) */
        funcs[18] = d3ddev_DeleteMatrix;     /* DeleteMatrix (2) */
        funcs[19] = d3ddev_BeginScene;       /* BeginScene (1) */
        funcs[20] = d3ddev_EndScene;         /* EndScene (1) */
        funcs[21] = d3ddev_GetDirect3D;      /* GetDirect3D (2) */

        g_d3ddevice_vtable_addr = alloc_vtable(markers, 22);
        for (int i = 0; i < 22; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirect3DViewport (21 methods: the DX3 16 plus the Viewport2/3 tail) ---- */
    {
        /* These were [16] while every loop below runs to 21 -- five entries written past the end
         * of both stack arrays on every startup. Slots 16..20 were then read back from whatever
         * the smash landed on, so Clear2 (slot 20) resolved to garbage and raised an unresolved
         * ICALL mid-render, at a different point on every run. */
        uint32_t markers[21];
        recomp_func_t funcs[21];
        for (int i = 0; i < 21; i++) markers[i] = MK_D3DVP + i;

        funcs[0]  = com_stub_3arg;    /* QueryInterface */
        funcs[1]  = dd_AddRef;        /* AddRef */
        funcs[2]  = dd_Release;       /* Release */
        funcs[3]  = com_stub_2arg;    /* Initialize */
        funcs[4]  = com_stub_2arg;    /* GetViewport */
        funcs[5]  = d3dvp_SetViewport;/* SetViewport (2) */
        funcs[6]  = com_stub_5arg;    /* TransformVertices */
        funcs[7]  = com_stub_3arg;    /* LightElements */
        funcs[8]  = com_stub_2arg;    /* SetBackground */
        funcs[9]  = com_stub_3arg;    /* GetBackground */
        funcs[10] = com_stub_2arg;    /* SetBackgroundDepth */
        funcs[11] = com_stub_2arg;    /* GetBackgroundDepth */
        funcs[12] = d3dvp_Clear;      /* Clear (5) */
        funcs[13] = com_stub_2arg;    /* AddLight */
        funcs[14] = com_stub_2arg;    /* DeleteLight */
        funcs[15] = com_stub_4arg;    /* NextLight */
        /* IDirect3DViewport2/3 methods. The vtable stopped at 16 entries, but the game calls
         * index 20 (Clear2) at 0x00598024 -- reading past the end of a 16-entry vtable. */
        funcs[16] = com_stub_2arg;      /* GetViewport2 */
        funcs[17] = d3dvp_SetViewport;  /* SetViewport2 -- D3DVIEWPORT2 shares the leading
                                         * dwSize/dwX/dwY/dwWidth/dwHeight layout */
        funcs[18] = com_stub_2arg;      /* SetBackgroundDepth2 */
        funcs[19] = com_stub_2arg;      /* GetBackgroundDepth2 */
        funcs[20] = com_stub_7arg;      /* Clear2 (this + 6 args) */

        g_d3dviewport_vtable_addr = alloc_vtable(markers, 21);
        for (int i = 0; i < 21; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirect3DExecuteBuffer (10 methods) ---- */
    {
        uint32_t markers[10];
        recomp_func_t funcs[10];
        for (int i = 0; i < 10; i++) markers[i] = MK_D3DEB + i;

        funcs[0] = com_stub_3arg;          /* QueryInterface */
        funcs[1] = dd_AddRef;              /* AddRef */
        funcs[2] = dd_Release;             /* Release */
        funcs[3] = com_stub_3arg;          /* Initialize */
        funcs[4] = d3deb_Lock;             /* Lock (2) */
        funcs[5] = d3deb_Unlock;           /* Unlock (1) */
        funcs[6] = d3deb_SetExecuteData;   /* SetExecuteData (2) */
        funcs[7] = com_stub_2arg;          /* GetExecuteData */
        funcs[8] = com_stub_5arg;          /* Validate */
        funcs[9] = com_stub_2arg;          /* Optimize */

        g_d3dexecbuf_vtable_addr = alloc_vtable(markers, 10);
        for (int i = 0; i < 10; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirect3DTexture (8 methods) ---- */
    {
        uint32_t markers[8];
        recomp_func_t funcs[8];
        for (int i = 0; i < 8; i++) markers[i] = MK_D3DTEX + i;

        funcs[0] = com_stub_3arg;    /* QueryInterface */
        funcs[1] = dd_AddRef;        /* AddRef */
        funcs[2] = dd_Release;       /* Release */
        funcs[3] = com_stub_3arg;    /* Initialize */
        funcs[4] = d3dtex_GetHandle; /* GetHandle (3) */
        funcs[5] = com_stub_3arg;    /* PaletteChanged */
        funcs[6] = d3dtex_Load;      /* Load (2) */
        funcs[7] = com_stub_1arg;    /* Unload */

        g_d3dtexture_vtable_addr = alloc_vtable(markers, 8);
        for (int i = 0; i < 8; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirectInput (8 methods) ---- */
    {
        uint32_t markers[8];
        recomp_func_t funcs[8];
        for (int i = 0; i < 8; i++) markers[i] = MK_DI + i;

        funcs[0] = com_stub_3arg;    /* QueryInterface */
        funcs[1] = dd_AddRef;        /* AddRef */
        funcs[2] = dd_Release;       /* Release */
        funcs[3] = di_CreateDevice;  /* CreateDevice (4) */
        funcs[4] = di_EnumDevices;   /* EnumDevices (4) */
        funcs[5] = com_stub_2arg;    /* GetDeviceStatus */
        funcs[6] = com_stub_3arg;    /* RunControlPanel */
        funcs[7] = com_stub_3arg;    /* Initialize */

        g_dinput_vtable_addr = alloc_vtable(markers, 8);
        for (int i = 0; i < 8; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirectInputDevice (18 methods) ---- */
    {
        uint32_t markers[18];
        recomp_func_t funcs[18];
        for (int i = 0; i < 18; i++) markers[i] = MK_DIDEV + i;

        funcs[0]  = com_stub_3arg;        /* QueryInterface */
        funcs[1]  = dd_AddRef;            /* AddRef */
        funcs[2]  = dd_Release;           /* Release */
        funcs[3]  = didev_GetCapabilities;/* GetCapabilities (2) */
        funcs[4]  = didev_EnumObjects;    /* EnumObjects (4) */
        funcs[5]  = com_stub_3arg;        /* GetProperty */
        funcs[6]  = com_stub_3arg;        /* SetProperty */
        funcs[7]  = com_stub_1arg;        /* Acquire */
        funcs[8]  = com_stub_1arg;        /* Unacquire */
        funcs[9]  = didev_GetDeviceState; /* GetDeviceState (3) */
        funcs[10] = didev_GetDeviceData;  /* GetDeviceData (5) */
        funcs[11] = com_stub_2arg;        /* SetDataFormat */
        funcs[12] = com_stub_2arg;        /* SetEventNotification */
        funcs[13] = com_stub_3arg;        /* SetCooperativeLevel */
        funcs[14] = com_stub_4arg;        /* GetObjectInfo */
        funcs[15] = com_stub_2arg;        /* GetDeviceInfo */
        funcs[16] = com_stub_3arg;        /* RunControlPanel */
        funcs[17] = com_stub_4arg;        /* Initialize */

        g_didevice_vtable_addr = alloc_vtable(markers, 18);
        for (int i = 0; i < 18; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirectSound (11 methods) ---- */
    {
        uint32_t markers[11];
        recomp_func_t funcs[11];
        for (int i = 0; i < 11; i++) markers[i] = MK_DS + i;

        funcs[0]  = com_stub_3arg;          /* QueryInterface */
        funcs[1]  = dd_AddRef;              /* AddRef */
        funcs[2]  = dd_Release;             /* Release */
        funcs[3]  = ds_CreateSoundBuffer;   /* CreateSoundBuffer (4) */
        funcs[4]  = com_stub_2arg;          /* GetCaps */
        funcs[5]  = ds_DuplicateSoundBuffer; /* DuplicateSoundBuffer */
        funcs[6]  = ds_SetCooperativeLevel; /* SetCooperativeLevel (3) */
        funcs[7]  = com_stub_1arg;          /* Compact */
        funcs[8]  = com_stub_2arg;          /* GetSpeakerConfig */
        funcs[9]  = com_stub_2arg;          /* SetSpeakerConfig */
        funcs[10] = com_stub_2arg;          /* Initialize */

        g_dsound_vtable_addr = alloc_vtable(markers, 11);
        for (int i = 0; i < 11; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirectSoundBuffer (21 methods) ---- */
    {
        uint32_t markers[21];
        recomp_func_t funcs[21];
        for (int i = 0; i < 21; i++) markers[i] = MK_DSB + i;

        funcs[0]  = com_stub_3arg;           /* QueryInterface */
        funcs[1]  = dd_AddRef;               /* AddRef */
        funcs[2]  = dd_Release;              /* Release */
        funcs[3]  = dsb_GetCaps;             /* GetCaps (2) */
        funcs[4]  = dsb_GetCurrentPosition;  /* GetCurrentPosition (3) */
        funcs[5]  = com_stub_4arg;           /* GetFormat */
        funcs[6]  = com_stub_2arg;           /* GetVolume */
        funcs[7]  = com_stub_2arg;           /* GetPan */
        funcs[8]  = com_stub_2arg;           /* GetFrequency */
        funcs[9]  = dsb_GetStatus;           /* GetStatus (2) */
        funcs[10] = com_stub_3arg;           /* Initialize */
        funcs[11] = dsb_Lock;                /* Lock (8) */
        funcs[12] = dsb_Play;               /* Play (4) */
        funcs[13] = com_stub_2arg;           /* SetCurrentPosition */
        funcs[14] = dsb_SetFormat;           /* SetFormat (2) */
        funcs[15] = com_stub_2arg;           /* SetVolume */
        funcs[16] = com_stub_2arg;           /* SetPan */
        funcs[17] = com_stub_2arg;           /* SetFrequency */
        funcs[18] = dsb_Stop;               /* Stop (1) */
        funcs[19] = dsb_Unlock;              /* Unlock (5) */
        funcs[20] = com_stub_1arg;           /* Restore */

        g_dsbuffer_vtable_addr = alloc_vtable(markers, 21);
        for (int i = 0; i < 21; i++)
            register_bridge(markers[i], funcs[i]);
    }

    /* ---- IDirectPlay4 loopback (53 methods) ----
     * Arg counts (incl. this) follow dplay.h's IDirectPlay4Vtbl. Everything is a
     * DP_OK success stub except QueryInterface(self), Receive(no messages) and
     * GetMessageCount(0). Only session-setup methods the game actually invokes
     * matter (Release, Close, GetCaps, InitializeConnection, Open, ...). */
    {
        uint32_t markers[53];
        recomp_func_t funcs[53];
        for (int i = 0; i < 53; i++) { markers[i] = MK_DPLAY + i; funcs[i] = com_stub_3arg; }
        funcs[0]  = dplay_QueryInterface;   /* QueryInterface (3) */
        funcs[1]  = dd_AddRef;              /* AddRef (1) */
        funcs[2]  = dd_Release;             /* Release (1) */
        funcs[3]  = com_stub_3arg;          /* AddPlayerToGroup (3) */
        funcs[4]  = dplay_Close_dp;         /* Close (1) */
        funcs[5]  = com_stub_6arg;          /* CreateGroup (6) */
        funcs[6]  = dplay_CreatePlayer;     /* CreatePlayer (7) */
        funcs[7]  = com_stub_3arg;          /* DeletePlayerFromGroup (3) */
        funcs[8]  = com_stub_2arg;          /* DestroyGroup (2) */
        funcs[9]  = com_stub_2arg;          /* DestroyPlayer (2) */
        funcs[10] = com_stub_6arg;          /* EnumGroupPlayers (6) */
        funcs[11] = com_stub_5arg;          /* EnumGroups (5) */
        funcs[12] = com_stub_5arg;          /* EnumPlayers (5) */
        funcs[13] = dplay_EnumSessions;     /* EnumSessions (6) */
        funcs[14] = dplay_GetCaps_dp;       /* GetCaps (3) */
        funcs[15] = com_stub_5arg;          /* GetGroupData (5) */
        funcs[16] = com_stub_4arg;          /* GetGroupName (4) */
        funcs[17] = dplay_GetMessageCount;  /* GetMessageCount (3) */
        funcs[18] = com_stub_4arg;          /* GetPlayerAddress (4) */
        funcs[19] = com_stub_4arg;          /* GetPlayerCaps (4) */
        funcs[20] = com_stub_5arg;          /* GetPlayerData (5) */
        funcs[21] = com_stub_4arg;          /* GetPlayerName (4) */
        funcs[22] = com_stub_3arg;          /* GetSessionDesc (3) */
        funcs[23] = com_stub_2arg;          /* Initialize (2) */
        funcs[24] = dplay_Open;             /* Open (3) */
        funcs[25] = dplay_Receive;          /* Receive (6) */
        funcs[26] = dplay_Send;             /* Send (6) — loopback capture */
        funcs[27] = com_stub_5arg;          /* SetGroupData (5) */
        funcs[28] = com_stub_4arg;          /* SetGroupName (4) */
        funcs[29] = com_stub_5arg;          /* SetPlayerData (5) */
        funcs[30] = com_stub_4arg;          /* SetPlayerName (4) */
        funcs[31] = com_stub_3arg;          /* SetSessionDesc (3) */
        funcs[32] = com_stub_3arg;          /* AddGroupToGroup (3) */
        funcs[33] = com_stub_7arg;          /* CreateGroupInGroup (7) */
        funcs[34] = com_stub_3arg;          /* DeleteGroupFromGroup (3) */
        funcs[35] = dplay_EnumConnections;  /* EnumConnections (5) */
        funcs[36] = com_stub_6arg;          /* EnumGroupsInGroup (6) */
        funcs[37] = com_stub_5arg;          /* GetGroupConnectionSettings (5) */
        funcs[38] = dplay_InitializeConnection; /* InitializeConnection (3) */
        funcs[39] = com_stub_5arg;          /* SecureOpen (5) */
        funcs[40] = com_stub_5arg;          /* SendChatMessage (5) */
        funcs[41] = com_stub_4arg;          /* SetGroupConnectionSettings (4) */
        funcs[42] = com_stub_3arg;          /* StartSession (3) */
        funcs[43] = com_stub_3arg;          /* GetGroupFlags (3) */
        funcs[44] = com_stub_3arg;          /* GetGroupParent (3) */
        funcs[45] = com_stub_5arg;          /* GetPlayerAccount (5) */
        funcs[46] = com_stub_3arg;          /* GetPlayerFlags (3) */
        funcs[47] = com_stub_3arg;          /* GetGroupOwner (3) */
        funcs[48] = com_stub_3arg;          /* SetGroupOwner (3) */
        funcs[49] = dplay_SendEx;           /* SendEx (10) — loopback capture */
        funcs[50] = com_stub_6arg;          /* GetMessageQueue (6) */
        funcs[51] = com_stub_3arg;          /* CancelMessage (3) */
        funcs[52] = com_stub_4arg;          /* CancelPriority (4) */

        g_dplay_vtable_addr = alloc_vtable(markers, 53);
        for (int i = 0; i < 53; i++)
            register_bridge(markers[i], funcs[i]);
    }

    COM_LOG("[COM] Registered %d COM vtable bridges (total bridges: %d)\n",
            g_import_bridge_count - bridges_before, g_import_bridge_count);
}

/* ============================================================
 * Bridge Implementations (called from imports.c)
 * ============================================================ */

void bridge_DirectDrawCreate_impl(void) {
    /* DirectDrawCreate(lpGUID, lplpDD, pUnkOuter) - 3 args, stdcall */
    uint32_t lpGUID = MEM32(g_esp + 4);
    uint32_t lplpDD = MEM32(g_esp + 8);
    uint32_t pUnk   = MEM32(g_esp + 12);

    COM_LOG("[COM] DirectDrawCreate(guid=0x%08X, lplpDD=0x%08X)\n", lpGUID, lplpDD);

    mock_com_obj_t* dd = alloc_mock(MOCK_TAG_DDRAW, g_ddraw_vtable_addr);
    MEM32(lplpDD) = (uint32_t)(uintptr_t)dd;
    COM_LOG("[COM]   -> IDirectDraw mock at 0x%08X (vtbl=0x%08X)\n",
            (uint32_t)(uintptr_t)dd, dd->lpVtbl);

    g_eax = 0; /* DD_OK */
    g_esp += 16; /* pop ret + 3 args */
}

void bridge_DirectInputCreateA_impl(void) {
    /* DirectInputCreateA(hInst, dwVersion, lplpDI, pUnkOuter) - 4 args, stdcall */
    uint32_t hInst   = MEM32(g_esp + 4);
    uint32_t version = MEM32(g_esp + 8);
    uint32_t lplpDI  = MEM32(g_esp + 12);

    COM_LOG("[COM] DirectInputCreateA(ver=0x%08X, lplpDI=0x%08X)\n", version, lplpDI);

    mock_com_obj_t* di = alloc_mock(MOCK_TAG_DINPUT, g_dinput_vtable_addr);
    MEM32(lplpDI) = (uint32_t)(uintptr_t)di;
    COM_LOG("[COM]   -> IDirectInput mock at 0x%08X\n", (uint32_t)(uintptr_t)di);

    g_eax = 0; /* DI_OK */
    g_esp += 20; /* pop ret + 4 args */
}

void bridge_DirectSoundCreate_impl(void) {
    /* DirectSoundCreate(lpGuid, lplpDS, pUnkOuter) - 3 args, stdcall */
    uint32_t lpGuid = MEM32(g_esp + 4);
    uint32_t lplpDS = MEM32(g_esp + 8);

    COM_LOG("[COM] DirectSoundCreate(lplpDS=0x%08X)\n", lplpDS);

    mock_com_obj_t* ds = alloc_mock(MOCK_TAG_DSOUND, g_dsound_vtable_addr);
    MEM32(lplpDS) = (uint32_t)(uintptr_t)ds;
    COM_LOG("[COM]   -> IDirectSound mock at 0x%08X\n", (uint32_t)(uintptr_t)ds);

    g_eax = 0; /* DS_OK */
    g_esp += 16; /* pop ret + 3 args */
}

/* Upload the current back buffer to D3D11 staging texture.
 * Called from PeekMessage keepalive to ensure the display always
 * shows the latest rendered content, not just stale frames. */
void com_upload_back_buffer(void) {
    if (g_back_surface && g_back_surface->extra[0] && d3d11_is_initialized()) {
        { static int _ubb; if (_ubb < 3) {
            fprintf(stderr, "[UPLOAD] back_buf=0x%X %ux%u pitch=%u bpp=%u\n",
                g_back_surface->extra[0], g_back_surface->extra[1],
                g_back_surface->extra[2], g_back_surface->extra[4],
                g_back_surface->extra[3]);
            fflush(stderr); _ubb++;
        } }
        d3d11_upload_surface(
            (uint8_t*)(uintptr_t)g_back_surface->extra[0],
            g_back_surface->extra[1],
            g_back_surface->extra[2],
            g_back_surface->extra[4],
            g_back_surface->extra[3]
        );
    }
}
