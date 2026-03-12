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

extern unsigned int g_total_calls;
extern unsigned int g_total_icalls;

static int g_heap_check_count = 0;
static int g_heap_corrupt = 0;
static void heap_check(const char* where) {
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
static void com_dispatch_callback(uint32_t va) {
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

/* Pixel buffer for surfaces (640x480x2 = 614400 bytes) */
#define SURFACE_BUF_SIZE (640 * 480 * 2)
static uint8_t* g_surface_buffer = NULL;
static uint8_t* g_backbuf_buffer = NULL;

/* Global mock objects (for cross-reference) */
static mock_com_obj_t* g_primary_surface = NULL;
static mock_com_obj_t* g_back_surface = NULL;

/* Stored display mode */
static uint32_t g_display_width = 640;
static uint32_t g_display_height = 480;
static uint32_t g_display_bpp = 16;

/* Captured HWND for D3D11 renderer */
static HWND g_game_hwnd = NULL;

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
    COM_LOG("[COM] IDirectDraw::QueryInterface(riid_dw0=0x%08X, ppv=0x%08X)\n",
            guid_dw0, ppv);

    /* For any QI, return a mock IDirect3D object.
     * XWA only QIs for IDirect3D from IDirectDraw. */
    mock_com_obj_t* d3d = alloc_mock(MOCK_TAG_D3D, g_d3d_vtable_addr);
    MEM32(ppv) = (uint32_t)(uintptr_t)d3d;
    COM_LOG("[COM]   -> IDirect3D mock at 0x%08X\n", (uint32_t)(uintptr_t)d3d);

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
        g_surface_buffer = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SURFACE_BUF_SIZE);
        g_backbuf_buffer = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SURFACE_BUF_SIZE);
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
        uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        surf = create_mock_surface(buf);
        surf->extra[1] = w;
        surf->extra[2] = h;
        surf->extra[4] = w * (bpp / 8);
    }

    MEM32(ppSurf) = (uint32_t)(uintptr_t)surf;
    { static int _cs; fprintf(stderr, "[COM] CreateSurface #%d: surf=0x%08X buf=0x%08X w=%u h=%u caps=0x%X\n",
            _cs++, (uint32_t)(uintptr_t)surf, surf->extra[0], surf->extra[1], surf->extra[2], caps); }

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
    }

    g_eax = 0;
    g_esp += 20; /* pop ret + 4 args */
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
        }
    }
    if (pHEL) {
        uint32_t size = MEM32(pHEL);
        if (size > 0) {
            MEM32(pHEL + 4) = 0x640;
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

    /* Call callback with 640x480x16 mode if callback is valid */
    if (cb != 0) {
        /* Allocate a DDSURFACEDESC on the simulated stack */
        uint32_t save_esp = g_esp;

        /* Build a temp DDSURFACEDESC (108 bytes) */
        uint8_t desc[108];
        memset(desc, 0, sizeof(desc));
        *(uint32_t*)(desc + 0) = 108;   /* dwSize */
        *(uint32_t*)(desc + 4) = 0x1006; /* dwFlags */
        *(uint32_t*)(desc + 8) = 640;    /* dwWidth */
        *(uint32_t*)(desc + 12) = 480;   /* dwHeight */
        *(uint32_t*)(desc + 16) = 1280;  /* lPitch */
        *(uint32_t*)(desc + 72) = 32;    /* DDPIXELFORMAT.dwSize */
        *(uint32_t*)(desc + 76) = 0x40;  /* DDPF_RGB */
        *(uint32_t*)(desc + 84) = 16;    /* dwRGBBitCount */
        *(uint32_t*)(desc + 88) = 0xF800;
        *(uint32_t*)(desc + 92) = 0x07E0;
        *(uint32_t*)(desc + 96) = 0x001F;

        /* Put desc somewhere in mapped memory */
        uint32_t desc_va = 0x00B0F000; /* scratch area in BSS */
        memcpy((void*)(uintptr_t)desc_va, desc, sizeof(desc));

        /* Call: callback(pDesc, ctx) - stdcall, 2 args */
        PUSH32(g_esp, ctx);
        PUSH32(g_esp, desc_va);
        PUSH32(g_esp, 0xDEAD0099u); /* return addr */
        /* Dispatch to callback */
        com_dispatch_callback(cb);
        /* callback is stdcall(2 args), should have cleaned stack */

        g_esp = save_esp; /* restore */
    }

    g_eax = 0;
    g_esp += 24; /* pop ret + 5 args */
}

/* ============================================================
 * IDirectDrawSurface Methods
 *
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
    COM_LOG("[COM] IDirectDrawSurface::QueryInterface(riid_dw0=0x%08X)\n", guid_dw0);

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
    }
    { static int _ll; if (_ll < 30) { fprintf(stderr, "[COM]   Lock -> lpSurface=0x%08X w=%u h=%u pitch=%u\n", pixbuf, width, height, pitch); _ll++; } }

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
        MEM32(pDesc + 84) = surf->extra[3]; /* bpp */
        if (surf->extra[3] == 16) {
            MEM32(pDesc + 88) = 0xF800;
            MEM32(pDesc + 92) = 0x07E0;
            MEM32(pDesc + 96) = 0x001F;
        }
    }

    g_eax = 0;
    g_esp += 12;
}

static void dds_Flip(void) {
    /* this=esp+4, pSurf=esp+8, flags=esp+12 */
    if (d3d11_is_initialized()) {
        /* Upload the back buffer 2D surface before presenting */
        if (g_back_surface && g_back_surface->extra[0]) {
            { static int _fc; if (_fc < 20) {
                uint8_t* buf = (uint8_t*)(uintptr_t)g_back_surface->extra[0];
                uint32_t sz = g_back_surface->extra[1] * g_back_surface->extra[2] * 2;
                int nz = 0; uint32_t nz_count = 0;
                for (uint32_t i = 0; i < sz; i++) { if (buf[i]) { nz = 1; nz_count++; } }
                fprintf(stderr, "[COM] dds_Flip #%d: back_buf=0x%X %ux%u nz_bytes=%u/%u\n",
                    _fc, g_back_surface->extra[0], g_back_surface->extra[1], g_back_surface->extra[2], nz_count, sz);
                _fc++;
            } }
            d3d11_upload_surface(
                (uint8_t*)(uintptr_t)g_back_surface->extra[0],
                g_back_surface->extra[1],
                g_back_surface->extra[2],
                g_back_surface->extra[4],
                g_back_surface->extra[3]
            );
            /* Dump frame 50 to BMP for debugging */
            { static int _dumped = 0; _dumped++; if (_dumped == 50) {
                uint32_t w = g_back_surface->extra[1], h = g_back_surface->extra[2];
                uint32_t pitch = g_back_surface->extra[4];
                uint8_t* px = (uint8_t*)(uintptr_t)g_back_surface->extra[0];
                FILE* fp = fopen("D:\\recomp\\pc\\xwa\\frame_dump.bmp", "wb");
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
                        uint16_t* sp = (uint16_t*)(px + y * pitch);
                        memset(row, 0, row32);
                        for (uint32_t x = 0; x < w; x++) {
                            uint16_t c = sp[x];
                            uint8_t r = (uint8_t)(((c >> 11) & 0x1F) * 255 / 31);
                            uint8_t g = (uint8_t)(((c >> 5) & 0x3F) * 255 / 63);
                            uint8_t b = (uint8_t)((c & 0x1F) * 255 / 31);
                            row[x*3+0] = b; row[x*3+1] = g; row[x*3+2] = r;
                        }
                        fwrite(row, 1, row32, fp);
                    }
                    HeapFree(GetProcessHeap(), 0, row);
                    fclose(fp);
                    fprintf(stderr, "[DUMP] Wrote frame to D:\\recomp\\pc\\xwa\\frame_dump.bmp (%ux%u)\n", w, h);
                }
            } }
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
            if (x1 > dstW) x1 = dstW;
            if (y1 > dstH) y1 = dstH;
        }

        { static int _cf; if (_cf < 5) { fprintf(stderr, "[COM]   ColorFill: color=0x%04X rect=(%u,%u)-(%u,%u)\n", fillColor, x0, y0, x1, y1); _cf++; } }

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
        for (uint32_t y = 0; y < copyH; y++) {
            memcpy(dstBuf + y * dstPitch, srcBuf + y * srcPitch, rowBytes);
        }
    }
    g_eax = 0;
    g_esp += 28; /* pop ret + 6 args */
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
    g_esp += 16; /* pop ret + 3 args */
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

    { static int _bf; if (_bf < 20) {
        fprintf(stderr, "[COM] dds_BltFast(dst=0x%08X, x=%u, y=%u, src=0x%08X, dwTrans=0x%X, srcCK=%u/0x%04X)\n",
            pThis, dstX, dstY, pSrcSurf, dwTrans,
            src ? src->extra[6] : 0, src ? src->extra[5] : 0); _bf++;
    } }
    /* Copy src rect to dst at (dstX, dstY) with optional source color keying */
    if (src && dst && src->extra[0] && dst->extra[0]) {
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
        /* Clip to destination bounds */
        if (dstX + srcW > dstW) srcW = dstW - dstX;
        if (dstY + srcH > dstH) srcH = dstH - dstY;
        uint8_t* srcBuf = (uint8_t*)(uintptr_t)src->extra[0];
        uint8_t* dstBuf = (uint8_t*)(uintptr_t)dst->extra[0];

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
        MEM32(pFmt + 12) = surf->extra[3]; /* bpp */
        if (surf->extra[3] == 16) {
            MEM32(pFmt + 16) = 0xF800;
            MEM32(pFmt + 20) = 0x07E0;
            MEM32(pFmt + 24) = 0x001F;
        }
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
        strcpy((char*)(uintptr_t)desc_va, "Mock Direct3D HAL");
        /* name string at scratch+64 */
        uint32_t name_va = scratch + 64;
        strcpy((char*)(uintptr_t)name_va, "MockD3D");
        /* D3DDEVICEDESC for HAL at scratch+128 (size=0xFC, 252 bytes) */
        uint32_t hal_desc_va = scratch + 128;
        MEM32(hal_desc_va) = 252; /* dwSize */
        MEM32(hal_desc_va + 4) = 0x1F; /* dwFlags - all caps */
        /* D3DDEVICEDESC for HEL at scratch+384 */
        uint32_t hel_desc_va = scratch + 384;
        MEM32(hel_desc_va) = 252;
        MEM32(hel_desc_va + 4) = 0x1F;

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

    mock_com_obj_t* eb = alloc_mock(MOCK_TAG_D3DEXECBUF, g_d3dexecbuf_vtable_addr);
    /* Allocate actual buffer for execute buffer data */
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufsize);
    eb->extra[0] = (uint32_t)(uintptr_t)buf;
    eb->extra[1] = bufsize;
    MEM32(ppEB) = (uint32_t)(uintptr_t)eb;

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

    /* Call callback with 16-bit 565 texture format */
    if (cb != 0) {
        uint32_t scratch = 0x00B0F600;
        memset((void*)(uintptr_t)scratch, 0, 64);
        /* DDSURFACEDESC with pixel format */
        MEM32(scratch + 0) = 32; /* dwSize of DDPIXELFORMAT */
        MEM32(scratch + 4) = 0x40; /* DDPF_RGB */
        MEM32(scratch + 12) = 16; /* bpp */
        MEM32(scratch + 16) = 0xF800;
        MEM32(scratch + 20) = 0x07E0;
        MEM32(scratch + 24) = 0x001F;

        uint32_t save_esp = g_esp;
        PUSH32(g_esp, ctx);
        PUSH32(g_esp, scratch);
        PUSH32(g_esp, 0xDEAD0097u);
        com_dispatch_callback(cb);
        g_esp = save_esp;
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
    d3d11_begin_scene();
    g_eax = 0;
    g_esp += 8;
}

static void d3ddev_EndScene(void) {
    d3d11_end_scene();
    g_eax = 0;
    g_esp += 8;
}

static void d3ddev_Execute(void) {
    /* this=esp+4, pEB=esp+8, pViewport=esp+12, flags=esp+16 */
    uint32_t pEB = MEM32(g_esp + 8);

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
    /* this=esp+4, pDesc=esp+8 */
    uint32_t pThis = MEM32(g_esp + 4);
    uint32_t pDesc = MEM32(g_esp + 8);
    mock_com_obj_t* eb = (mock_com_obj_t*)(uintptr_t)pThis;

    if (pDesc) {
        /* D3DEXECUTEBUFFERDESC: dwSize=+0, dwFlags=+4, dwCaps=+8,
         * dwBufferSize=+12, lpData=+16 */
        MEM32(pDesc + 0) = 24; /* dwSize */
        MEM32(pDesc + 4) = 0x3; /* D3DDEB_BUFSIZE | D3DDEB_CAPS */
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

    if (pData) {
        eb->extra[2] = MEM32(pData + 4);  /* dwVertexOffset */
        eb->extra[3] = MEM32(pData + 8);  /* dwVertexCount */
        eb->extra[4] = MEM32(pData + 12); /* dwInstructionOffset */
        eb->extra[5] = MEM32(pData + 16); /* dwInstructionLength */
    }

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
    uint32_t ppDev = MEM32(g_esp + 12);
    mock_com_obj_t* dev = alloc_mock(MOCK_TAG_DIDEVICE, g_didevice_vtable_addr);
    MEM32(ppDev) = (uint32_t)(uintptr_t)dev;
    COM_LOG("[COM] IDirectInput::CreateDevice -> 0x%08X\n", (uint32_t)(uintptr_t)dev);
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
    uint32_t cbData = MEM32(g_esp + 8);
    uint32_t lpvData = MEM32(g_esp + 12);
    /* Zero-fill the state buffer (no keys pressed, joystick centered) */
    if (lpvData && cbData > 0) {
        memset((void*)(uintptr_t)lpvData, 0, cbData);
    }
    g_eax = 0;
    g_esp += 16;
}

static void didev_GetDeviceData(void) {
    /* this=esp+4, cbObjData=esp+8, rgdod=esp+12, pdwItems=esp+16, flags=esp+20 */
    uint32_t pdwItems = MEM32(g_esp + 16);
    /* No data available */
    if (pdwItems) MEM32(pdwItems) = 0;
    g_eax = 0;
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

/* ============================================================
 * Vtable Construction and Bridge Registration
 * ============================================================ */

void com_mocks_init(void) {
    COM_LOG("[COM] Initializing COM mock interfaces...\n");
    int bridges_before = g_import_bridge_count;

    /* ---- IDirectDraw (23 methods) ---- */
    {
        uint32_t markers[23];
        recomp_func_t funcs[23];
        for (int i = 0; i < 23; i++) markers[i] = MK_DD + i;

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
        funcs[17] = com_stub_2arg;         /* [17] GetVerticalBlankStatus (2) */
        funcs[18] = com_stub_2arg;         /* [18] Initialize (2) */
        funcs[19] = com_stub_1arg;         /* [19] RestoreDisplayMode (1) */
        funcs[20] = dd_SetCooperativeLevel;/* [20] SetCooperativeLevel (3) */
        funcs[21] = dd_SetDisplayMode;     /* [21] SetDisplayMode (4) */
        funcs[22] = com_stub_3arg;         /* [22] WaitForVerticalBlank (3) */

        g_ddraw_vtable_addr = alloc_vtable(markers, 23);
        for (int i = 0; i < 23; i++)
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

    /* ---- IDirect3DViewport (16 methods) ---- */
    {
        uint32_t markers[16];
        recomp_func_t funcs[16];
        for (int i = 0; i < 16; i++) markers[i] = MK_D3DVP + i;

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

        g_d3dviewport_vtable_addr = alloc_vtable(markers, 16);
        for (int i = 0; i < 16; i++)
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
        funcs[5]  = com_stub_3arg;          /* DuplicateSoundBuffer */
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
