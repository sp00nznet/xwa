/*
 * d3d: the game's Direct3D (version 1: IDirect3D, execute buffers) on top of
 * softdd's surfaces, drawn by gpu.c.
 *
 * X-Wing's "640x480 3D Hardware" mode transforms and lights its geometry
 * itself and hands Direct3D screen-space triangles (D3DTLVERTEX) in execute
 * buffers; that is what makes a high-resolution renderer possible without
 * touching the game's 3D code. The objects here keep what the game sets and
 * turn each Execute into gpu_draw() calls. Viewport::Clear also writes KEY16
 * into the render target, so the 2D the game draws over the 3D afterwards
 * (the cockpit) is all that is left in it, and gpu.c composites it over the
 * high-resolution 3D.
 *
 * The device answers as a HAL with 16-bit rendering and textures in 565,
 * 1555, 4444 and 8-bit palettized formats.
 */
#define WIN32_LEAN_AND_MEAN

#include "softdd_int.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpu.h"

#define UNIMPL(what) do { static int once; if (!once++) fprintf(stderr, "[d3d] unimplemented: %s\n", what); } while (0)

static int g_active;
int d3d_active(void) { return g_active; }

/* ---- small objects: material, light, viewport, execute buffer --------------- */
typedef struct { IDirect3DMaterialVtbl* lpVtbl; LONG refs; D3DMATERIAL m; } Mat;
typedef struct { IDirect3DLightVtbl* lpVtbl; LONG refs; } Light;
typedef struct { IDirect3DViewportVtbl* lpVtbl; LONG refs; D3DVIEWPORT vp; uint32_t bg; float z; struct Dev* dev; } VP;
typedef struct { IDirect3DExecuteBufferVtbl* lpVtbl; LONG refs; uint8_t* buf; DWORD size; D3DEXECUTEDATA ed; } EB;
typedef struct Dev { IDirect3DDeviceVtbl* lpVtbl; LONG refs; Surf* target; D3DMATRIX mats[64]; int nmats; } Dev;
typedef struct { IDirect3DVtbl* lpVtbl; LONG refs; } D3D;

static HRESULT WINAPI no_qi(void* t, REFIID r, void** o) {
    (void)t;
    fprintf(stderr, "[d3d] QueryInterface {%08lX-%04X-%04X} refused\n", r->Data1, r->Data2, r->Data3);
    *o = NULL;
    return E_NOINTERFACE;
}
#define REFS(T) \
    static ULONG WINAPI T##_AddRef(void* t) { return ++((T*)t)->refs; } \
    static ULONG WINAPI T##_Release(void* t) { LONG n = --((T*)t)->refs; if (!n) free(t); return n; }
REFS(Mat) REFS(Light) REFS(VP) REFS(D3D)
static ULONG WINAPI EB_AddRef(void* t) { return ++((EB*)t)->refs; }
static ULONG WINAPI EB_Release(void* t) { EB* e = (EB*)t; LONG n = --e->refs; if (!n) { free(e->buf); free(e); } return n; }
static ULONG WINAPI Dev_AddRef(void* t) { return ++((Dev*)t)->refs; }
static ULONG WINAPI Dev_Release(void* t) { return --((Dev*)t)->refs; }   /* one per process */

/* material: the viewport's background colour */
static HRESULT WINAPI mat_Initialize(void* t, LPDIRECT3D d) { (void)t; (void)d; return DD_OK; }
static HRESULT WINAPI mat_Set(void* t, LPD3DMATERIAL m) { ((Mat*)t)->m = *m; return DD_OK; }
static HRESULT WINAPI mat_Get(void* t, LPD3DMATERIAL m) { *m = ((Mat*)t)->m; return DD_OK; }
static HRESULT WINAPI mat_GetHandle(void* t, LPDIRECT3DDEVICE d, LPD3DMATERIALHANDLE h) { (void)d; *h = (D3DMATERIALHANDLE)(uintptr_t)t; return DD_OK; }
static HRESULT WINAPI mat_Reserve(void* t) { (void)t; return DD_OK; }
static IDirect3DMaterialVtbl mat_vt = { (void*)no_qi, (void*)Mat_AddRef, (void*)Mat_Release, (void*)mat_Initialize,
                                        (void*)mat_Set, (void*)mat_Get, (void*)mat_GetHandle, (void*)mat_Reserve, (void*)mat_Reserve };

static HRESULT WINAPI light_Initialize(void* t, LPDIRECT3D d) { (void)t; (void)d; return DD_OK; }
static HRESULT WINAPI light_Set(void* t, LPD3DLIGHT l) { (void)t; (void)l; return DD_OK; }
static IDirect3DLightVtbl light_vt = { (void*)no_qi, (void*)Light_AddRef, (void*)Light_Release, (void*)light_Initialize,
                                       (void*)light_Set, (void*)light_Set };

/* viewport */
static uint32_t to_rgb(const D3DCOLORVALUE* c) {
    int r = (int)(c->r * 255 + 0.5f), g = (int)(c->g * 255 + 0.5f), b = (int)(c->b * 255 + 0.5f);
    r = r < 0 ? 0 : r > 255 ? 255 : r, g = g < 0 ? 0 : g > 255 ? 255 : g, b = b < 0 ? 0 : b > 255 ? 255 : b;
    return (uint32_t)(r << 16 | g << 8 | b);
}
static HRESULT WINAPI vp_Initialize(void* t, LPDIRECT3D d) { (void)t; (void)d; return DD_OK; }
static HRESULT WINAPI vp_Get(void* t, LPD3DVIEWPORT v) { *v = ((VP*)t)->vp; return DD_OK; }
static HRESULT WINAPI vp_Set(void* t, LPD3DVIEWPORT v) { ((VP*)t)->vp = *v; return DD_OK; }
static HRESULT WINAPI vp_Transform(void* t, DWORD n, LPD3DTRANSFORMDATA d, DWORD f, LPDWORD o) {
    (void)t; (void)n; (void)d; (void)f; (void)o; UNIMPL("Viewport::TransformVertices"); return DDERR_UNSUPPORTED;
}
static HRESULT WINAPI vp_Light(void* t, DWORD n, LPD3DLIGHTDATA d) { (void)t; (void)n; (void)d; return DDERR_UNSUPPORTED; }
static HRESULT WINAPI vp_SetBackground(void* t, D3DMATERIALHANDLE h) {
    Mat* m = (Mat*)(uintptr_t)h;
    ((VP*)t)->bg = m ? to_rgb(&m->m.diffuse) : 0;
    return DD_OK;
}
static HRESULT WINAPI vp_GetBackground(void* t, LPD3DMATERIALHANDLE h, LPBOOL v) { (void)t; *h = 0; *v = FALSE; return DD_OK; }
static HRESULT WINAPI vp_SetBgDepth(void* t, LPDIRECTDRAWSURFACE s) { (void)t; (void)s; return DD_OK; }
static HRESULT WINAPI vp_GetBgDepth(void* t, LPDIRECTDRAWSURFACE* s, LPBOOL v) { (void)t; *s = NULL; *v = FALSE; return DD_OK; }
/* Clear: the 3D target (gpu), and the rectangles in the render target become
 * KEY16, so only what the game draws over the 3D afterwards stays opaque. */
static int g_cleared;   /* this frame: 1 target, 2 z-buffer */
static HRESULT WINAPI vp_Clear(void* t, DWORD n, LPD3DRECT r, DWORD flags) {
    VP* v = (VP*)t;
    if (flags & D3DCLEAR_TARGET) g_cleared |= 1;
    if (flags & D3DCLEAR_ZBUFFER) g_cleared |= 2;
    Surf* s = v->dev ? v->dev->target : NULL;
    for (DWORD i = 0; i < n; i++) {
        gpu_clear(r[i].x1, r[i].y1, r[i].x2, r[i].y2, flags & D3DCLEAR_TARGET, v->bg, flags & D3DCLEAR_ZBUFFER, v->z);
        if (s && s->bpp == 16 && (flags & D3DCLEAR_TARGET)) {
            int x0 = r[i].x1 < 0 ? 0 : r[i].x1, y0 = r[i].y1 < 0 ? 0 : r[i].y1;
            int x1 = r[i].x2 > s->w ? s->w : r[i].x2, y1 = r[i].y2 > s->h ? s->h : r[i].y2;
            for (int y = y0; y < y1; y++) {
                uint16_t* p = (uint16_t*)(s->bits + (size_t)y * s->pitch);
                for (int x = x0; x < x1; x++) p[x] = KEY16;
            }
            s->version++;
        }
    }
    g_active = 1;
    return DD_OK;
}
static HRESULT WINAPI vp_Lights(void* t, LPDIRECT3DLIGHT l) { (void)t; (void)l; return DD_OK; }
static HRESULT WINAPI vp_NextLight(void* t, LPDIRECT3DLIGHT l, LPDIRECT3DLIGHT* o, DWORD f) { (void)t; (void)l; (void)f; *o = NULL; return DDERR_UNSUPPORTED; }
/* Viewport2/3's additions. Direct3D gives one object the whole v3 table
 * whichever version was asked for, and this build of the game relies on it:
 * it calls Clear2 (slot 20) on a viewport from IDirect3D::CreateViewport. */
static HRESULT WINAPI vp_Get2(void* t, void* v) { (void)t; (void)v; return DD_OK; }
static HRESULT WINAPI vp_SetBgDepth2(void* t, void* s) { (void)t; (void)s; return DD_OK; }
static HRESULT WINAPI vp_GetBgDepth2(void* t, void** s, LPBOOL v) { (void)t; *s = NULL; *v = FALSE; return DD_OK; }
static HRESULT WINAPI vp_Clear2(void* t, DWORD n, LPD3DRECT r, DWORD flags, DWORD color, float z, DWORD stencil) {
    (void)stencil;
    VP* v = (VP*)t;
    uint32_t bg = v->bg;
    v->bg = color & 0xFFFFFF, v->z = z;
    vp_Clear(t, n, r, flags & (D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER));
    v->bg = bg, v->z = 1.0f;
    return DD_OK;
}
static void* vp_vt[21] = { (void*)no_qi, (void*)VP_AddRef, (void*)VP_Release, (void*)vp_Initialize,
    (void*)vp_Get, (void*)vp_Set, (void*)vp_Transform, (void*)vp_Light, (void*)vp_SetBackground, (void*)vp_GetBackground,
    (void*)vp_SetBgDepth, (void*)vp_GetBgDepth, (void*)vp_Clear, (void*)vp_Lights, (void*)vp_Lights, (void*)vp_NextLight,
    (void*)vp_Get2, (void*)vp_Get2, (void*)vp_SetBgDepth2, (void*)vp_GetBgDepth2, (void*)vp_Clear2 };

/* execute buffer: plain memory the game fills between Lock and Unlock */
static HRESULT WINAPI eb_Initialize(void* t, LPDIRECT3DDEVICE d, LPD3DEXECUTEBUFFERDESC e) { (void)t; (void)d; (void)e; return DD_OK; }
static HRESULT WINAPI eb_Lock(void* t, LPD3DEXECUTEBUFFERDESC d) {
    EB* e = (EB*)t;
    d->dwFlags |= D3DDEB_LPDATA | D3DDEB_BUFSIZE;
    d->lpData = e->buf;
    d->dwBufferSize = e->size;
    return DD_OK;
}
static HRESULT WINAPI eb_Unlock(void* t) { (void)t; return DD_OK; }
static HRESULT WINAPI eb_SetData(void* t, LPD3DEXECUTEDATA d) { ((EB*)t)->ed = *d; return DD_OK; }
static HRESULT WINAPI eb_GetData(void* t, LPD3DEXECUTEDATA d) { *d = ((EB*)t)->ed; return DD_OK; }
static HRESULT WINAPI eb_Validate(void* t, LPDWORD o, LPD3DVALIDATECALLBACK cb, LPVOID c, DWORD r) { (void)t; (void)o; (void)cb; (void)c; (void)r; return DD_OK; }
static HRESULT WINAPI eb_Optimize(void* t, DWORD f) { (void)t; (void)f; return DD_OK; }
static IDirect3DExecuteBufferVtbl eb_vt = { (void*)no_qi, (void*)EB_AddRef, (void*)EB_Release, (void*)eb_Initialize,
    (void*)eb_Lock, (void*)eb_Unlock, (void*)eb_SetData, (void*)eb_GetData, (void*)eb_Validate, (void*)eb_Optimize };

/* ---- texture: the IDirect3DTexture face of a softdd surface ------------------ */
#define TSURF(t) softdd_surf(t)
static ULONG WINAPI tex_AddRef(void* t) { return ++TSURF(t)->refs; }
static ULONG WINAPI tex_Release(void* t) { Surf* s = TSURF(t); return s->lpVtbl->Release((IDirectDrawSurface*)s); }
static HRESULT WINAPI tex_QI(void* t, REFIID r, void** o) { Surf* s = TSURF(t); return s->lpVtbl->QueryInterface((IDirectDrawSurface*)s, r, o); }
static HRESULT WINAPI tex_Initialize(void* t, LPDIRECT3DDEVICE d, LPDIRECTDRAWSURFACE s) { (void)t; (void)d; (void)s; return DD_OK; }
static HRESULT WINAPI tex_GetHandle(void* t, LPDIRECT3DDEVICE d, LPD3DTEXTUREHANDLE h) { (void)d; *h = (D3DTEXTUREHANDLE)(uintptr_t)TSURF(t); return DD_OK; }
static HRESULT WINAPI tex_PaletteChanged(void* t, DWORD a, DWORD b) { (void)a; (void)b; TSURF(t)->version++; return DD_OK; }
/* Load: a system-memory copy into the "video memory" texture */
static void tex_copy(Surf* d, Surf* s) {
    if (!d || !s || d == s) return;
    int rows = d->h < s->h ? d->h : s->h, n = d->pitch < s->pitch ? d->pitch : s->pitch;
    for (int y = 0; y < rows; y++) memcpy(d->bits + (size_t)y * d->pitch, s->bits + (size_t)y * s->pitch, n);
    if (s->pal && s->pal != d->pal) { s->pal->lpVtbl->AddRef(s->pal); if (d->pal) d->pal->lpVtbl->Release(d->pal); d->pal = s->pal; }
    d->has_ck = s->has_ck, d->ck_lo = s->ck_lo, d->ck_hi = s->ck_hi;
    d->version++;
}
static HRESULT WINAPI tex_Load(void* t, LPDIRECT3DTEXTURE src) { tex_copy(TSURF(t), src ? TSURF(src) : NULL); return DD_OK; }
static HRESULT WINAPI tex_Unload(void* t) { (void)t; return DD_OK; }
IDirect3DTextureVtbl d3d_texture_vt = { (void*)tex_QI, (void*)tex_AddRef, (void*)tex_Release, (void*)tex_Initialize,
    (void*)tex_GetHandle, (void*)tex_PaletteChanged, (void*)tex_Load, (void*)tex_Unload };

/* ---- the device's description ------------------------------------------------- */
static void describe(D3DDEVICEDESC* d, int hal) {
    DWORD size = d->dwSize ? d->dwSize : sizeof *d;
    memset(d, 0, size);
    d->dwSize = size;
    if (!hal) return;
    d->dwFlags = D3DDD_COLORMODEL | D3DDD_DEVCAPS | D3DDD_TRICAPS | D3DDD_LINECAPS | D3DDD_DEVICERENDERBITDEPTH
               | D3DDD_DEVICEZBUFFERBITDEPTH | D3DDD_MAXBUFFERSIZE | D3DDD_MAXVERTEXCOUNT | D3DDD_BCLIPPING;
    d->dcmColorModel = D3DCOLOR_RGB;
    d->dwDevCaps = D3DDEVCAPS_FLOATTLVERTEX | D3DDEVCAPS_EXECUTESYSTEMMEMORY | D3DDEVCAPS_TLVERTEXSYSTEMMEMORY
                 | D3DDEVCAPS_TEXTURESYSTEMMEMORY | D3DDEVCAPS_TEXTUREVIDEOMEMORY | D3DDEVCAPS_DRAWPRIMTLVERTEX
                 | D3DDEVCAPS_CANRENDERAFTERFLIP | D3DDEVCAPS_HWRASTERIZATION;
    D3DPRIMCAPS pc = { sizeof pc };
    pc.dwMiscCaps = D3DPMISCCAPS_MASKZ | D3DPMISCCAPS_CULLNONE | D3DPMISCCAPS_CULLCW | D3DPMISCCAPS_CULLCCW;
    pc.dwRasterCaps = D3DPRASTERCAPS_DITHER | D3DPRASTERCAPS_ZTEST | D3DPRASTERCAPS_SUBPIXEL | D3DPRASTERCAPS_FOGVERTEX;
    pc.dwZCmpCaps = pc.dwAlphaCmpCaps = 0xFF;
    pc.dwSrcBlendCaps = pc.dwDestBlendCaps = 0x1FFF;
    pc.dwShadeCaps = 0xFFFFF;
    pc.dwTextureCaps = D3DPTEXTURECAPS_PERSPECTIVE | D3DPTEXTURECAPS_TRANSPARENCY | D3DPTEXTURECAPS_ALPHA;
    pc.dwTextureFilterCaps = D3DPTFILTERCAPS_NEAREST | D3DPTFILTERCAPS_LINEAR | D3DPTFILTERCAPS_MIPNEAREST
                           | D3DPTFILTERCAPS_MIPLINEAR | D3DPTFILTERCAPS_LINEARMIPNEAREST | D3DPTFILTERCAPS_LINEARMIPLINEAR;
    pc.dwTextureBlendCaps = 0xFF;
    pc.dwTextureAddressCaps = D3DPTADDRESSCAPS_WRAP | D3DPTADDRESSCAPS_MIRROR | D3DPTADDRESSCAPS_CLAMP;
    d->dpcLineCaps = d->dpcTriCaps = pc;
    d->dwDeviceRenderBitDepth = DDBD_16;
    d->dwDeviceZBufferBitDepth = DDBD_16;
    d->dwMaxVertexCount = 65535;
}

/* ---- execute ---------------------------------------------------------------------- */
static gpu_state g_st = { 0, 1, 1, 4, 0, 2, 1, 2, 0, 0, 0, 0, 0, 0, 1 };
static Surf* g_tex_surf;   /* TEXTUREHANDLE */
static gpu_vertex g_work[65536];
static uint16_t g_idx[65536 * 3];

static void set_state(DWORD k, DWORD v) {
    switch (k) {
    case D3DRENDERSTATE_TEXTUREHANDLE: g_tex_surf = (Surf*)(uintptr_t)v; break;
    case D3DRENDERSTATE_TEXTUREADDRESS: g_st.wrap = (int)v; break;
    case D3DRENDERSTATE_ZENABLE: g_st.zenable = v != 0; break;
    case D3DRENDERSTATE_ZWRITEENABLE: g_st.zwrite = v != 0; break;
    case D3DRENDERSTATE_ZFUNC: g_st.zfunc = (int)v; break;
    case D3DRENDERSTATE_ALPHATESTENABLE: g_st.alphatest = v != 0; break;
    case D3DRENDERSTATE_ALPHAREF: g_st.alpharef = (int)v; break;
    case D3DRENDERSTATE_SRCBLEND: g_st.src = (int)v; break;
    case D3DRENDERSTATE_DESTBLEND: g_st.dst = (int)v; break;
    case D3DRENDERSTATE_TEXTUREMAPBLEND: g_st.mapblend = (int)v; break;
    case D3DRENDERSTATE_ALPHABLENDENABLE: g_st.blend = v != 0; break;
    case D3DRENDERSTATE_FOGENABLE: g_st.fog = v != 0; break;
    case D3DRENDERSTATE_SPECULARENABLE: g_st.specular = v != 0; break;
    case D3DRENDERSTATE_FOGCOLOR: g_st.fogcolor = v; break;
    case D3DRENDERSTATE_COLORKEYENABLE: g_st.colorkey = v != 0; break;
    default: break;   /* shading, dither, cull, filters (ours), perspective (always) */
    }
}

static int bind_texture(void) {
    Surf* s = g_tex_surf;
    if (!s || !s->bits) return 0;
    gpu_fmt f = { s->bpp, s->rmask, s->gmask, s->bmask, s->amask,
                  s->pal ? ((Pal*)s->pal)->e : NULL, s->has_ck && (g_st.colorkey || !s->amask), s->ck_lo };
    return gpu_texture(s, s->version, s->bits, s->w, s->h, s->pitch, &f);
}

/* Draw the collected triangles: only the vertices they use are sent. */
static void flush(int ni) {
    if (ni <= 0) return;
    int lo = 65535, hi = 0;
    for (int i = 0; i < ni; i++) { if (g_idx[i] < lo) lo = g_idx[i]; if (g_idx[i] > hi) hi = g_idx[i]; }
    for (int i = 0; i < ni; i++) g_idx[i] = (uint16_t)(g_idx[i] - lo);
    g_st.tex = bind_texture();
    if (getenv("XW_LOG3D")) {   /* the first batches, for checking what the game sends */
        static int n;
        if (n++ < 40) {
            const gpu_vertex* v = g_work + lo + g_idx[0];
            fprintf(stderr, "[3d] %d tris tex %p(%d) z%d/%d/%d blend %d %d/%d map %d ck %d | v0 %.1f %.1f z%.4f rhw%.4f c%08X s%08X uv %.3f %.3f\n",
                    ni / 3, (void*)g_tex_surf, g_st.tex, g_st.zenable, g_st.zwrite, g_st.zfunc, g_st.blend, g_st.src, g_st.dst,
                    g_st.mapblend, g_st.colorkey, v->sx, v->sy, v->sz, v->rhw, v->color, v->specular, v->tu, v->tv);
        }
    }
    gpu_draw(g_work + lo, hi - lo + 1, g_idx, ni, &g_st);
}

static void execute(EB* e) {
    uint8_t* base = e->buf;
    D3DEXECUTEDATA* ed = &e->ed;
    if (ed->dwVertexCount > 65536 || ed->dwVertexOffset + ed->dwVertexCount * 32 > e->size) return;
    const gpu_vertex* in = (const gpu_vertex*)(base + ed->dwVertexOffset);
    int processed = 0;
    uint8_t *p = base + ed->dwInstructionOffset, *end = p + ed->dwInstructionLength;
    if (end > base + e->size) end = base + e->size;
    while (p + sizeof(D3DINSTRUCTION) <= end) {
        D3DINSTRUCTION* ins = (D3DINSTRUCTION*)p;
        uint8_t* d = p + sizeof *ins;
        uint8_t* next = d + (size_t)ins->bSize * ins->wCount;
        switch (ins->bOpcode) {
        case D3DOP_PROCESSVERTICES:
            for (int i = 0; i < ins->wCount; i++) {
                D3DPROCESSVERTICES* pv = (D3DPROCESSVERTICES*)(d + i * ins->bSize);
                if ((pv->dwFlags & D3DPROCESSVERTICES_OPMASK) != D3DPROCESSVERTICES_COPY) UNIMPL("PROCESSVERTICES transform");
                if (pv->wStart + pv->dwCount <= ed->dwVertexCount && pv->wDest + pv->dwCount <= 65536)
                    memcpy(g_work + pv->wDest, in + pv->wStart, pv->dwCount * sizeof(gpu_vertex));
                processed = 1;
            }
            break;
        case D3DOP_STATERENDER:
            for (int i = 0; i < ins->wCount; i++) {
                D3DSTATE* s = (D3DSTATE*)(d + i * ins->bSize);
                set_state(s->drstRenderStateType, s->dwArg[0]);
            }
            break;
        case D3DOP_TRIANGLE: {
            if (!processed) { memcpy(g_work, in, ed->dwVertexCount * sizeof(gpu_vertex)); processed = 1; }
            int n = 0;
            for (int i = 0; i < ins->wCount; i++) {
                D3DTRIANGLE* t = (D3DTRIANGLE*)(d + i * ins->bSize);
                if (n + 3 > (int)(sizeof g_idx / 2)) { flush(n); n = 0; }
                g_idx[n++] = t->v1, g_idx[n++] = t->v2, g_idx[n++] = t->v3;
            }
            flush(n);
            break;
        }
        case D3DOP_TEXTURELOAD:
            for (int i = 0; i < ins->wCount; i++) {
                D3DTEXTURELOAD* tl = (D3DTEXTURELOAD*)(d + i * ins->bSize);
                tex_copy((Surf*)(uintptr_t)tl->hDestTexture, (Surf*)(uintptr_t)tl->hSrcTexture);
            }
            break;
        case D3DOP_EXIT:
            return;
        case D3DOP_BRANCHFORWARD: UNIMPL("BRANCHFORWARD (not taken)"); break;
        case D3DOP_POINT: UNIMPL("POINT"); break;
        case D3DOP_LINE: UNIMPL("LINE"); break;
        case D3DOP_SPAN: UNIMPL("SPAN"); break;
        case D3DOP_MATRIXLOAD: case D3DOP_MATRIXMULTIPLY: case D3DOP_STATETRANSFORM:
        case D3DOP_STATELIGHT: case D3DOP_SETSTATUS:
            break;
        default:
            fprintf(stderr, "[d3d] opcode %u: execute buffer stops\n", ins->bOpcode);
            return;
        }
        if (!ins->bSize && ins->wCount) return;   /* malformed: would loop */
        p = next;
    }
}

/* ---- device ---------------------------------------------------------------------- */
static Dev g_dev_obj;
#define dev_QI no_qi
static HRESULT WINAPI dev_Initialize(void* t, LPDIRECT3D d, LPGUID g, LPD3DDEVICEDESC e) { (void)t; (void)d; (void)g; (void)e; return DD_OK; }
static HRESULT WINAPI dev_GetCaps(void* t, LPD3DDEVICEDESC hal, LPD3DDEVICEDESC hel) { (void)t; describe(hal, 1); describe(hel, 0); return DD_OK; }
static HRESULT WINAPI dev_Swap(void* t, LPDIRECT3DTEXTURE a, LPDIRECT3DTEXTURE b) { (void)t; (void)a; (void)b; UNIMPL("SwapTextureHandles"); return DD_OK; }
static HRESULT WINAPI dev_CreateEB(void* t, LPD3DEXECUTEBUFFERDESC d, LPDIRECT3DEXECUTEBUFFER* o, IUnknown* u) {
    (void)t; (void)u;
    EB* e = (EB*)calloc(1, sizeof *e);
    e->lpVtbl = &eb_vt, e->refs = 1;
    e->size = d->dwBufferSize ? d->dwBufferSize : 65536;
    e->buf = (uint8_t*)calloc(1, e->size);
    *o = (LPDIRECT3DEXECUTEBUFFER)e;
    return DD_OK;
}
static HRESULT WINAPI dev_GetStats(void* t, LPD3DSTATS s) { (void)t; DWORD n = s->dwSize; memset(s, 0, n); s->dwSize = n; return DD_OK; }
/* The frame is three layers: the 2D the game drew before its 3D (the stars),
 * the 3D, and the 2D after it (the cockpit). At the first Execute of a frame
 * the render target holds the first: it goes under the 3D (gpu_background),
 * and the target becomes KEY16, so only what is drawn after the 3D covers it. */
static int g_frame_open;
void d3d_frame_done(void) { g_frame_open = 0; g_cleared = 0; }
static void open_frame(Surf* s) {
    if (g_frame_open || !s || s->bpp != 16) return;
    g_frame_open = 1;
    /* XvT never clears through the viewport (its depth test is LESS, and a
     * card of the day began each frame cleared): what the game did not clear
     * starts the frame clear, the depth at the far plane. */
    if ((g_cleared & 3) != 3)
        gpu_clear(0, 0, s->w, s->h, !(g_cleared & 1), 0, !(g_cleared & 2),
                  /* Balance of Power tests GREATER (nearer is larger): its far plane is 0 */
                  g_st.zfunc == D3DCMP_GREATER || g_st.zfunc == D3DCMP_GREATEREQUAL ? 0.0f : 1.0f);
    gpu_background(s->bits, s->w, s->h, s->pitch, s->bpp, NULL);
    for (int y = 0; y < s->h; y++) {
        uint16_t* p = (uint16_t*)(s->bits + (size_t)y * s->pitch);
        for (int x = 0; x < s->w; x++) p[x] = KEY16;
    }
    s->version++;
}

static HRESULT WINAPI dev_Execute(void* t, LPDIRECT3DEXECUTEBUFFER b, LPDIRECT3DVIEWPORT v, DWORD f) {
    (void)v; (void)f;
    g_active = 1;
    open_frame(((Dev*)t)->target);
    execute((EB*)b);
    return DD_OK;
}
static HRESULT WINAPI dev_AddViewport(void* t, LPDIRECT3DVIEWPORT v) { ((VP*)v)->dev = (Dev*)t; return DD_OK; }
static HRESULT WINAPI dev_DelViewport(void* t, LPDIRECT3DVIEWPORT v) { (void)t; (void)v; return DD_OK; }
static HRESULT WINAPI dev_NextViewport(void* t, LPDIRECT3DVIEWPORT v, LPDIRECT3DVIEWPORT* o, DWORD f) { (void)t; (void)v; (void)f; *o = NULL; return DDERR_UNSUPPORTED; }
static HRESULT WINAPI dev_Pick(void* t, LPDIRECT3DEXECUTEBUFFER b, LPDIRECT3DVIEWPORT v, DWORD f, LPD3DRECT r) { (void)t; (void)b; (void)v; (void)f; (void)r; return DDERR_UNSUPPORTED; }
static HRESULT WINAPI dev_GetPick(void* t, LPDWORD n, LPD3DPICKRECORD r) { (void)t; (void)r; *n = 0; return DD_OK; }
typedef HRESULT (CALLBACK *texfmt_cb)(LPDDSURFACEDESC, LPVOID);
static HRESULT WINAPI dev_EnumTexFormats(void* t, LPD3DENUMTEXTUREFORMATSCALLBACK cb, LPVOID ctx) {
    (void)t;
    static const DWORD fm[][6] = {   /* bits, r, g, b, a, palettized */
        { 16, 0xF800, 0x07E0, 0x001F, 0, 0 }, { 16, 0x7C00, 0x03E0, 0x001F, 0x8000, 0 },
        { 16, 0x0F00, 0x00F0, 0x000F, 0xF000, 0 }, { 8, 0, 0, 0, 0, 1 },
    };
    for (int i = 0; i < 4; i++) {
        DDSURFACEDESC d;
        memset(&d, 0, sizeof d);
        d.dwSize = sizeof d;
        d.dwFlags = DDSD_CAPS | DDSD_PIXELFORMAT;
        d.ddsCaps.dwCaps = DDSCAPS_TEXTURE;
        d.ddpfPixelFormat.dwSize = sizeof d.ddpfPixelFormat;
        d.ddpfPixelFormat.dwFlags = DDPF_RGB | (fm[i][4] ? DDPF_ALPHAPIXELS : 0) | (fm[i][5] ? DDPF_PALETTEINDEXED8 : 0);
        d.ddpfPixelFormat.dwRGBBitCount = fm[i][0];
        d.ddpfPixelFormat.dwRBitMask = fm[i][1];
        d.ddpfPixelFormat.dwGBitMask = fm[i][2];
        d.ddpfPixelFormat.dwBBitMask = fm[i][3];
        d.ddpfPixelFormat.dwRGBAlphaBitMask = fm[i][4];
        if (((texfmt_cb)cb)(&d, ctx) == D3DENUMRET_CANCEL) break;
    }
    return DD_OK;
}
static HRESULT WINAPI dev_CreateMatrix(void* t, LPD3DMATRIXHANDLE h) { Dev* d = (Dev*)t; *h = d->nmats < 63 ? ++d->nmats : 63; return DD_OK; }
static HRESULT WINAPI dev_SetMatrix(void* t, D3DMATRIXHANDLE h, const LPD3DMATRIX m) { if (h < 64) ((Dev*)t)->mats[h] = *m; return DD_OK; }
static HRESULT WINAPI dev_GetMatrix(void* t, D3DMATRIXHANDLE h, LPD3DMATRIX m) { if (h < 64) *m = ((Dev*)t)->mats[h]; return DD_OK; }
static HRESULT WINAPI dev_DelMatrix(void* t, D3DMATRIXHANDLE h) { (void)t; (void)h; return DD_OK; }
static HRESULT WINAPI dev_Scene(void* t) { (void)t; return DD_OK; }
static HRESULT WINAPI dev_GetD3D(void* t, LPDIRECT3D* o) { (void)t; return d3d_create((void**)o); }
static IDirect3DDeviceVtbl dev_vt = { (void*)dev_QI, (void*)Dev_AddRef, (void*)Dev_Release, (void*)dev_Initialize,
    (void*)dev_GetCaps, (void*)dev_Swap, (void*)dev_CreateEB, (void*)dev_GetStats, (void*)dev_Execute,
    (void*)dev_AddViewport, (void*)dev_DelViewport, (void*)dev_NextViewport, (void*)dev_Pick, (void*)dev_GetPick,
    (void*)dev_EnumTexFormats, (void*)dev_CreateMatrix, (void*)dev_SetMatrix, (void*)dev_GetMatrix,
    (void*)dev_DelMatrix, (void*)dev_Scene, (void*)dev_Scene, (void*)dev_GetD3D };

HRESULT d3d_device_create(Surf* target, void** out) {
    g_dev_obj.lpVtbl = &dev_vt;
    g_dev_obj.refs++;
    g_dev_obj.target = target;
    *out = &g_dev_obj;
    fprintf(stderr, "[d3d] device on a %dx%dx%d surface: rendered by gpu.c\n", target->w, target->h, target->bpp);
    return DD_OK;
}

/* ---- IDirect3D ------------------------------------------------------------------- */
typedef HRESULT (CALLBACK *devs_cb)(GUID*, LPSTR, LPSTR, LPD3DDEVICEDESC, LPD3DDEVICEDESC, LPVOID);
#define d3d_QI no_qi
static HRESULT WINAPI d3d_Initialize(void* t, REFCLSID c) { (void)t; (void)c; return DD_OK; }
static HRESULT WINAPI d3d_EnumDevices(void* t, LPD3DENUMDEVICESCALLBACK cb, LPVOID ctx) {
    (void)t;
    static D3DDEVICEDESC hal, hel;
    static GUID guid;
    static char desc[] = "Direct3D 11", name[] = "Direct3D HAL";
    guid = IID_IDirect3DHALDevice;
    hal.dwSize = hel.dwSize = sizeof hal;
    describe(&hal, 1);
    describe(&hel, 0);
    ((devs_cb)cb)(&guid, desc, name, &hal, &hel, ctx);
    return DD_OK;
}
static HRESULT WINAPI d3d_CreateLight(void* t, LPDIRECT3DLIGHT* o, IUnknown* u) {
    (void)t; (void)u; Light* l = (Light*)calloc(1, sizeof *l); l->lpVtbl = &light_vt; l->refs = 1; *o = (LPDIRECT3DLIGHT)l; return DD_OK;
}
static HRESULT WINAPI d3d_CreateMaterial(void* t, LPDIRECT3DMATERIAL* o, IUnknown* u) {
    (void)t; (void)u; Mat* m = (Mat*)calloc(1, sizeof *m); m->lpVtbl = &mat_vt; m->refs = 1; *o = (LPDIRECT3DMATERIAL)m; return DD_OK;
}
static HRESULT WINAPI d3d_CreateViewport(void* t, LPDIRECT3DVIEWPORT* o, IUnknown* u) {
    (void)t; (void)u; VP* v = (VP*)calloc(1, sizeof *v); v->z = 1.0f; v->lpVtbl = (IDirect3DViewportVtbl*)vp_vt; v->refs = 1; *o = (LPDIRECT3DVIEWPORT)v; return DD_OK;
}
static HRESULT WINAPI d3d_FindDevice(void* t, LPD3DFINDDEVICESEARCH s, LPD3DFINDDEVICERESULT r) {
    (void)t; (void)s;
    r->guid = IID_IDirect3DHALDevice;
    r->ddHwDesc.dwSize = r->ddSwDesc.dwSize = sizeof r->ddHwDesc;
    describe(&r->ddHwDesc, 1);
    describe(&r->ddSwDesc, 0);
    return DD_OK;
}
static IDirect3DVtbl d3d_vt = { (void*)d3d_QI, (void*)D3D_AddRef, (void*)D3D_Release, (void*)d3d_Initialize,
    (void*)d3d_EnumDevices, (void*)d3d_CreateLight, (void*)d3d_CreateMaterial, (void*)d3d_CreateViewport, (void*)d3d_FindDevice };

HRESULT d3d_create(void** out) {
    D3D* d = (D3D*)calloc(1, sizeof *d);
    d->lpVtbl = &d3d_vt, d->refs = 1;
    *out = d;
    fprintf(stderr, "[d3d] IDirect3D: the game's 3D hardware mode, through Direct3D 11\n");
    return DD_OK;
}
