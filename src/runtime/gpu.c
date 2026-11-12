/*
 * gpu: the game's picture through Direct3D 11.
 *
 * Two layers, composited at present:
 *
 *   3D   the game's Direct3D (version 1, execute buffers; d3d.c parses them)
 *        draws screen-space vertices in its 640x480 coordinates. They are
 *        rendered into a target the size of the picture on screen, so the
 *        geometry is as sharp as the window is big (1080p, 4K), with the
 *        texture filtering of the settings (the original is nearest).
 *   2D   the primary as the game drew it: menus, cutscenes, the cockpit. It
 *        is scaled with Gunman's shaders (sharp-bilinear, smooth, CRT,
 *        nearest, integer). When there was 3D this frame, the pixels the game
 *        cleared for it (a key value d3d.c writes on Viewport::Clear) are holes
 *        and the 3D shows through: the cockpit drawn over a high-resolution
 *        view.
 *
 * Textures come in through gpu_texture() keyed by surface and version; a
 * replacement PNG in mods/textures/<hash>.png is used in place of the
 * original (hd_textures), and dump_textures writes each original there to
 * mods/dump/ for an artist to upscale. PNGs go through WIC.
 */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <wincodec.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpu.h"

gpu_settings g_gpu = { GPU_SHARP, 1, 0, 0, 1, 0, 4 };   /* widescreen off: Hor+ needs the flight projection (ROADMAP) */
const char* const gpu_mode_names[GPU_NMODES] = { "sharp", "smooth", "crt", "nearest", "integer" };

#define GW 640
#define GH 480

typedef HRESULT (WINAPI *compile_fn)(LPCVOID, SIZE_T, LPCSTR, const void*, void*, LPCSTR, LPCSTR,
                                     UINT, UINT, ID3DBlob**, ID3DBlob**);

/* ---- shaders ---------------------------------------------------------------- */
static const char k_hlsl[] =
/* the 2D picture and the 3D target, drawn into the picture's rectangle */
"Texture2D t0 : register(t0);\n"
"SamplerState s_lin : register(s0);\n"
"SamplerState s_pt : register(s1);\n"
"cbuffer P : register(b0) { float2 src; float2 dst; int mode; int keyed; int layer3d; int pad; };\n"
"struct Q { float4 pos : SV_Position; float2 uv : TEXCOORD0; };\n"
"Q vs_quad(uint id : SV_VertexID) {\n"
"  Q o; float2 p = float2((id << 1) & 2, id & 2);\n"
"  o.pos = float4(p * float2(2, -2) + float2(-1, 1), 0, 1); o.uv = p; return o;\n"
"}\n"
"float4 sharp(float2 uv) {\n"
"  float2 scale = max(dst / src, 1.0);\n"
"  float2 texel = uv * src, fl = floor(texel), c = frac(texel) - 0.5;\n"
"  float2 range = 0.5 - 0.5 / scale;\n"
"  float2 f = (c - clamp(c, -range, range)) * scale + 0.5;\n"
"  return t0.Sample(s_lin, (fl + f) / src);\n"
"}\n"
"float4 ps_quad(Q i) : SV_Target {\n"
"  if (layer3d) return t0.Sample(s_pt, i.uv);\n"
"  float4 c = mode == 1 ? t0.Sample(s_lin, i.uv) : (mode >= 3 ? t0.Sample(s_pt, i.uv) : sharp(i.uv));\n"
"  if (keyed && t0.Sample(s_pt, i.uv).a < 0.5) discard;\n"   /* a hole: the 3D below */
"  if (mode == 2) {\n"                                       /* CRT: scanlines + aperture grille */
"    float k = saturate((dst.y / src.y - 1.5) / 1.5);\n"
"    float d = frac(i.uv.y * src.y) - 0.5;\n"
"    float beam = lerp(1.0, exp(-d * d * 8.0) * 1.6, k);\n"
"    uint m = (uint)i.pos.x % 3u;\n"
"    float3 mask = m == 0u ? float3(1.25, 0.87, 0.87) : m == 1u ? float3(0.87, 1.25, 0.87) : float3(0.87, 0.87, 1.25);\n"
"    c.rgb *= beam * lerp(float3(1, 1, 1), mask, k);\n"
"  }\n"
"  return float4(c.rgb, 1);\n"
"}\n"
/* the game's 3D */
"cbuffer S : register(b1) { float4 fogcol; float xscale; int texon; int mapblend; int spec; int fog; int atest; float aref; int pad2; };\n"
"struct VI { float4 p : POSITION; float4 c : COLOR0; float4 s : COLOR1; float2 t : TEXCOORD0; };\n"
"struct VO { float4 p : SV_Position; float4 c : COLOR0; float4 s : COLOR1; float2 t : TEXCOORD0; };\n"
"Texture2D tex : register(t1);\n"
"SamplerState s_tex : register(s2);\n"
"VO vs_tl(VI i) {\n"
"  VO o;\n"
"  float x = (i.p.x / 320.0 - 1.0) * xscale;\n"               /* Hor+: the 4:3 middle of a wider view */
"  o.p = float4(x, 1.0 - i.p.y / 240.0, saturate(i.p.z), 1);\n"
"  if (i.p.w > 1e-6 && i.p.w < 1e6) o.p *= 1.0 / i.p.w;\n"     /* perspective-correct texturing */
"  o.c = i.c; o.s = i.s; o.t = i.t; return o;\n"
"}\n"
"float4 ps_tl(VO i) : SV_Target {\n"
"  float4 c = i.c;\n"
"  if (texon) {\n"
"    float4 t = tex.Sample(s_tex, i.t);\n"
"    if (mapblend == 1 || mapblend == 3 || mapblend == 6) c = mapblend == 1 ? float4(t.rgb, t.a) : t;\n" /* DECAL, DECALALPHA, COPY */
"    else if (mapblend == 4) c = t * i.c;\n"                       /* MODULATEALPHA */
"    else if (mapblend == 7) c = float4(saturate(t.rgb + i.c.rgb), t.a);\n" /* ADD */
"    else c = float4(t.rgb * i.c.rgb, t.a < 0.5 ? 0 : i.c.a);\n"   /* MODULATE: the key still cuts */
"    if (atest && t.a < 0.5) discard;\n"
"  }\n"
"  if (spec) c.rgb = saturate(c.rgb + i.s.rgb);\n"
"  if (fog) c.rgb = lerp(fogcol.rgb, c.rgb, i.s.a);\n"
"  if (atest > 1 && c.a < aref) discard;\n"
"  return c;\n"
"}\n";

/* ---- state ----------------------------------------------------------------- */
static HWND g_wnd;
static int g_ok;
static ID3D11Device* g_dev;
static ID3D11DeviceContext* g_ctx;
static IDXGISwapChain* g_sc;
static ID3D11RenderTargetView* g_bb_rtv;
static int g_bb_w, g_bb_h;
static ID3D11VertexShader *g_vs_quad, *g_vs_tl;
static ID3D11PixelShader *g_ps_quad, *g_ps_tl;
static ID3D11InputLayout* g_layout;
static ID3D11Buffer *g_cb_p, *g_cb_s, *g_vb, *g_ib;
static ID3D11SamplerState *g_s_lin, *g_s_pt, *g_s_tex[3][2];   /* filter x (wrap, clamp) */
static ID3D11RasterizerState* g_rs;
static ID3D11BlendState* g_bs_opaque;

/* the 2D picture */
typedef struct { ID3D11Texture2D* tex; ID3D11ShaderResourceView* srv; int w, h; uint32_t* rgba; } layer_t;
static layer_t g_l2d;   /* the frame as presented: over the 3D when there is 3D */
static layer_t g_lbg;   /* what the frame held when the 3D began: under it */
static int g_2d_keyed;

/* the 3D target: the picture's size on screen (times MSAA), and its depth */
static ID3D11Texture2D *g_3d, *g_3d_resolved, *g_3d_depth;
static ID3D11RenderTargetView* g_3d_rtv;
static ID3D11ShaderResourceView* g_3d_srv;
static ID3D11DepthStencilView* g_3d_dsv;
static int g_3d_w, g_3d_h, g_3d_msaa;
static int g_3d_draws;          /* since the last present */
static RECT g_pic;              /* the picture (4:3) on the back buffer */
static RECT g_pic3d;            /* the 3D view (wider when Hor+) */

static volatile LONG g_shot_due;
static char g_shot_path[MAX_PATH];

#define MAXV 65536
#define MAXI (65536 * 3)

static void fail(const char* what, HRESULT hr) {
    fprintf(stderr, "[gpu] %s failed (%08lX): drawing with GDI\n", what, hr);
}

static ID3DBlob* compile(compile_fn fn, const char* entry, const char* target) {
    ID3DBlob *b = NULL, *err = NULL;
    HRESULT hr = fn(k_hlsl, sizeof k_hlsl - 1, "gpu", NULL, NULL, entry, target, 0, 0, &b, &err);
    if (FAILED(hr)) {
        fprintf(stderr, "[gpu] %s: %s\n", entry, err ? (const char*)ID3D10Blob_GetBufferPointer(err) : "?");
        if (err) ID3D10Blob_Release(err);
        return NULL;
    }
    return b;
}

static ID3D11SamplerState* sampler(D3D11_FILTER f, D3D11_TEXTURE_ADDRESS_MODE a, int aniso) {
    D3D11_SAMPLER_DESC d = { f, a, a, a, 0, aniso, D3D11_COMPARISON_NEVER, { 0 }, 0, D3D11_FLOAT32_MAX };
    ID3D11SamplerState* s = NULL;
    ID3D11Device_CreateSamplerState(g_dev, &d, &s);
    return s;
}

static ID3D11Buffer* buffer(UINT size, UINT bind) {
    D3D11_BUFFER_DESC d = { size, D3D11_USAGE_DYNAMIC, bind, D3D11_CPU_ACCESS_WRITE, 0, 0 };
    ID3D11Buffer* b = NULL;
    ID3D11Device_CreateBuffer(g_dev, &d, NULL, &b);
    return b;
}

static void* map(ID3D11Buffer* b) {
    D3D11_MAPPED_SUBRESOURCE m;
    return SUCCEEDED(ID3D11DeviceContext_Map(g_ctx, (ID3D11Resource*)b, 0, D3D11_MAP_WRITE_DISCARD, 0, &m))
        ? m.pData : NULL;
}
static void unmap(ID3D11Buffer* b) { ID3D11DeviceContext_Unmap(g_ctx, (ID3D11Resource*)b, 0); }

int gpu_ready(void) { return g_ok; }

int gpu_init(HWND w) {
    if (g_ok) return 1;
    g_wnd = w;
    HMODULE dc = LoadLibraryA("d3dcompiler_47.dll");
    compile_fn compile_hlsl = dc ? (compile_fn)GetProcAddress(dc, "D3DCompile") : NULL;
    if (!compile_hlsl) { fail("d3dcompiler_47", 0); return 0; }
    RECT r;
    GetClientRect(w, &r);
    DXGI_SWAP_CHAIN_DESC sd = { 0 };
    sd.BufferDesc.Width = r.right > 0 ? r.right : GW;
    sd.BufferDesc.Height = r.bottom > 0 ? r.bottom : GH;
    sd.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.OutputWindow = w;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0,
                                               D3D11_SDK_VERSION, &sd, &g_sc, &g_dev, NULL, &g_ctx);
    if (FAILED(hr))   /* no GPU (a VM): WARP still beats GDI */
        hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP, NULL, 0, NULL, 0,
                                           D3D11_SDK_VERSION, &sd, &g_sc, &g_dev, NULL, &g_ctx);
    if (FAILED(hr)) { fail("D3D11CreateDeviceAndSwapChain", hr); return 0; }
    { IDXGIFactory* f = NULL;   /* Alt+Enter is ours (F11), not DXGI's exclusive mode */
      if (SUCCEEDED(IDXGISwapChain_GetParent(g_sc, &IID_IDXGIFactory, (void**)&f))) {
          IDXGIFactory_MakeWindowAssociation(f, w, DXGI_MWA_NO_ALT_ENTER); IDXGIFactory_Release(f); } }

    ID3DBlob *vq = compile(compile_hlsl, "vs_quad", "vs_5_0"), *pq = compile(compile_hlsl, "ps_quad", "ps_5_0"),
             *vt = compile(compile_hlsl, "vs_tl", "vs_5_0"), *pt = compile(compile_hlsl, "ps_tl", "ps_5_0");
    if (!vq || !pq || !vt || !pt) return 0;
    ID3D11Device_CreateVertexShader(g_dev, ID3D10Blob_GetBufferPointer(vq), ID3D10Blob_GetBufferSize(vq), NULL, &g_vs_quad);
    ID3D11Device_CreatePixelShader(g_dev, ID3D10Blob_GetBufferPointer(pq), ID3D10Blob_GetBufferSize(pq), NULL, &g_ps_quad);
    ID3D11Device_CreateVertexShader(g_dev, ID3D10Blob_GetBufferPointer(vt), ID3D10Blob_GetBufferSize(vt), NULL, &g_vs_tl);
    ID3D11Device_CreatePixelShader(g_dev, ID3D10Blob_GetBufferPointer(pt), ID3D10Blob_GetBufferSize(pt), NULL, &g_ps_tl);
    D3D11_INPUT_ELEMENT_DESC il[] = {
        { "POSITION", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "COLOR", 0, DXGI_FORMAT_B8G8R8A8_UNORM, 0, 16, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "COLOR", 1, DXGI_FORMAT_B8G8R8A8_UNORM, 0, 20, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 24, D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };
    ID3D11Device_CreateInputLayout(g_dev, il, 4, ID3D10Blob_GetBufferPointer(vt), ID3D10Blob_GetBufferSize(vt), &g_layout);
    g_cb_p = buffer(32, D3D11_BIND_CONSTANT_BUFFER);
    g_cb_s = buffer(48, D3D11_BIND_CONSTANT_BUFFER);
    g_vb = buffer(MAXV * sizeof(gpu_vertex), D3D11_BIND_VERTEX_BUFFER);
    g_ib = buffer(MAXI * 2, D3D11_BIND_INDEX_BUFFER);
    g_s_lin = sampler(D3D11_FILTER_MIN_MAG_MIP_LINEAR, D3D11_TEXTURE_ADDRESS_CLAMP, 1);
    g_s_pt = sampler(D3D11_FILTER_MIN_MAG_MIP_POINT, D3D11_TEXTURE_ADDRESS_CLAMP, 1);
    for (int a = 0; a < 2; a++) {
        D3D11_TEXTURE_ADDRESS_MODE m = a ? D3D11_TEXTURE_ADDRESS_CLAMP : D3D11_TEXTURE_ADDRESS_WRAP;
        g_s_tex[0][a] = sampler(D3D11_FILTER_MIN_MAG_MIP_POINT, m, 1);
        g_s_tex[1][a] = sampler(D3D11_FILTER_MIN_MAG_MIP_LINEAR, m, 1);
        g_s_tex[2][a] = sampler(D3D11_FILTER_ANISOTROPIC, m, 16);
    }
    D3D11_RASTERIZER_DESC rd = { D3D11_FILL_SOLID, D3D11_CULL_NONE, FALSE, 0, 0, 0, TRUE, FALSE, TRUE, FALSE };
    ID3D11Device_CreateRasterizerState(g_dev, &rd, &g_rs);
    D3D11_BLEND_DESC bd = { 0 };
    bd.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    ID3D11Device_CreateBlendState(g_dev, &bd, &g_bs_opaque);
    g_ok = 1;
    gpu_resize();
    fprintf(stderr, "[gpu] Direct3D 11: %dx%d window\n", g_bb_w, g_bb_h);
    if (g_gpu.fullscreen) gpu_set_fullscreen(1);
    return 1;
}

/* ---- the picture's rectangle and the targets that follow it ------------------ */
float gpu_aspect_gain(void) {
    if (!g_gpu.widescreen || !g_bb_h) return 1.0f;
    float a = (float)g_bb_w / g_bb_h / (4.0f / 3.0f);
    return a > 1.0f ? a : 1.0f;
}

static void make_3d(void) {
    int w = g_pic3d.right - g_pic3d.left, h = g_pic3d.bottom - g_pic3d.top;
    int ms = g_gpu.msaa < 1 ? 1 : g_gpu.msaa;
    if (w == g_3d_w && h == g_3d_h && ms == g_3d_msaa && g_3d) return;
    if (g_3d_rtv) ID3D11RenderTargetView_Release(g_3d_rtv), g_3d_rtv = NULL;
    if (g_3d_srv) ID3D11ShaderResourceView_Release(g_3d_srv), g_3d_srv = NULL;
    if (g_3d_dsv) ID3D11DepthStencilView_Release(g_3d_dsv), g_3d_dsv = NULL;
    if (g_3d) ID3D11Texture2D_Release(g_3d), g_3d = NULL;
    if (g_3d_resolved) ID3D11Texture2D_Release(g_3d_resolved), g_3d_resolved = NULL;
    if (g_3d_depth) ID3D11Texture2D_Release(g_3d_depth), g_3d_depth = NULL;
    if (w <= 0 || h <= 0) return;
    UINT q = 0;
    while (ms > 1 && (FAILED(ID3D11Device_CheckMultisampleQualityLevels(g_dev, DXGI_FORMAT_B8G8R8A8_UNORM, ms, &q)) || !q))
        ms /= 2;
    D3D11_TEXTURE2D_DESC td = { (UINT)w, (UINT)h, 1, 1, DXGI_FORMAT_B8G8R8A8_UNORM, { (UINT)ms, 0 },
                                D3D11_USAGE_DEFAULT, D3D11_BIND_RENDER_TARGET | (ms == 1 ? D3D11_BIND_SHADER_RESOURCE : 0), 0, 0 };
    ID3D11Device_CreateTexture2D(g_dev, &td, NULL, &g_3d);
    ID3D11Device_CreateRenderTargetView(g_dev, (ID3D11Resource*)g_3d, NULL, &g_3d_rtv);
    if (ms > 1) {
        td.SampleDesc.Count = 1;
        td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        ID3D11Device_CreateTexture2D(g_dev, &td, NULL, &g_3d_resolved);
    }
    ID3D11Device_CreateShaderResourceView(g_dev, (ID3D11Resource*)(ms > 1 ? g_3d_resolved : g_3d), NULL, &g_3d_srv);
    td.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;
    td.SampleDesc.Count = ms;
    td.BindFlags = D3D11_BIND_DEPTH_STENCIL;
    ID3D11Device_CreateTexture2D(g_dev, &td, NULL, &g_3d_depth);
    ID3D11Device_CreateDepthStencilView(g_dev, (ID3D11Resource*)g_3d_depth, NULL, &g_3d_dsv);
    g_3d_w = w, g_3d_h = h, g_3d_msaa = ms;
}

void gpu_resize(void) {
    if (!g_ok) return;
    RECT r;
    GetClientRect(g_wnd, &r);
    if (r.right <= 0 || r.bottom <= 0) return;
    if (r.right != g_bb_w || r.bottom != g_bb_h || !g_bb_rtv) {
        if (g_bb_rtv) ID3D11RenderTargetView_Release(g_bb_rtv), g_bb_rtv = NULL;
        ID3D11DeviceContext_OMSetRenderTargets(g_ctx, 0, NULL, NULL);
        IDXGISwapChain_ResizeBuffers(g_sc, 0, r.right, r.bottom, DXGI_FORMAT_UNKNOWN, 0);
        ID3D11Texture2D* bb = NULL;
        IDXGISwapChain_GetBuffer(g_sc, 0, &IID_ID3D11Texture2D, (void**)&bb);
        ID3D11Device_CreateRenderTargetView(g_dev, (ID3D11Resource*)bb, NULL, &g_bb_rtv);
        ID3D11Texture2D_Release(bb);
        g_bb_w = r.right, g_bb_h = r.bottom;
    }
    /* The 4:3 picture, letterboxed; integer mode: whole multiples only. */
    int w = g_bb_w, h = g_bb_w * 3 / 4;
    if (h > g_bb_h) h = g_bb_h, w = g_bb_h * 4 / 3;
    if (g_gpu.mode == GPU_INTEGER && w >= GW) { int k = w / GW; w = GW * k, h = GH * k; }
    g_pic.left = (g_bb_w - w) / 2, g_pic.top = (g_bb_h - h) / 2;
    g_pic.right = g_pic.left + w, g_pic.bottom = g_pic.top + h;
    g_pic3d = g_pic;
    float gain = gpu_aspect_gain();
    if (gain > 1.0f) {
        int w3 = (int)(w * gain + 0.5f);
        if (w3 > g_bb_w) w3 = g_bb_w;
        g_pic3d.left = (g_bb_w - w3) / 2, g_pic3d.right = g_pic3d.left + w3;
    }
    make_3d();
}

void gpu_set_fullscreen(int on) {
    static WINDOWPLACEMENT wp = { sizeof wp };
    static LONG style;
    if (on == g_gpu.fullscreen && style) return;
    g_gpu.fullscreen = on;
    if (on) {
        MONITORINFO mi = { sizeof mi };
        GetWindowPlacement(g_wnd, &wp);
        style = GetWindowLongA(g_wnd, GWL_STYLE);
        GetMonitorInfoA(MonitorFromWindow(g_wnd, MONITOR_DEFAULTTONEAREST), &mi);
        SetWindowLongA(g_wnd, GWL_STYLE, (style & ~WS_OVERLAPPEDWINDOW) | WS_POPUP);
        SetWindowPos(g_wnd, HWND_TOP, mi.rcMonitor.left, mi.rcMonitor.top, mi.rcMonitor.right - mi.rcMonitor.left,
                     mi.rcMonitor.bottom - mi.rcMonitor.top, SWP_FRAMECHANGED | SWP_SHOWWINDOW);
    } else if (style) {
        SetWindowLongA(g_wnd, GWL_STYLE, style);
        SetWindowPlacement(g_wnd, &wp);
        SetWindowPos(g_wnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }
    gpu_resize();
}

int gpu_to_game(POINT* p) {
    int w = g_pic.right - g_pic.left, h = g_pic.bottom - g_pic.top;
    if (!g_ok || w <= 0) return 1;   /* no presenter: the client area is the game's */
    int in = p->x >= g_pic.left && p->x < g_pic.right && p->y >= g_pic.top && p->y < g_pic.bottom;
    p->x = (p->x - g_pic.left) * GW / w;
    p->y = (p->y - g_pic.top) * GH / h;
    if (p->x < 0) p->x = 0; if (p->x >= GW) p->x = GW - 1;
    if (p->y < 0) p->y = 0; if (p->y >= GH) p->y = GH - 1;
    return in;
}

void gpu_from_game(POINT* p) {
    int w = g_pic.right - g_pic.left, h = g_pic.bottom - g_pic.top;
    if (!g_ok || w <= 0) return;
    p->x = g_pic.left + p->x * w / GW;
    p->y = g_pic.top + p->y * h / GH;
}

/* ---- the 2D picture ----------------------------------------------------------- */
static void upload(layer_t* L, const uint8_t* bits, int w, int h, int pitch, int bpp, const PALETTEENTRY* pal, int key) {
    if (w != L->w || h != L->h || !L->tex) {
        if (L->srv) ID3D11ShaderResourceView_Release(L->srv);
        if (L->tex) ID3D11Texture2D_Release(L->tex);
        D3D11_TEXTURE2D_DESC td = { (UINT)w, (UINT)h, 1, 1, DXGI_FORMAT_B8G8R8A8_UNORM, { 1, 0 },
                                    D3D11_USAGE_DEFAULT, D3D11_BIND_SHADER_RESOURCE, 0, 0 };
        ID3D11Device_CreateTexture2D(g_dev, &td, NULL, &L->tex);
        ID3D11Device_CreateShaderResourceView(g_dev, (ID3D11Resource*)L->tex, NULL, &L->srv);
        free(L->rgba);
        L->rgba = (uint32_t*)malloc((size_t)w * h * 4);
        L->w = w, L->h = h;
    }
    static uint32_t lut16[65536];
    static int lut_ready;
    if (!lut_ready) {
        for (int c = 0; c < 65536; c++) {
            uint32_t r = (c >> 11) & 31, g = (c >> 5) & 63, b = c & 31;
            lut16[c] = 0xFF000000u | ((r * 527 + 23) >> 6) << 16 | ((g * 259 + 33) >> 6) << 8 | ((b * 527 + 23) >> 6);
        }
        lut_ready = 1;
    }
    uint32_t lut8[256];
    if (bpp == 8)
        for (int i = 0; i < 256; i++)
            lut8[i] = pal ? 0xFF000000u | pal[i].peRed << 16 | pal[i].peGreen << 8 | pal[i].peBlue
                          : 0xFF000000u | i * 0x010101u;
    for (int y = 0; y < h; y++) {
        uint32_t* d = L->rgba + (size_t)y * w;
        if (bpp == 8) {
            const uint8_t* s = bits + (size_t)y * pitch;
            for (int x = 0; x < w; x++) d[x] = lut8[s[x]];
        } else {
            const uint16_t* s = (const uint16_t*)(bits + (size_t)y * pitch);
            for (int x = 0; x < w; x++) d[x] = (int)s[x] == key ? 0 : lut16[s[x]];
        }
    }
    ID3D11DeviceContext_UpdateSubresource(g_ctx, (ID3D11Resource*)L->tex, 0, NULL, L->rgba, w * 4, 0);
}

void gpu_frame_2d(const uint8_t* bits, int w, int h, int pitch, int bpp, const PALETTEENTRY* pal, int key) {
    if (!g_ok) return;
    upload(&g_l2d, bits, w, h, pitch, bpp, pal, key);
    g_2d_keyed = key >= 0 && bpp == 16;
}

static void quad(ID3D11ShaderResourceView* srv, const RECT* r, int sw, int sh, int keyed, int layer3d,
                 ID3D11RenderTargetView* rt);

void gpu_background(const uint8_t* bits, int w, int h, int pitch, int bpp, const PALETTEENTRY* pal) {
    if (!g_ok || !g_3d) return;
    upload(&g_lbg, bits, w, h, pitch, bpp, pal, -1);
    /* the 4:3 picture inside the (maybe wider) 3D target */
    RECT r = { g_pic.left - g_pic3d.left, 0, g_pic.right - g_pic3d.left, g_3d_h };
    quad(g_lbg.srv, &r, w, h, 0, 0, g_3d_rtv);   /* the depth is the game's to clear */
}

/* ---- 3D --------------------------------------------------------------------------- */
int gpu_scene_count(void) { return g_3d_draws; }
static volatile LONG g_since3d = 1000;   /* presents since the last one with 3D */
int gpu_in_flight(void) { return g_since3d < 30; }

static void set_3d_target(void) {
    D3D11_VIEWPORT vp = { 0, 0, (float)g_3d_w, (float)g_3d_h, 0, 1 };
    ID3D11DeviceContext_RSSetViewports(g_ctx, 1, &vp);
    ID3D11DeviceContext_OMSetRenderTargets(g_ctx, 1, &g_3d_rtv, g_3d_dsv);
}

void gpu_clear(int x0, int y0, int x1, int y1, int target, uint32_t color, int zbuffer, float z) {
    if (!g_ok || !g_3d) return;
    /* the game clears its whole view: a partial clear is rare, so the target goes whole */
    (void)x0; (void)y0; (void)x1; (void)y1;
    if (target) {
        float c[4] = { ((color >> 16) & 255) / 255.0f, ((color >> 8) & 255) / 255.0f, (color & 255) / 255.0f, 1 };
        ID3D11DeviceContext_ClearRenderTargetView(g_ctx, g_3d_rtv, c);
    }
    if (zbuffer) ID3D11DeviceContext_ClearDepthStencilView(g_ctx, g_3d_dsv, D3D11_CLEAR_DEPTH, z, 0);
}

/* state objects, made once per combination */
static ID3D11BlendState* blend_for(const gpu_state* s) {
    static ID3D11BlendState* cache[2][16][16];
    int on = s->blend ? 1 : 0, a = s->src & 15, b = s->dst & 15;
    if (!on) a = b = 0;
    ID3D11BlendState** slot = &cache[on][a][b];
    if (!*slot) {
        D3D11_BLEND_DESC bd = { 0 };
        D3D11_RENDER_TARGET_BLEND_DESC* r = &bd.RenderTarget[0];
        r->BlendEnable = on;
        r->SrcBlend = a ? (D3D11_BLEND)a : D3D11_BLEND_ONE;
        r->DestBlend = b ? (D3D11_BLEND)b : D3D11_BLEND_ZERO;
        r->BlendOp = r->BlendOpAlpha = D3D11_BLEND_OP_ADD;
        r->SrcBlendAlpha = D3D11_BLEND_ONE, r->DestBlendAlpha = D3D11_BLEND_ZERO;
        r->RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
        ID3D11Device_CreateBlendState(g_dev, &bd, slot);
    }
    return *slot;
}
static ID3D11DepthStencilState* depth_for(const gpu_state* s) {
    static ID3D11DepthStencilState* cache[2][2][9];
    int en = s->zenable ? 1 : 0, wr = s->zwrite ? 1 : 0, fn = s->zfunc >= 1 && s->zfunc <= 8 ? s->zfunc : 4;
    ID3D11DepthStencilState** slot = &cache[en][wr][fn];
    if (!*slot) {
        D3D11_DEPTH_STENCIL_DESC d = { 0 };
        d.DepthEnable = en || wr;
        d.DepthWriteMask = wr ? D3D11_DEPTH_WRITE_MASK_ALL : D3D11_DEPTH_WRITE_MASK_ZERO;
        d.DepthFunc = en ? (D3D11_COMPARISON_FUNC)fn : D3D11_COMPARISON_ALWAYS;
        ID3D11Device_CreateDepthStencilState(g_dev, &d, slot);
    }
    return *slot;
}

typedef struct { ID3D11Texture2D* t; ID3D11ShaderResourceView* srv; const void* key; uint32_t version; } tex_t;
static tex_t g_tex[4096];

void gpu_draw(const gpu_vertex* v, int nv, const uint16_t* idx, int ni, const gpu_state* st) {
    if (!g_ok || !g_3d || nv <= 0 || ni <= 0 || nv > MAXV || ni > MAXI) return;
    gpu_vertex* vb = (gpu_vertex*)map(g_vb);
    if (!vb) return;
    memcpy(vb, v, nv * sizeof *v);
    unmap(g_vb);
    uint16_t* ib = (uint16_t*)map(g_ib);
    if (!ib) return;
    memcpy(ib, idx, ni * 2);
    unmap(g_ib);
    struct { float fog[4]; float xscale; int texon, mapblend, spec, fog_on, atest; float aref; int pad; } cb;
    cb.fog[0] = ((st->fogcolor >> 16) & 255) / 255.0f, cb.fog[1] = ((st->fogcolor >> 8) & 255) / 255.0f;
    cb.fog[2] = (st->fogcolor & 255) / 255.0f, cb.fog[3] = 1;
    cb.xscale = 1.0f / gpu_aspect_gain();
    cb.texon = st->tex > 0 && g_tex[st->tex].srv;
    cb.mapblend = st->mapblend ? st->mapblend : 2;
    cb.spec = st->specular, cb.fog_on = st->fog;
    cb.atest = st->alphatest ? 2 : (st->colorkey ? 1 : 0);
    cb.aref = st->alpharef / 255.0f, cb.pad = 0;
    void* m = map(g_cb_s);
    if (!m) return;
    memcpy(m, &cb, sizeof cb);
    unmap(g_cb_s);

    set_3d_target();
    UINT stride = sizeof(gpu_vertex), off = 0;
    ID3D11DeviceContext_IASetVertexBuffers(g_ctx, 0, 1, &g_vb, &stride, &off);
    ID3D11DeviceContext_IASetIndexBuffer(g_ctx, g_ib, DXGI_FORMAT_R16_UINT, 0);
    ID3D11DeviceContext_IASetInputLayout(g_ctx, g_layout);
    ID3D11DeviceContext_IASetPrimitiveTopology(g_ctx, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ID3D11DeviceContext_VSSetShader(g_ctx, g_vs_tl, NULL, 0);
    ID3D11DeviceContext_PSSetShader(g_ctx, g_ps_tl, NULL, 0);
    ID3D11DeviceContext_PSSetConstantBuffers(g_ctx, 1, 1, &g_cb_s);
    ID3D11DeviceContext_VSSetConstantBuffers(g_ctx, 1, 1, &g_cb_s);
    if (cb.texon) {
        int f = g_gpu.filter < 0 ? 0 : g_gpu.filter > 2 ? 2 : g_gpu.filter;
        ID3D11DeviceContext_PSSetShaderResources(g_ctx, 1, 1, &g_tex[st->tex].srv);
        ID3D11DeviceContext_PSSetSamplers(g_ctx, 2, 1, &g_s_tex[f][st->wrap == 3]);
    }
    ID3D11DeviceContext_RSSetState(g_ctx, g_rs);
    ID3D11DeviceContext_OMSetBlendState(g_ctx, blend_for(st), NULL, 0xFFFFFFFF);
    ID3D11DeviceContext_OMSetDepthStencilState(g_ctx, depth_for(st), 0);
    ID3D11DeviceContext_DrawIndexed(g_ctx, ni, 0, 0);
    g_3d_draws++;
}

/* ---- textures ------------------------------------------------------------------- */
static IWICImagingFactory* wic(void) {
    static IWICImagingFactory* f;
    if (!f) {
        CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, &IID_IWICImagingFactory, (void**)&f);
    }
    return f;
}

/* A PNG as BGRA, or NULL. */
static uint32_t* png_load(const char* path, int* w, int* h) {
    IWICImagingFactory* f = wic();
    if (!f || GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return NULL;
    WCHAR wp[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH);
    IWICBitmapDecoder* d = NULL;
    IWICBitmapFrameDecode* fr = NULL;
    IWICFormatConverter* cv = NULL;
    uint32_t* px = NULL;
    UINT W, H;
    if (SUCCEEDED(IWICImagingFactory_CreateDecoderFromFilename(f, wp, NULL, GENERIC_READ, WICDecodeMetadataCacheOnDemand, &d))
        && SUCCEEDED(IWICBitmapDecoder_GetFrame(d, 0, &fr))
        && SUCCEEDED(IWICImagingFactory_CreateFormatConverter(f, &cv))
        && SUCCEEDED(IWICFormatConverter_Initialize(cv, (IWICBitmapSource*)fr, &GUID_WICPixelFormat32bppBGRA,
                                                    WICBitmapDitherTypeNone, NULL, 0, WICBitmapPaletteTypeCustom))
        && SUCCEEDED(IWICBitmapFrameDecode_GetSize(fr, &W, &H))
        && (px = (uint32_t*)malloc((size_t)W * H * 4)) != NULL
        && SUCCEEDED(IWICFormatConverter_CopyPixels(cv, NULL, W * 4, W * H * 4, (BYTE*)px))) {
        *w = W, *h = H;
    } else {
        free(px), px = NULL;
    }
    if (cv) IWICFormatConverter_Release(cv);
    if (fr) IWICBitmapFrameDecode_Release(fr);
    if (d) IWICBitmapDecoder_Release(d);
    return px;
}

static void png_save(const char* path, const uint32_t* px, int w, int h) {
    IWICImagingFactory* f = wic();
    if (!f) return;
    WCHAR wp[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH);
    IWICStream* s = NULL;
    IWICBitmapEncoder* e = NULL;
    IWICBitmapFrameEncode* fr = NULL;
    WICPixelFormatGUID fmt = GUID_WICPixelFormat32bppBGRA;
    if (SUCCEEDED(IWICImagingFactory_CreateStream(f, &s))
        && SUCCEEDED(IWICStream_InitializeFromFilename(s, wp, GENERIC_WRITE))
        && SUCCEEDED(IWICImagingFactory_CreateEncoder(f, &GUID_ContainerFormatPng, NULL, &e))
        && SUCCEEDED(IWICBitmapEncoder_Initialize(e, (IStream*)s, WICBitmapEncoderNoCache))
        && SUCCEEDED(IWICBitmapEncoder_CreateNewFrame(e, &fr, NULL))
        && SUCCEEDED(IWICBitmapFrameEncode_Initialize(fr, NULL))
        && SUCCEEDED(IWICBitmapFrameEncode_SetSize(fr, w, h))
        && SUCCEEDED(IWICBitmapFrameEncode_SetPixelFormat(fr, &fmt))
        && SUCCEEDED(IWICBitmapFrameEncode_WritePixels(fr, h, w * 4, w * h * 4, (BYTE*)px))) {
        IWICBitmapFrameEncode_Commit(fr);
        IWICBitmapEncoder_Commit(e);
    }
    if (fr) IWICBitmapFrameEncode_Release(fr);
    if (e) IWICBitmapEncoder_Release(e);
    if (s) IWICStream_Release(s);
}

static uint32_t chan(uint32_t v, uint32_t mask) {
    if (!mask) return 255;
    int sh = 0;
    while (!(mask >> sh & 1)) sh++;
    uint32_t max = mask >> sh;
    return ((v & mask) >> sh) * 255 / max;
}

/* FNV-1a of the original pixels as converted: the same texture hashes the same
 * in every mission and on every machine. */
static uint64_t hash(const uint32_t* px, int n, int w, int h) {
    uint64_t x = 1469598103934665603ull ^ ((uint64_t)w << 32 | (uint32_t)h);
    const uint8_t* b = (const uint8_t*)px;
    for (int i = 0; i < n * 4; i++) x = (x ^ b[i]) * 1099511628211ull;
    return x;
}

int gpu_texture(const void* key, uint32_t version, const uint8_t* bits, int w, int h, int pitch, const gpu_fmt* f) {
    if (!g_ok || !key || w <= 0 || h <= 0) return 0;
    int slot = 0, free_slot = 0;
    for (int i = 1; i < 4096; i++) {
        if (g_tex[i].key == key) { slot = i; break; }
        if (!g_tex[i].key && !free_slot) free_slot = i;
    }
    if (slot && g_tex[slot].version == version && g_tex[slot].srv) return slot;
    if (!slot) slot = free_slot;
    if (!slot) return 0;
    tex_t* t = &g_tex[slot];
    if (t->srv) ID3D11ShaderResourceView_Release(t->srv), t->srv = NULL;
    if (t->t) ID3D11Texture2D_Release(t->t), t->t = NULL;
    t->key = key, t->version = version;

    uint32_t* px = (uint32_t*)malloc((size_t)w * h * 4);
    for (int y = 0; y < h; y++) {
        const uint8_t* s = bits + (size_t)y * pitch;
        for (int x = 0; x < w; x++) {
            uint32_t v, r, g, b, a;
            if (f->bpp == 8) {
                v = s[x];
                const PALETTEENTRY* e = f->pal ? &f->pal[v] : NULL;
                r = e ? e->peRed : v, g = e ? e->peGreen : v, b = e ? e->peBlue : v, a = 255;
            } else {
                v = f->bpp == 16 ? ((const uint16_t*)s)[x] : ((const uint32_t*)s)[x];
                r = chan(v, f->r), g = chan(v, f->g), b = chan(v, f->b), a = f->a ? chan(v, f->a) : 255;
            }
            if (f->has_ck && v == f->ck) a = 0;
            px[(size_t)y * w + x] = a << 24 | r << 16 | g << 8 | b;
        }
    }
    int tw = w, th = h;
    uint32_t* use = px;
    if (g_gpu.hd_textures || g_gpu.dump_textures) {
        char path[MAX_PATH];
        uint64_t hv = hash(px, w * h, w, h);
        if (g_gpu.dump_textures) {
            CreateDirectoryA("mods", NULL);
            CreateDirectoryA("mods\\dump", NULL);
            _snprintf(path, sizeof path, "mods\\dump\\%016llx.png", (unsigned long long)hv);
            if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) png_save(path, px, w, h);
        }
        if (g_gpu.hd_textures) {
            _snprintf(path, sizeof path, "mods\\textures\\%016llx.png", (unsigned long long)hv);
            int rw, rh;
            uint32_t* hd = png_load(path, &rw, &rh);
            if (hd) { use = hd, tw = rw, th = rh; }
        }
    }
    /* mipmaps: a full chain, so filtered textures stay clean far away */
    D3D11_TEXTURE2D_DESC td = { (UINT)tw, (UINT)th, 0, 1, DXGI_FORMAT_B8G8R8A8_UNORM, { 1, 0 }, D3D11_USAGE_DEFAULT,
                                D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET, 0, D3D11_RESOURCE_MISC_GENERATE_MIPS };
    if (SUCCEEDED(ID3D11Device_CreateTexture2D(g_dev, &td, NULL, &t->t))) {
        ID3D11DeviceContext_UpdateSubresource(g_ctx, (ID3D11Resource*)t->t, 0, NULL, use, tw * 4, 0);
        ID3D11Device_CreateShaderResourceView(g_dev, (ID3D11Resource*)t->t, NULL, &t->srv);
        ID3D11DeviceContext_GenerateMips(g_ctx, t->srv);
    }
    if (use != px) free(use);
    free(px);
    return t->srv ? slot : 0;
}

/* ---- present ------------------------------------------------------------------- */
int gpu_shot_pending(void) { return g_shot_due != 0; }

void gpu_shot(const char* path) {
    for (int i = 0; g_shot_due && i < 200; i++) Sleep(5);   /* one at a time: a burst keeps every frame */
    lstrcpynA(g_shot_path, path, MAX_PATH);
    InterlockedExchange(&g_shot_due, 1);
}

static void write_shot(void) {
    ID3D11Texture2D *bb = NULL, *st = NULL;
    IDXGISwapChain_GetBuffer(g_sc, 0, &IID_ID3D11Texture2D, (void**)&bb);
    if (!bb) return;
    D3D11_TEXTURE2D_DESC td;
    ID3D11Texture2D_GetDesc(bb, &td);
    td.Usage = D3D11_USAGE_STAGING, td.BindFlags = 0, td.CPUAccessFlags = D3D11_CPU_ACCESS_READ, td.MiscFlags = 0;
    if (SUCCEEDED(ID3D11Device_CreateTexture2D(g_dev, &td, NULL, &st))) {
        D3D11_MAPPED_SUBRESOURCE m;
        ID3D11DeviceContext_CopyResource(g_ctx, (ID3D11Resource*)st, (ID3D11Resource*)bb);
        if (SUCCEEDED(ID3D11DeviceContext_Map(g_ctx, (ID3D11Resource*)st, 0, D3D11_MAP_READ, 0, &m))) {
            uint32_t* px = (uint32_t*)malloc((size_t)td.Width * td.Height * 4);
            for (UINT y = 0; y < td.Height; y++) {
                const uint32_t* s = (const uint32_t*)((const uint8_t*)m.pData + (size_t)y * m.RowPitch);
                for (UINT x = 0; x < td.Width; x++) px[(size_t)y * td.Width + x] = s[x] | 0xFF000000u;
            }
            ID3D11DeviceContext_Unmap(g_ctx, (ID3D11Resource*)st, 0);
            png_save(g_shot_path, px, td.Width, td.Height);
            free(px);
            fprintf(stderr, "[shot] %ux%u -> %s\n", td.Width, td.Height, g_shot_path);
        }
        ID3D11Texture2D_Release(st);
    }
    ID3D11Texture2D_Release(bb);
}

static void quad(ID3D11ShaderResourceView* srv, const RECT* r, int sw, int sh, int keyed, int layer3d,
                 ID3D11RenderTargetView* rt) {
    struct { float src[2], dst[2]; int mode, keyed, layer3d, pad; } cb = {
        { (float)sw, (float)sh }, { (float)(r->right - r->left), (float)(r->bottom - r->top) },
        g_gpu.mode, keyed, layer3d, 0 };
    void* m = map(g_cb_p);
    if (!m) return;
    memcpy(m, &cb, sizeof cb);
    unmap(g_cb_p);
    D3D11_VIEWPORT vp = { (float)r->left, (float)r->top, (float)(r->right - r->left), (float)(r->bottom - r->top), 0, 1 };
    ID3D11DeviceContext_RSSetViewports(g_ctx, 1, &vp);
    ID3D11DeviceContext_OMSetRenderTargets(g_ctx, 1, &rt, NULL);
    ID3D11DeviceContext_OMSetBlendState(g_ctx, g_bs_opaque, NULL, 0xFFFFFFFF);
    ID3D11DeviceContext_OMSetDepthStencilState(g_ctx, NULL, 0);
    ID3D11DeviceContext_RSSetState(g_ctx, g_rs);
    ID3D11DeviceContext_IASetInputLayout(g_ctx, NULL);
    ID3D11DeviceContext_IASetPrimitiveTopology(g_ctx, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ID3D11DeviceContext_VSSetShader(g_ctx, g_vs_quad, NULL, 0);
    ID3D11DeviceContext_PSSetShader(g_ctx, g_ps_quad, NULL, 0);
    ID3D11DeviceContext_PSSetConstantBuffers(g_ctx, 0, 1, &g_cb_p);
    ID3D11SamplerState* ss[2] = { g_s_lin, g_s_pt };
    ID3D11DeviceContext_PSSetSamplers(g_ctx, 0, 2, ss);
    ID3D11DeviceContext_PSSetShaderResources(g_ctx, 0, 1, &srv);
    ID3D11DeviceContext_Draw(g_ctx, 3, 0);
    ID3D11ShaderResourceView* none = NULL;
    ID3D11DeviceContext_PSSetShaderResources(g_ctx, 0, 1, &none);
}

void gpu_present(void) {
    if (!g_ok || !g_bb_rtv) return;
    float black[4] = { 0, 0, 0, 1 };
    ID3D11DeviceContext_ClearRenderTargetView(g_ctx, g_bb_rtv, black);
    int with3d = g_3d_draws > 0 && g_3d;
    if (with3d) {
        if (g_3d_msaa > 1)
            ID3D11DeviceContext_ResolveSubresource(g_ctx, (ID3D11Resource*)g_3d_resolved, 0, (ID3D11Resource*)g_3d, 0,
                                                   DXGI_FORMAT_B8G8R8A8_UNORM);
        ID3D11DeviceContext_OMSetRenderTargets(g_ctx, 0, NULL, NULL);
        quad(g_3d_srv, &g_pic3d, g_3d_w, g_3d_h, 0, 1, g_bb_rtv);
    }
    if (g_l2d.tex) quad(g_l2d.srv, &g_pic, g_l2d.w, g_l2d.h, with3d && g_2d_keyed, 0, g_bb_rtv);
    if (g_shot_due) { write_shot(); InterlockedExchange(&g_shot_due, 0); }
    IDXGISwapChain_Present(g_sc, 0, 0);   /* the game paces itself (vblank, timers); a vsync wait per palette fade stalled its loading */
    {   static long frames, draws3d, frames3d;
        frames++, draws3d += g_3d_draws, frames3d += g_3d_draws > 0;
        g_since3d = g_3d_draws > 0 ? 0 : g_since3d + 1;
        if (frames % 600 == 0) {
            int nt = 0;
            for (int i = 1; i < 4096; i++) nt += g_tex[i].srv != NULL;
            fprintf(stderr, "[gpu] %ld frames: %ld with 3D, %ld draws, %d textures\n", frames, frames3d, draws3d, nt);
        }
    }
    g_3d_draws = 0;
}
