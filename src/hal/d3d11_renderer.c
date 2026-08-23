/*
 * D3D11 Rendering Backend for XWA Recompilation
 *
 * Translates the game's Direct3D 5 execute buffer submissions into
 * Direct3D 11 draw calls. Also handles 2D surface blitting for menus/HUD.
 */

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>
#include <stdio.h>
#include <float.h>
#include <string.h>

#include "d3d11_renderer.h"
#include "shaders.h"

/* ============================================================
 * D3D11 State
 * ============================================================ */

static int g_d3d11_initialized = 0;

/* Core objects */
static ID3D11Device*            g_device = NULL;
static ID3D11DeviceContext*     g_context = NULL;
static IDXGISwapChain*          g_swapchain = NULL;
static ID3D11RenderTargetView*  g_rtv = NULL;
static ID3D11Texture2D*         g_depth_tex = NULL;
static ID3D11DepthStencilView*  g_dsv = NULL;

/* Shaders */
static ID3D11VertexShader*      g_vs_tlvertex = NULL;
static ID3D11PixelShader*       g_ps_textured = NULL;
static ID3D11PixelShader*       g_ps_solid = NULL;
static ID3D11InputLayout*       g_input_layout = NULL;

/* Buffers */
#define MAX_VERTICES    65536
#define MAX_INDICES     (65536 * 3)
static ID3D11Buffer*            g_vb = NULL;          /* Dynamic vertex buffer */
static ID3D11Buffer*            g_ib = NULL;          /* Dynamic index buffer */
static ID3D11Buffer*            g_cb_viewport = NULL;  /* Constant buffer */

/* States */
static ID3D11SamplerState*      g_sampler_linear = NULL;
static ID3D11SamplerState*      g_sampler_point = NULL;

/* Blend states */
static ID3D11BlendState*        g_blend_opaque = NULL;
static ID3D11BlendState*        g_blend_alpha = NULL;
static ID3D11BlendState*        g_blend_additive = NULL;

/* Rasterizer states */
static ID3D11RasterizerState*   g_raster_solid = NULL;
static ID3D11RasterizerState*   g_raster_wire = NULL;

/* Depth stencil states */
static ID3D11DepthStencilState* g_dss_enabled = NULL;
static ID3D11DepthStencilState* g_dss_disabled = NULL;
static ID3D11DepthStencilState* g_dss_nowrite = NULL;

/* 2D surface upload texture */
static ID3D11Texture2D*         g_staging_tex = NULL;
static ID3D11ShaderResourceView* g_staging_srv = NULL;

/* Fullscreen quad for 2D surface blit */
static ID3D11Buffer*            g_quad_vb = NULL;
static ID3D11Buffer*            g_quad_ib = NULL;

/* Viewport dimensions */
static uint32_t g_vp_width = 640;
static uint32_t g_vp_height = 480;

/* Current render state */
static uint32_t g_cur_texture_handle = 0;
static int g_cur_z_enable = 1;
static int g_cur_z_write = 1;
static int g_cur_alpha_blend = 0;
static uint32_t g_cur_src_blend = D3DBLEND_ONE;
static uint32_t g_cur_dst_blend = D3DBLEND_ZERO;
static int g_cur_colorkey = 0;
static uint32_t g_cur_texmapblend = D3DTBLEND_MODULATE;

/* g_cur_texmapblend used to be recorded and then ignored -- the pixel shader always did
 * `texel * diffuse`, so when the engine emitted diffuse 0xFF000000 (opaque black) every
 * textured pixel came out black. Push the mode into the shader constant buffer. */
static void push_viewport_cb(void) {
    if (!g_context || !g_cb_viewport) return;
    D3D11_MAPPED_SUBRESOURCE m;
    if (SUCCEEDED(ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_cb_viewport, 0,
                                          D3D11_MAP_WRITE_DISCARD, 0, &m))) {
        float* d = (float*)m.pData;
        d[0] = (float)g_vp_width;
        d[1] = (float)g_vp_height;
        d[2] = (float)g_cur_texmapblend;
        d[3] = 0.0f;
        ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_cb_viewport, 0);
    }
}

/* Frame stats */
static uint32_t g_frame_count = 0;
static uint32_t g_draw_calls = 0;
static uint32_t g_total_triangles = 0;

/* ============================================================
 * Texture Handle Table
 * ============================================================ */

typedef struct {
    uint8_t* pixels;        /* CPU pixel data (owned by game surface) */
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
    ID3D11Texture2D* tex;           /* D3D11 texture (lazily created) */
    ID3D11ShaderResourceView* srv;  /* Shader resource view */
    int dirty;                      /* Needs re-upload */
} texture_entry_t;

static texture_entry_t g_textures[MAX_TEXTURE_HANDLES];

/* ============================================================
 * Helper: Compile shader from source
 * ============================================================ */

static ID3DBlob* compile_shader(const char* source, const char* entry, const char* target) {
    ID3DBlob* blob = NULL;
    ID3DBlob* errors = NULL;
    HRESULT hr = D3DCompile(source, strlen(source), NULL, NULL, NULL,
                            entry, target, D3DCOMPILE_OPTIMIZATION_LEVEL3, 0,
                            &blob, &errors);
    if (FAILED(hr)) {
        if (errors) {
            fprintf(stderr, "[D3D11] Shader compile error (%s): %s\n",
                    entry, (const char*)ID3D10Blob_GetBufferPointer(errors));
            ID3D10Blob_Release(errors);
        }
        return NULL;
    }
    if (errors) ID3D10Blob_Release(errors);
    return blob;
}

/* ============================================================
 * Helper: Create a texture from 16-bit RGB565 pixel data
 * ============================================================ */

static void create_texture_from_pixels(texture_entry_t* tex) {
    if (!tex->pixels || tex->width == 0 || tex->height == 0) return;

    /* Convert RGB565 to BGRA8888 */
    uint32_t w = tex->width;
    uint32_t h = tex->height;
    uint32_t* rgba = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, w * h * 4);
    if (!rgba) return;

    for (uint32_t y = 0; y < h; y++) {
        uint16_t* src = (uint16_t*)(tex->pixels + y * tex->pitch);
        uint32_t* dst = rgba + y * w;
        for (uint32_t x = 0; x < w; x++) {
            uint16_t c = src[x];
            uint32_t r = ((c >> 11) & 0x1F) * 255 / 31;
            uint32_t g = ((c >> 5) & 0x3F) * 255 / 63;
            uint32_t b = (c & 0x1F) * 255 / 31;
            /* Color key: treat pure black (0x0000) as transparent if colorkey enabled */
            uint32_t a = (c == 0 && g_cur_colorkey) ? 0 : 255;
            dst[x] = (a << 24) | (r << 16) | (g << 8) | b;
        }
    }

    D3D11_TEXTURE2D_DESC desc = {0};
    desc.Width = w;
    desc.Height = h;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA init = {0};
    init.pSysMem = rgba;
    init.SysMemPitch = w * 4;

    HRESULT hr;
    if (tex->tex) {
        /* Update existing texture */
        ID3D11DeviceContext_UpdateSubresource(g_context, (ID3D11Resource*)tex->tex, 0, NULL, rgba, w * 4, 0);
    } else {
        hr = ID3D11Device_CreateTexture2D(g_device, &desc, &init, &tex->tex);
        if (FAILED(hr)) {
            HeapFree(GetProcessHeap(), 0, rgba);
            return;
        }

        D3D11_SHADER_RESOURCE_VIEW_DESC srvd = {0};
        srvd.Format = desc.Format;
        srvd.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
        srvd.Texture2D.MipLevels = 1;
        hr = ID3D11Device_CreateShaderResourceView(g_device, (ID3D11Resource*)tex->tex, &srvd, &tex->srv);
        if (FAILED(hr)) {
            ID3D11Texture2D_Release(tex->tex);
            tex->tex = NULL;
            HeapFree(GetProcessHeap(), 0, rgba);
            return;
        }
    }

    tex->dirty = 0;
    HeapFree(GetProcessHeap(), 0, rgba);
}

/* ============================================================
 * Initialization
 * ============================================================ */

/* The game calls SetDisplayMode(640x480) for the menus and then SetDisplayMode(800x600) for
 * flight. D3D11 was initialised on the first call and never resized, so the flight screen
 * projected vertices into an 800x600 space while the render target stayed 640x480 -- the whole
 * scene landed below and to the right of the visible area (measured: draws at y 485..594 with
 * a 480-tall target). Resize the swap chain and depth buffer to follow the mode change. */
int d3d11_resize(uint32_t width, uint32_t height) {
    if (!g_d3d11_initialized || !g_swapchain) return 0;
    if (width == g_vp_width && height == g_vp_height) return 1;
    if (!width || !height) return 0;

    ID3D11DeviceContext_OMSetRenderTargets(g_context, 0, NULL, NULL);
    if (g_rtv)       { ID3D11RenderTargetView_Release(g_rtv);  g_rtv = NULL; }
    if (g_dsv)       { ID3D11DepthStencilView_Release(g_dsv);  g_dsv = NULL; }
    if (g_depth_tex) { ID3D11Texture2D_Release(g_depth_tex);   g_depth_tex = NULL; }

    HRESULT hr = IDXGISwapChain_ResizeBuffers(g_swapchain, 0, width, height,
                                              DXGI_FORMAT_UNKNOWN, 0);
    if (FAILED(hr)) {
        fprintf(stderr, "[D3D11] ResizeBuffers(%ux%u) failed hr=0x%08lX\n", width, height, (unsigned long)hr);
        return 0;
    }

    ID3D11Texture2D* back_buffer = NULL;
    hr = IDXGISwapChain_GetBuffer(g_swapchain, 0, &IID_ID3D11Texture2D, (void**)&back_buffer);
    if (FAILED(hr)) return 0;
    hr = ID3D11Device_CreateRenderTargetView(g_device, (ID3D11Resource*)back_buffer, NULL, &g_rtv);
    ID3D11Texture2D_Release(back_buffer);
    if (FAILED(hr)) return 0;

    D3D11_TEXTURE2D_DESC dtd = {0};
    dtd.Width = width;
    dtd.Height = height;
    dtd.MipLevels = 1;
    dtd.ArraySize = 1;
    dtd.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;
    dtd.SampleDesc.Count = 1;
    dtd.Usage = D3D11_USAGE_DEFAULT;
    dtd.BindFlags = D3D11_BIND_DEPTH_STENCIL;
    if (FAILED(ID3D11Device_CreateTexture2D(g_device, &dtd, NULL, &g_depth_tex))) return 0;
    if (FAILED(ID3D11Device_CreateDepthStencilView(g_device, (ID3D11Resource*)g_depth_tex, NULL, &g_dsv))) return 0;

    g_vp_width = width;
    g_vp_height = height;
    ID3D11DeviceContext_OMSetRenderTargets(g_context, 1, &g_rtv, g_dsv);
    D3D11_VIEWPORT vp = { 0.0f, 0.0f, (float)width, (float)height, 0.0f, 1.0f };
    ID3D11DeviceContext_RSSetViewports(g_context, 1, &vp);
    push_viewport_cb();
    fprintf(stderr, "[D3D11] resized render target to %ux%u\n", width, height);
    fflush(stderr);
    return 1;
}

int d3d11_init(void* hwnd, uint32_t width, uint32_t height) {
    HRESULT hr;

    if (g_d3d11_initialized) return 1;
    if (!hwnd) {
        fprintf(stderr, "[D3D11] ERROR: NULL hwnd\n");
        return 0;
    }

    g_vp_width = width;
    g_vp_height = height;

    fprintf(stderr, "[D3D11] Initializing D3D11 renderer (%ux%u)\n", width, height);

    /* Create device and swap chain */
    DXGI_SWAP_CHAIN_DESC scd = {0};
    scd.BufferCount = 2;
    scd.BufferDesc.Width = width;
    scd.BufferDesc.Height = height;
    scd.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    scd.BufferDesc.RefreshRate.Numerator = 60;
    scd.BufferDesc.RefreshRate.Denominator = 1;
    scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scd.OutputWindow = (HWND)hwnd;
    scd.SampleDesc.Count = 1;
    scd.Windowed = TRUE;
    scd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;

    D3D_FEATURE_LEVEL feature_levels[] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
    };
    D3D_FEATURE_LEVEL feature_level_out;

    UINT flags = 0;
#ifdef _DEBUG
    flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    hr = D3D11CreateDeviceAndSwapChain(
        NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, flags,
        feature_levels, 3, D3D11_SDK_VERSION,
        &scd, &g_swapchain, &g_device, &feature_level_out, &g_context);

    if (FAILED(hr)) {
        /* Fallback: try without FLIP_DISCARD */
        scd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        scd.BufferCount = 1;
        hr = D3D11CreateDeviceAndSwapChain(
            NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, flags,
            feature_levels, 3, D3D11_SDK_VERSION,
            &scd, &g_swapchain, &g_device, &feature_level_out, &g_context);
    }

    if (FAILED(hr)) {
        fprintf(stderr, "[D3D11] ERROR: D3D11CreateDeviceAndSwapChain failed (0x%08X)\n", (unsigned)hr);
        return 0;
    }

    fprintf(stderr, "[D3D11] Device created, feature level 0x%04X\n", (unsigned)feature_level_out);

    /* Create render target view from back buffer */
    ID3D11Texture2D* back_buffer = NULL;
    hr = IDXGISwapChain_GetBuffer(g_swapchain, 0, &IID_ID3D11Texture2D, (void**)&back_buffer);
    if (FAILED(hr)) {
        fprintf(stderr, "[D3D11] ERROR: GetBuffer failed\n");
        return 0;
    }
    hr = ID3D11Device_CreateRenderTargetView(g_device, (ID3D11Resource*)back_buffer, NULL, &g_rtv);
    ID3D11Texture2D_Release(back_buffer);
    if (FAILED(hr)) {
        fprintf(stderr, "[D3D11] ERROR: CreateRenderTargetView failed\n");
        return 0;
    }

    /* Create depth/stencil buffer */
    D3D11_TEXTURE2D_DESC dtd = {0};
    dtd.Width = width;
    dtd.Height = height;
    dtd.MipLevels = 1;
    dtd.ArraySize = 1;
    dtd.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;
    dtd.SampleDesc.Count = 1;
    dtd.Usage = D3D11_USAGE_DEFAULT;
    dtd.BindFlags = D3D11_BIND_DEPTH_STENCIL;

    hr = ID3D11Device_CreateTexture2D(g_device, &dtd, NULL, &g_depth_tex);
    if (FAILED(hr)) {
        fprintf(stderr, "[D3D11] ERROR: CreateTexture2D (depth) failed\n");
        return 0;
    }
    hr = ID3D11Device_CreateDepthStencilView(g_device, (ID3D11Resource*)g_depth_tex, NULL, &g_dsv);
    if (FAILED(hr)) {
        fprintf(stderr, "[D3D11] ERROR: CreateDepthStencilView failed\n");
        return 0;
    }

    /* Compile shaders */
    ID3DBlob* vs_blob = compile_shader(g_shader_source, "vs_tlvertex", "vs_4_0");
    if (!vs_blob) return 0;

    ID3DBlob* ps_tex_blob = compile_shader(g_shader_source, "ps_textured", "ps_4_0");
    if (!ps_tex_blob) { ID3D10Blob_Release(vs_blob); return 0; }

    ID3DBlob* ps_solid_blob = compile_shader(g_shader_source, "ps_solid", "ps_4_0");
    if (!ps_solid_blob) { ID3D10Blob_Release(vs_blob); ID3D10Blob_Release(ps_tex_blob); return 0; }

    hr = ID3D11Device_CreateVertexShader(g_device,
        ID3D10Blob_GetBufferPointer(vs_blob), ID3D10Blob_GetBufferSize(vs_blob),
        NULL, &g_vs_tlvertex);
    if (FAILED(hr)) {
        fprintf(stderr, "[D3D11] ERROR: CreateVertexShader failed\n");
        return 0;
    }

    hr = ID3D11Device_CreatePixelShader(g_device,
        ID3D10Blob_GetBufferPointer(ps_tex_blob), ID3D10Blob_GetBufferSize(ps_tex_blob),
        NULL, &g_ps_textured);
    hr = ID3D11Device_CreatePixelShader(g_device,
        ID3D10Blob_GetBufferPointer(ps_solid_blob), ID3D10Blob_GetBufferSize(ps_solid_blob),
        NULL, &g_ps_solid);

    /* Create input layout matching D3DTLVERTEX */
    D3D11_INPUT_ELEMENT_DESC layout[] = {
        { "POSITION", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0,  0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "COLOR",    0, DXGI_FORMAT_R8G8B8A8_UNORM,     0, 16, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "COLOR",    1, DXGI_FORMAT_R8G8B8A8_UNORM,     0, 20, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        { "TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT,       0, 24, D3D11_INPUT_PER_VERTEX_DATA, 0 },
    };

    hr = ID3D11Device_CreateInputLayout(g_device, layout, 4,
        ID3D10Blob_GetBufferPointer(vs_blob), ID3D10Blob_GetBufferSize(vs_blob),
        &g_input_layout);

    ID3D10Blob_Release(vs_blob);
    ID3D10Blob_Release(ps_tex_blob);
    ID3D10Blob_Release(ps_solid_blob);

    if (FAILED(hr)) {
        fprintf(stderr, "[D3D11] ERROR: CreateInputLayout failed\n");
        return 0;
    }

    /* Create dynamic vertex buffer */
    D3D11_BUFFER_DESC vbd = {0};
    vbd.ByteWidth = MAX_VERTICES * sizeof(D3DTLVERTEX);
    vbd.Usage = D3D11_USAGE_DYNAMIC;
    vbd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    vbd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    hr = ID3D11Device_CreateBuffer(g_device, &vbd, NULL, &g_vb);
    if (FAILED(hr)) return 0;

    /* Create dynamic index buffer */
    D3D11_BUFFER_DESC ibd = {0};
    ibd.ByteWidth = MAX_INDICES * sizeof(uint16_t);
    ibd.Usage = D3D11_USAGE_DYNAMIC;
    ibd.BindFlags = D3D11_BIND_INDEX_BUFFER;
    ibd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    hr = ID3D11Device_CreateBuffer(g_device, &ibd, NULL, &g_ib);
    if (FAILED(hr)) return 0;

    /* Create constant buffer for viewport */
    D3D11_BUFFER_DESC cbd = {0};
    cbd.ByteWidth = 16; /* float4: width, height, pad, pad */
    cbd.Usage = D3D11_USAGE_DYNAMIC;
    cbd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    cbd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    hr = ID3D11Device_CreateBuffer(g_device, &cbd, NULL, &g_cb_viewport);
    if (FAILED(hr)) return 0;

    /* Update viewport constant buffer */
    {
        D3D11_MAPPED_SUBRESOURCE mapped;
        hr = ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_cb_viewport, 0,
                                     D3D11_MAP_WRITE_DISCARD, 0, &mapped);
        if (SUCCEEDED(hr)) {
            float* data = (float*)mapped.pData;
            data[0] = (float)width;
            data[1] = (float)height;
            data[2] = 0.0f;
            data[3] = 0.0f;
            ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_cb_viewport, 0);
        }
    }

    /* Create sampler states */
    D3D11_SAMPLER_DESC sd = {0};
    sd.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
    sd.AddressU = D3D11_TEXTURE_ADDRESS_WRAP;
    sd.AddressV = D3D11_TEXTURE_ADDRESS_WRAP;
    sd.AddressW = D3D11_TEXTURE_ADDRESS_WRAP;
    sd.MaxAnisotropy = 1;
    sd.ComparisonFunc = D3D11_COMPARISON_ALWAYS;
    sd.MaxLOD = D3D11_FLOAT32_MAX;
    ID3D11Device_CreateSamplerState(g_device, &sd, &g_sampler_linear);

    sd.Filter = D3D11_FILTER_MIN_MAG_MIP_POINT;
    ID3D11Device_CreateSamplerState(g_device, &sd, &g_sampler_point);

    /* Create blend states */
    D3D11_BLEND_DESC bd = {0};
    bd.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    ID3D11Device_CreateBlendState(g_device, &bd, &g_blend_opaque);

    bd.RenderTarget[0].BlendEnable = TRUE;
    bd.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
    bd.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
    bd.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
    bd.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
    bd.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ZERO;
    bd.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
    ID3D11Device_CreateBlendState(g_device, &bd, &g_blend_alpha);

    bd.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
    bd.RenderTarget[0].DestBlend = D3D11_BLEND_ONE;
    ID3D11Device_CreateBlendState(g_device, &bd, &g_blend_additive);

    /* Create rasterizer states */
    D3D11_RASTERIZER_DESC rd = {0};
    rd.FillMode = D3D11_FILL_SOLID;
    rd.CullMode = D3D11_CULL_NONE;
    /* The engine hands us already-transformed vertices whose sz runs outside [0,1] (measured
     * down to -1.875). D3D11 hard-clips anything outside 0 <= z <= w, which silently deleted
     * whole primitives -- the space backdrop drew as one triangle of its quad. DirectDraw/D3D5
     * clamped instead, so match that and let the depth test handle ordering. */
    rd.DepthClipEnable = FALSE;
    ID3D11Device_CreateRasterizerState(g_device, &rd, &g_raster_solid);

    rd.FillMode = D3D11_FILL_WIREFRAME;
    ID3D11Device_CreateRasterizerState(g_device, &rd, &g_raster_wire);

    /* Create depth stencil states */
    D3D11_DEPTH_STENCIL_DESC dsd = {0};
    dsd.DepthEnable = TRUE;
    dsd.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
    dsd.DepthFunc = D3D11_COMPARISON_LESS_EQUAL;
    ID3D11Device_CreateDepthStencilState(g_device, &dsd, &g_dss_enabled);

    dsd.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
    ID3D11Device_CreateDepthStencilState(g_device, &dsd, &g_dss_nowrite);

    dsd.DepthEnable = FALSE;
    dsd.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
    ID3D11Device_CreateDepthStencilState(g_device, &dsd, &g_dss_disabled);

    /* Create staging texture for 2D surface upload */
    {
        D3D11_TEXTURE2D_DESC std = {0};
        std.Width = width;
        std.Height = height;
        std.MipLevels = 1;
        std.ArraySize = 1;
        std.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        std.SampleDesc.Count = 1;
        std.Usage = D3D11_USAGE_DEFAULT;
        std.BindFlags = D3D11_BIND_SHADER_RESOURCE;

        hr = ID3D11Device_CreateTexture2D(g_device, &std, NULL, &g_staging_tex);
        if (SUCCEEDED(hr)) {
            D3D11_SHADER_RESOURCE_VIEW_DESC srvd = {0};
            srvd.Format = std.Format;
            srvd.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
            srvd.Texture2D.MipLevels = 1;
            ID3D11Device_CreateShaderResourceView(g_device, (ID3D11Resource*)g_staging_tex, &srvd, &g_staging_srv);
        }
    }

    /* Create fullscreen quad vertex buffer for 2D blit */
    {
        /* Fullscreen quad: 4 vertices as D3DTLVERTEX */
        D3DTLVERTEX quad[4] = {
            { 0.0f,          0.0f,           0.0f, 1.0f, 0xFFFFFFFF, 0, 0.0f, 0.0f },
            { (float)width,  0.0f,           0.0f, 1.0f, 0xFFFFFFFF, 0, 1.0f, 0.0f },
            { 0.0f,          (float)height,  0.0f, 1.0f, 0xFFFFFFFF, 0, 0.0f, 1.0f },
            { (float)width,  (float)height,  0.0f, 1.0f, 0xFFFFFFFF, 0, 1.0f, 1.0f },
        };

        D3D11_BUFFER_DESC qvbd = {0};
        qvbd.ByteWidth = sizeof(quad);
        qvbd.Usage = D3D11_USAGE_IMMUTABLE;
        qvbd.BindFlags = D3D11_BIND_VERTEX_BUFFER;
        D3D11_SUBRESOURCE_DATA qinit = { quad, 0, 0 };
        ID3D11Device_CreateBuffer(g_device, &qvbd, &qinit, &g_quad_vb);

        uint16_t quad_idx[6] = { 0, 1, 2, 2, 1, 3 };
        D3D11_BUFFER_DESC qibd = {0};
        qibd.ByteWidth = sizeof(quad_idx);
        qibd.Usage = D3D11_USAGE_IMMUTABLE;
        qibd.BindFlags = D3D11_BIND_INDEX_BUFFER;
        D3D11_SUBRESOURCE_DATA qiinit = { quad_idx, 0, 0 };
        ID3D11Device_CreateBuffer(g_device, &qibd, &qiinit, &g_quad_ib);
    }

    /* Set initial pipeline state */
    ID3D11DeviceContext_OMSetRenderTargets(g_context, 1, &g_rtv, g_dsv);

    D3D11_VIEWPORT vp = { 0.0f, 0.0f, (float)width, (float)height, 0.0f, 1.0f };
    ID3D11DeviceContext_RSSetViewports(g_context, 1, &vp);

    ID3D11DeviceContext_IASetInputLayout(g_context, g_input_layout);
    ID3D11DeviceContext_IASetPrimitiveTopology(g_context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ID3D11DeviceContext_VSSetShader(g_context, g_vs_tlvertex, NULL, 0);
    ID3D11DeviceContext_VSSetConstantBuffers(g_context, 0, 1, &g_cb_viewport);
    ID3D11DeviceContext_PSSetConstantBuffers(g_context, 0, 1, &g_cb_viewport);
    ID3D11DeviceContext_PSSetSamplers(g_context, 0, 1, &g_sampler_linear);
    ID3D11DeviceContext_RSSetState(g_context, g_raster_solid);
    ID3D11DeviceContext_OMSetDepthStencilState(g_context, g_dss_enabled, 0);

    float blend_factor[4] = { 0, 0, 0, 0 };
    ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_opaque, blend_factor, 0xFFFFFFFF);

    memset(g_textures, 0, sizeof(g_textures));

    g_d3d11_initialized = 1;
    /* Creating the D3D11 device re-enables FP exceptions in this process: the mask applied
     * before the guest entry (main.c) is undone by the time flight starts, and flight then
     * dies with STATUS_FLOAT_INVALID_OPERATION (0xC0000090) at FLIGHT INIT. The original
     * runs with x87 CW 0x037F -- everything masked. Re-apply it here. */
    if (!getenv("XWA_FPTRAP")) { unsigned _cw = 0; _controlfp_s(&_cw, _MCW_EM, _MCW_EM);
        fprintf(stderr, "[FP] re-masked after D3D11 device creation (cw=0x%X)\n", _cw); }
    fprintf(stderr, "[D3D11] Renderer initialized successfully\n");
    return 1;
}

/* ============================================================
 * Shutdown
 * ============================================================ */

void d3d11_shutdown(void) {
    if (!g_d3d11_initialized) return;

    /* Release textures */
    for (int i = 0; i < MAX_TEXTURE_HANDLES; i++) {
        if (g_textures[i].srv) ID3D11ShaderResourceView_Release(g_textures[i].srv);
        if (g_textures[i].tex) ID3D11Texture2D_Release(g_textures[i].tex);
    }

    if (g_quad_ib)        ID3D11Buffer_Release(g_quad_ib);
    if (g_quad_vb)        ID3D11Buffer_Release(g_quad_vb);
    if (g_staging_srv)    ID3D11ShaderResourceView_Release(g_staging_srv);
    if (g_staging_tex)    ID3D11Texture2D_Release(g_staging_tex);
    if (g_dss_disabled)   ID3D11DepthStencilState_Release(g_dss_disabled);
    if (g_dss_nowrite)    ID3D11DepthStencilState_Release(g_dss_nowrite);
    if (g_dss_enabled)    ID3D11DepthStencilState_Release(g_dss_enabled);
    if (g_raster_wire)    ID3D11RasterizerState_Release(g_raster_wire);
    if (g_raster_solid)   ID3D11RasterizerState_Release(g_raster_solid);
    if (g_blend_additive) ID3D11BlendState_Release(g_blend_additive);
    if (g_blend_alpha)    ID3D11BlendState_Release(g_blend_alpha);
    if (g_blend_opaque)   ID3D11BlendState_Release(g_blend_opaque);
    if (g_sampler_point)  ID3D11SamplerState_Release(g_sampler_point);
    if (g_sampler_linear) ID3D11SamplerState_Release(g_sampler_linear);
    if (g_cb_viewport)    ID3D11Buffer_Release(g_cb_viewport);
    if (g_ib)             ID3D11Buffer_Release(g_ib);
    if (g_vb)             ID3D11Buffer_Release(g_vb);
    if (g_input_layout)   ID3D11InputLayout_Release(g_input_layout);
    if (g_ps_solid)       ID3D11PixelShader_Release(g_ps_solid);
    if (g_ps_textured)    ID3D11PixelShader_Release(g_ps_textured);
    if (g_vs_tlvertex)    ID3D11VertexShader_Release(g_vs_tlvertex);
    if (g_dsv)            ID3D11DepthStencilView_Release(g_dsv);
    if (g_depth_tex)      ID3D11Texture2D_Release(g_depth_tex);
    if (g_rtv)            ID3D11RenderTargetView_Release(g_rtv);
    if (g_context)        ID3D11DeviceContext_Release(g_context);
    if (g_swapchain)      IDXGISwapChain_Release(g_swapchain);
    if (g_device)         ID3D11Device_Release(g_device);

    g_d3d11_initialized = 0;
    fprintf(stderr, "[D3D11] Renderer shut down\n");
}

/* ============================================================
 * Frame Management
 * ============================================================ */

void d3d11_begin_scene(void) {
    if (!g_d3d11_initialized) return;

    float clear_color[4] = { 0.0f, 0.0f, 0.2f, 1.0f }; /* Dark blue */
    ID3D11DeviceContext_ClearRenderTargetView(g_context, g_rtv, clear_color);
    ID3D11DeviceContext_ClearDepthStencilView(g_context, g_dsv,
        D3D11_CLEAR_DEPTH | D3D11_CLEAR_STENCIL, 1.0f, 0);

    /* Reset render state */
    ID3D11DeviceContext_OMSetRenderTargets(g_context, 1, &g_rtv, g_dsv);

    D3D11_VIEWPORT vp = { 0.0f, 0.0f, (float)g_vp_width, (float)g_vp_height, 0.0f, 1.0f };
    ID3D11DeviceContext_RSSetViewports(g_context, 1, &vp);

    g_draw_calls = 0;
    g_total_triangles = 0;
}

void d3d11_end_scene(void) {
    /* No-op: actual present happens on Flip */
}

static void draw_surface_quad(void) {
    /* Redraw the fullscreen surface quad (last uploaded texture).
     * Needed because DXGI_SWAP_EFFECT_DISCARD invalidates backbuffer after Present. */
    if (!g_staging_srv || !g_quad_vb || !g_quad_ib) return;

    float clear_color[4] = { 0.0f, 0.0f, 0.0f, 1.0f };
    ID3D11DeviceContext_ClearRenderTargetView(g_context, g_rtv, clear_color);
    ID3D11DeviceContext_OMSetRenderTargets(g_context, 1, &g_rtv, NULL);

    D3D11_VIEWPORT vp = { 0.0f, 0.0f, (float)g_vp_width, (float)g_vp_height, 0.0f, 1.0f };
    ID3D11DeviceContext_RSSetViewports(g_context, 1, &vp);

    ID3D11DeviceContext_OMSetDepthStencilState(g_context, g_dss_disabled, 0);
    float bf[4] = { 0, 0, 0, 0 };
    ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_opaque, bf, 0xFFFFFFFF);

    ID3D11DeviceContext_VSSetShader(g_context, g_vs_tlvertex, NULL, 0);
    ID3D11DeviceContext_VSSetConstantBuffers(g_context, 0, 1, &g_cb_viewport);
    ID3D11DeviceContext_PSSetConstantBuffers(g_context, 0, 1, &g_cb_viewport);
    ID3D11DeviceContext_PSSetShader(g_context, g_ps_textured, NULL, 0);
    ID3D11DeviceContext_PSSetShaderResources(g_context, 0, 1, &g_staging_srv);
    ID3D11DeviceContext_PSSetSamplers(g_context, 0, 1, &g_sampler_point);

    UINT stride = sizeof(D3DTLVERTEX);
    UINT off = 0;
    ID3D11DeviceContext_IASetVertexBuffers(g_context, 0, 1, &g_quad_vb, &stride, &off);
    ID3D11DeviceContext_IASetIndexBuffer(g_context, g_quad_ib, DXGI_FORMAT_R16_UINT, 0);
    ID3D11DeviceContext_IASetPrimitiveTopology(g_context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ID3D11DeviceContext_IASetInputLayout(g_context, g_input_layout);
    ID3D11DeviceContext_DrawIndexed(g_context, 6, 0, 0);
}

unsigned long g_execute_calls = 0;
static uint32_t g_3d_since_present = 0;   /* 3D vertices submitted since the last Present */  /* ponytail: count d3d11_execute invocations for diagnosis */

/* XWA_CAPTURE: read the backbuffer back and report/dump it. Proof of what is actually on
 * screen, independent of the DirectDraw-side nz counters. */
static void d3d11_capture_frame(void) {
    static int on = -1, shots = 0;
    if (on < 0) on = getenv("XWA_CAPTURE") ? 1 : 0;
    /* Only capture frames that actually contain 3D geometry -- otherwise the first few
     * (empty) presents consume the budget. */
    if (!on || shots >= 10 || g_3d_since_present < 150) return;   /* frames carrying real geometry */
    ID3D11Texture2D* back = NULL;
    if (FAILED(IDXGISwapChain_GetBuffer(g_swapchain, 0, &IID_ID3D11Texture2D, (void**)&back))) return;
    D3D11_TEXTURE2D_DESC td; ID3D11Texture2D_GetDesc(back, &td);
    D3D11_TEXTURE2D_DESC sd = td;
    sd.Usage = D3D11_USAGE_STAGING; sd.BindFlags = 0;
    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ; sd.MiscFlags = 0;
    ID3D11Texture2D* stage = NULL;
    if (SUCCEEDED(ID3D11Device_CreateTexture2D(g_device, &sd, NULL, &stage))) {
        ID3D11DeviceContext_CopyResource(g_context, (ID3D11Resource*)stage, (ID3D11Resource*)back);
        D3D11_MAPPED_SUBRESOURCE m;
        if (SUCCEEDED(ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)stage, 0, D3D11_MAP_READ, 0, &m))) {
            uint32_t nz = 0, w = td.Width, h = td.Height;
            for (uint32_t y = 0; y < h; y++) {
                uint8_t* row = (uint8_t*)m.pData + (size_t)y * m.RowPitch;
                for (uint32_t x = 0; x < w; x++) {
                    uint8_t* px = row + x * 4;
                    if (px[0] | px[1] | px[2]) nz++;
                }
            }
            shots++;
            fprintf(stderr, "[CAPTURE] backbuffer %ux%u: %u/%u non-black pixels (%.1f%%)\n",
                    w, h, nz, w * h, 100.0 * nz / (w * h));
            if (nz) {
                char path[128]; sprintf(path, "D:\\recomp\\pc\\xwa\\frame_3d_%d.bmp", shots);
                FILE* f = fopen(path, "wb");
                if (f) {
                    uint32_t row32 = w * 3; if (row32 % 4) row32 += 4 - (row32 % 4);
                    uint32_t img = row32 * h; uint8_t hdr[54] = {0};
                    hdr[0]='B'; hdr[1]='M'; *(uint32_t*)(hdr+2)=54+img; *(uint32_t*)(hdr+10)=54;
                    *(uint32_t*)(hdr+14)=40; *(int32_t*)(hdr+18)=(int32_t)w; *(int32_t*)(hdr+22)=(int32_t)h;
                    *(uint16_t*)(hdr+26)=1; *(uint16_t*)(hdr+28)=24; *(uint32_t*)(hdr+34)=img;
                    fwrite(hdr,1,54,f);
                    uint8_t* line = (uint8_t*)calloc(1,row32);
                    for (int y = (int)h - 1; y >= 0; y--) {
                        uint8_t* row = (uint8_t*)m.pData + (size_t)y * m.RowPitch;
                        for (uint32_t x = 0; x < w; x++) {
                            line[x*3+0] = row[x*4+0]; line[x*3+1] = row[x*4+1]; line[x*3+2] = row[x*4+2];
                        }
                        fwrite(line,1,row32,f);
                    }
                    free(line); fclose(f);
                    fprintf(stderr, "[CAPTURE] wrote %s\n", path);
                }
            }
            fflush(stderr);
            ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)stage, 0);
        }
        ID3D11Texture2D_Release(stage);
    }
    ID3D11Texture2D_Release(back);
}


/* Capture the swap-chain back buffer to a 24-bit BMP. The existing frame dump reads the
 * DirectDraw mock's back buffer, which is the SOFTWARE surface -- it stays black even when
 * the D3D11 path is drawing thousands of triangles. This reads what actually reaches the GPU. */
void d3d11_capture_bmp(const char* path) {
    ID3D11Texture2D* back = NULL; ID3D11Texture2D* stage = NULL;
    D3D11_TEXTURE2D_DESC td; D3D11_MAPPED_SUBRESOURCE map;
    if (!g_device || !g_context || !g_swapchain) return;
    if (FAILED(g_swapchain->lpVtbl->GetBuffer(g_swapchain, 0, &IID_ID3D11Texture2D, (void**)&back))) return;
    back->lpVtbl->GetDesc(back, &td);
    td.Usage = D3D11_USAGE_STAGING; td.BindFlags = 0;
    td.CPUAccessFlags = D3D11_CPU_ACCESS_READ; td.MiscFlags = 0;
    if (SUCCEEDED(g_device->lpVtbl->CreateTexture2D(g_device, &td, NULL, &stage))) {
        g_context->lpVtbl->CopyResource(g_context, (ID3D11Resource*)stage, (ID3D11Resource*)back);
        if (SUCCEEDED(g_context->lpVtbl->Map(g_context, (ID3D11Resource*)stage, 0, D3D11_MAP_READ, 0, &map))) {
            uint32_t w = td.Width, h = td.Height;
            uint32_t rowb = ((w * 3u) + 3u) & ~3u;      /* BMP rows are 4-byte aligned */
            uint32_t imgsz = rowb * h;
            FILE* f = fopen(path, "wb");
            if (f) {
                uint8_t hdr[54]; uint32_t off = 54, fsz = 54 + imgsz; uint32_t i;
                memset(hdr, 0, sizeof hdr);
                hdr[0]='B'; hdr[1]='M';
                memcpy(hdr+2,&fsz,4); memcpy(hdr+10,&off,4);
                { uint32_t v=40; memcpy(hdr+14,&v,4); }
                memcpy(hdr+18,&w,4); memcpy(hdr+22,&h,4);
                { uint16_t pl=1, bc=24; memcpy(hdr+26,&pl,2); memcpy(hdr+28,&bc,2); }
                memcpy(hdr+34,&imgsz,4);
                fwrite(hdr,1,54,f);
                { uint8_t* row = (uint8_t*)malloc(rowb);
                  if (row) {
                    for (i = 0; i < h; i++) {          /* BMP is bottom-up */
                        const uint8_t* src = (const uint8_t*)map.pData + (size_t)(h-1-i) * map.RowPitch;
                        uint32_t x; memset(row, 0, rowb);
                        for (x = 0; x < w; x++) {      /* RGBA/BGRA -> BGR */
                            row[x*3+0] = src[x*4+0]; row[x*3+1] = src[x*4+1]; row[x*3+2] = src[x*4+2];
                        }
                        fwrite(row,1,rowb,f);
                    }
                    free(row);
                  } }
                fclose(f);
                fprintf(stderr, "[RTDUMP] wrote %s (%ux%u)\n", path, w, h); fflush(stderr);
            }
            g_context->lpVtbl->Unmap(g_context, (ID3D11Resource*)stage, 0);
        }
        stage->lpVtbl->Release(stage);
    }
    back->lpVtbl->Release(back);
}

/* ============================================================
 * d3d11_draw_native -- submit already-screen-space triangles directly.
 *
 * The lifted model renderer (sub_00442F70) is unreachable in this port: the OPT node records the
 * resource resolver returns do not match the layout the walker's type dispatch expects, and there is
 * no working in-port reference to diff against (the concourse uses a different renderer entirely).
 * The GEOMETRY ITSELF is loaded and valid, so draw it here instead -- the standard recomp fallback of
 * replacing a render path that cannot be lifted.
 * ============================================================ */
/* Vertices are submitted mid-frame by the guest render walk, but the frame is cleared afterwards,
 * so they never survive to the presented image. Buffer them and draw just before Present. */
static D3DTLVERTEX g_native_buf[32768];
static int g_native_n = 0;

/* Native geometry is drawn per texture, so the buffer carries a batch list alongside it. */
#define NATIVE_BATCHES 256
typedef struct { int tex; int start; int count; } native_batch_t;
static native_batch_t g_native_batch[NATIVE_BATCHES];
static int g_native_batch_n = 0;

/* Textures the native path owns, keyed by the OPT texture node address. */
#define NATIVE_TEXTURES 256
static struct { uint32_t key; ID3D11ShaderResourceView* srv; } g_native_tex[NATIVE_TEXTURES];
static int g_native_tex_n = 0;

int d3d11_native_texture(uint32_t key, const uint32_t* rgba, int w, int h) {
    int i;
    for (i = 0; i < g_native_tex_n; i++) if (g_native_tex[i].key == key) return i;
    if (!g_device || g_native_tex_n >= NATIVE_TEXTURES || !rgba || w <= 0 || h <= 0) return -1;
    {
        D3D11_TEXTURE2D_DESC td = {0};
        D3D11_SUBRESOURCE_DATA sd = {0};
        ID3D11Texture2D* tex = NULL;
        ID3D11ShaderResourceView* srv = NULL;
        td.Width = (UINT)w; td.Height = (UINT)h; td.MipLevels = 1; td.ArraySize = 1;
        td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        td.SampleDesc.Count = 1;
        td.Usage = D3D11_USAGE_IMMUTABLE;
        td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        sd.pSysMem = rgba;
        sd.SysMemPitch = (UINT)(w * 4);
        if (FAILED(ID3D11Device_CreateTexture2D(g_device, &td, &sd, &tex))) return -1;
        if (FAILED(ID3D11Device_CreateShaderResourceView(g_device, (ID3D11Resource*)tex, NULL, &srv))) {
            ID3D11Texture2D_Release(tex); return -1;
        }
        ID3D11Texture2D_Release(tex);
        g_native_tex[g_native_tex_n].key = key;
        g_native_tex[g_native_tex_n].srv = srv;
        return g_native_tex_n++;
    }
}

/* Drop anything queued this frame: the scene is rebuilt from scratch on every update, and it can
 * be rebuilt several times between presents. */
void d3d11_native_reset(void) { g_native_n = 0; g_native_batch_n = 0; }

void d3d11_draw_native(const D3DTLVERTEX* verts, int count, int tex) {
    if (!verts || count < 3) return;
    if (g_native_n + count > 32768) count = 32768 - g_native_n;
    if (count <= 0) return;
    memcpy(&g_native_buf[g_native_n], verts, (size_t)count * sizeof(D3DTLVERTEX));
    if (g_native_batch_n > 0 && g_native_batch[g_native_batch_n - 1].tex == tex
        && g_native_batch[g_native_batch_n - 1].start + g_native_batch[g_native_batch_n - 1].count == g_native_n) {
        g_native_batch[g_native_batch_n - 1].count += count;
    } else if (g_native_batch_n < NATIVE_BATCHES) {
        g_native_batch[g_native_batch_n].tex = tex;
        g_native_batch[g_native_batch_n].start = g_native_n;
        g_native_batch[g_native_batch_n].count = count;
        g_native_batch_n++;
    }
    g_native_n += count;
}

/* The mesh recogniser only runs on a few frames, so geometry arrives in bursts. Keep the last
 * complete set and redraw it every frame -- otherwise the ship flashes for one frame and the
 * capture (and the user) sees an empty sky. */
static D3DTLVERTEX g_native_keep[32768];
static int g_native_keep_n = 0;
static native_batch_t g_native_keep_batch[NATIVE_BATCHES];
static int g_native_keep_batch_n = 0;

static void d3d11_flush_native(void) {
    int count = g_native_n, nbatch = g_native_batch_n;
    g_native_n = 0; g_native_batch_n = 0;
    if (count >= 3) {
        memcpy(g_native_keep, g_native_buf, (size_t)count * sizeof(D3DTLVERTEX));
        memcpy(g_native_keep_batch, g_native_batch, (size_t)nbatch * sizeof(native_batch_t));
        g_native_keep_n = count; g_native_keep_batch_n = nbatch;
    } else if (g_native_keep_n >= 3) {
        memcpy(g_native_buf, g_native_keep, (size_t)g_native_keep_n * sizeof(D3DTLVERTEX));
        memcpy(g_native_batch, g_native_keep_batch, (size_t)g_native_keep_batch_n * sizeof(native_batch_t));
        count = g_native_keep_n; nbatch = g_native_keep_batch_n;
    }
    if (!g_d3d11_initialized || count < 3) return;
    if (count > MAX_VERTICES) count = MAX_VERTICES;
    /* Count native geometry as 3D for this frame. g_3d_since_present was only ever bumped by
     * d3d11_execute, the engine's execute-buffer path; when the picture comes from the native
     * renderer instead, every frame looked empty to d3d11_present, which then ran
     * draw_surface_quad() -- and that CLEARS the target and paints the 2D DirectDraw surface
     * over the scene. The ships were drawn and immediately erased, every frame. */
    g_3d_since_present += (uint32_t)count;
    {
        D3D11_MAPPED_SUBRESOURCE mapped;
        if (FAILED(ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_vb, 0,
                                           D3D11_MAP_WRITE_DISCARD, 0, &mapped))) return;
        memcpy(mapped.pData, g_native_buf, (size_t)count * sizeof(D3DTLVERTEX));
        ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_vb, 0);
    }
    {
        /* Bind the same pipeline state d3d11_execute establishes -- without it the draw is a no-op
         * (no shaders / render target bound at present time). */
        UINT stride = sizeof(D3DTLVERTEX), offset = 0;
        D3D11_VIEWPORT vp = { 0.0f, 0.0f, (float)g_vp_width, (float)g_vp_height, 0.0f, 1.0f };
        ID3D11DeviceContext_OMSetRenderTargets(g_context, 1, &g_rtv, g_dsv);
        ID3D11DeviceContext_RSSetViewports(g_context, 1, &vp);
        ID3D11DeviceContext_IASetInputLayout(g_context, g_input_layout);
        ID3D11DeviceContext_VSSetShader(g_context, g_vs_tlvertex, NULL, 0);
        ID3D11DeviceContext_VSSetConstantBuffers(g_context, 0, 1, &g_cb_viewport);
        ID3D11DeviceContext_PSSetShader(g_context, g_ps_solid, NULL, 0);
        ID3D11DeviceContext_PSSetConstantBuffers(g_context, 0, 1, &g_cb_viewport);
        ID3D11DeviceContext_RSSetState(g_context, g_raster_solid);
        /* Solid, depth-sorted: the native path emits real OPT faces as triangles, so it needs a
         * clean depth buffer of its own (the guest's 2D blits leave whatever was there). */
        ID3D11DeviceContext_ClearDepthStencilView(g_context, g_dsv, D3D11_CLEAR_DEPTH, 1.0f, 0);
        ID3D11DeviceContext_OMSetDepthStencilState(g_context, g_dss_enabled, 0);
        ID3D11DeviceContext_IASetVertexBuffers(g_context, 0, 1, &g_vb, &stride, &offset);
        ID3D11DeviceContext_IASetPrimitiveTopology(g_context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        if (nbatch <= 0) {
            ID3D11DeviceContext_Draw(g_context, (UINT)count, 0);
        } else {
            /* MODULATE, so the flat shading still lights the textured hull. */
            D3D11_MAPPED_SUBRESOURCE cb;
            int b;
            if (SUCCEEDED(ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_cb_viewport, 0,
                                                  D3D11_MAP_WRITE_DISCARD, 0, &cb))) {
                float* f = (float*)cb.pData;
                f[0] = (float)g_vp_width; f[1] = (float)g_vp_height; f[2] = 2.0f; f[3] = 0.0f;
                ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_cb_viewport, 0);
            }
            for (b = 0; b < nbatch; b++) {
                int t = g_native_batch[b].tex;
                if (g_native_batch[b].count < 3) continue;
                if (t >= 0 && t < g_native_tex_n && g_native_tex[t].srv) {
                    ID3D11DeviceContext_PSSetShader(g_context, g_ps_textured, NULL, 0);
                    ID3D11DeviceContext_PSSetShaderResources(g_context, 0, 1, &g_native_tex[t].srv);
                    /* POINT sampling: these are 8x8..128x64 textures stretched over whole hull
                     * panels. Linear filtering turns them into smooth gradients that read as shading;
                     * the original renderer's chunky texels are what makes them read as texture. */
                    {   ID3D11SamplerState* smp = getenv("XWA_TEXLINEAR") ? g_sampler_linear : g_sampler_point;
                        if (!smp) smp = g_sampler_linear;
                        if (smp) ID3D11DeviceContext_PSSetSamplers(g_context, 0, 1, &smp); }
                } else {
                    ID3D11DeviceContext_PSSetShader(g_context, g_ps_solid, NULL, 0);
                }
                ID3D11DeviceContext_Draw(g_context, (UINT)g_native_batch[b].count,
                                         (UINT)g_native_batch[b].start);
            }
        }
        g_draw_calls++;
        g_total_triangles += (uint32_t)(count / 3);
    }
}

static void d3d11_draw_native_unused(const D3DTLVERTEX* verts, int count) {
    if (!g_d3d11_initialized || !verts || count < 3) return;
    if (count > MAX_VERTICES) count = MAX_VERTICES;
    {
        D3D11_MAPPED_SUBRESOURCE mapped;
        if (FAILED(ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_vb, 0,
                                           D3D11_MAP_WRITE_DISCARD, 0, &mapped))) return;
        memcpy(mapped.pData, verts, (size_t)count * sizeof(D3DTLVERTEX));
        ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_vb, 0);
    }
    {
        UINT stride = sizeof(D3DTLVERTEX), offset = 0;
        ID3D11DeviceContext_IASetVertexBuffers(g_context, 0, 1, &g_vb, &stride, &offset);
        ID3D11DeviceContext_IASetPrimitiveTopology(g_context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        ID3D11DeviceContext_Draw(g_context, (UINT)(count - (count % 3)), 0);
        g_draw_calls++;
        g_total_triangles += (uint32_t)(count / 3);
    }
}

void d3d11_present(void) {
    if (!g_d3d11_initialized) return;

    d3d11_flush_native();   /* draw buffered native geometry onto the finished frame */

    /* XWA_PERIODIC: the default (concourse) run never exits, so the end-of-run counter summary
     * never prints. Emit the object-type histogram and model-renderer counts periodically so the
     * CONCOURSE can be compared against flight. */
    if (getenv("XWA_PERIODIC")) {
        static unsigned _pp;
        if ((_pp++ % 100u) == 0u) {
            extern unsigned g_objtype[40]; extern unsigned g_bindfn[8];
            extern unsigned g_spawnfn[8]; extern unsigned g_frameblk;
            {   extern int xwa_readable(uint32_t, uint32_t);
                extern ptrdiff_t g_mem_base;
                uint32_t tbl = *(uint32_t*)((uintptr_t)0x7B33C4u + g_mem_base);
                uint32_t cnt = *(uint32_t*)((uintptr_t)0x917E64u + g_mem_base), i, live = 0;
                if (tbl && cnt && cnt < 4096u) for (i = 0; i < cnt; i++) {
                    uint32_t o = tbl + i * 0x27u;
                    if (xwa_readable(o, 0x27) && *(uint16_t*)((uintptr_t)(o + 2) + g_mem_base)) live++;
                }
                fprintf(stderr, "[PERIODIC] frameblk=0x%06X simtick=%u arrsched=%u create=%u | live objects=%u\n",
                        g_frameblk, g_spawnfn[4], g_spawnfn[6], g_spawnfn[7], live);
            }
            fprintf(stderr, "[PERIODIC] 442F70=%u 448000=%u 482000=%u | types:",
                    g_bindfn[0], g_bindfn[3], g_bindfn[4]);
            for (int _i = 0; _i < 40; _i++) if (g_objtype[_i]) fprintf(stderr, " t%d=%u", _i, g_objtype[_i]);
            fprintf(stderr, "\n"); fflush(stderr);
        }
    }

    {   /* Serviced here so the capture sees a composited, presented frame (see XWA_SNAPUI). */
        extern int g_ui_snap_req;
        if (g_ui_snap_req) { g_ui_snap_req = 0; d3d11_capture_bmp("ui_screen.bmp"); }
    }

    /* XWA_RTDUMP=N: after N presents that actually drew something, save the GPU back buffer.
     * Waits for a frame with real draw calls so the dump is not an empty pre-flight frame. */
    if (getenv("XWA_RTDUMP")) {
        static int _done = 0; static unsigned _drawn = 0;
        if (!_done) {
            /* Count only frames that carry the geometry we are actually trying to photograph.
             * "any draw call" fired on an engine 2D frame long before the native renderer had
             * submitted anything, so the dump was the cleared target with the HUD text on it. */
            {   static int want_native = -1;
                if (want_native < 0) want_native = getenv("XWA_NATIVEDRAW") ? 1 : 0;
                if (want_native ? (g_native_keep_n >= 3) : (g_3d_since_present > 0)) _drawn++; }
            unsigned _want = (unsigned)atoi(getenv("XWA_RTDUMP")); if (!_want) _want = 30;
            if (_drawn >= _want) { _done = 1;
                fprintf(stderr, "[RTDUMP] capturing: 3d_verts=%u native_keep=%d draw_calls=%lu\n",
                        g_3d_since_present, g_native_keep_n, (unsigned long)g_draw_calls);
                fflush(stderr);
                d3d11_capture_bmp("rt_flight.bmp"); }
        }
    }

    /* XWA_RENDCOUNT read from the PRESENT path. The other dump site is the flight-source blit,
     * which is capped at 12 prints and fires during loading -- long before the flight render
     * loop -- so it always reported zeros regardless of what the render pipeline did. */
    if (getenv("XWA_RENDCOUNT")) {
        static unsigned _pf; 
        if ((_pf++ % 60) == 0) {
            extern unsigned g_rcount[8]; extern const char* const g_rcount_name[8];
            fprintf(stderr, "[RC@present %u]", _pf);
            for (int _i = 0; _i < 8; _i++) fprintf(stderr, "  %s=%u", g_rcount_name[_i], g_rcount[_i]);
            fprintf(stderr, "\n"); fflush(stderr);
        }
    }

    {   /* the mission's per-frame update, which the force-launch flight loop never calls */
        static int _st = -1; extern void xwa_drive_simtick(void); extern ptrdiff_t g_mem_base;
        volatile uint32_t* _fgt;
        if (_st < 0) _st = getenv("XWA_SIMDRIVE") ? 1 : 0;
        _fgt = (volatile uint32_t*)((uintptr_t)0x7B33C4u + g_mem_base);
        if (_st && *_fgt != 0) xwa_drive_simtick();
    }
    { static int _sb = -1; extern ptrdiff_t g_mem_base; extern void xwa_drive_render(void);
      volatile uint32_t *_fg;
      if (_sb < 0) { char* e = getenv("XWA_DRIVERENDER"); _sb = e ? 1 : 0; }
      _fg = (volatile uint32_t*)((uintptr_t)0x7B33C4u + g_mem_base);  /* flight-group table */
      if (_sb && *_fg != 0) xwa_drive_render(); }
    { static int _ds = -1; extern ptrdiff_t g_mem_base; extern void xwa_drive_spawn(void);
      volatile uint32_t *_fg2;
      if (_ds < 0) { char* e = getenv("XWA_DPSPAWN"); _ds = e ? 1 : 0; }
      _fg2 = (volatile uint32_t*)((uintptr_t)0x7B33C4u + g_mem_base);
      if (_ds && *_fg2 != 0) xwa_drive_spawn(); }

    /* The surface quad CLEARS the render target and blits the 2D DirectDraw surface over it.
     * That is right for the frontend, but in flight the 3D scene is drawn through execute
     * buffers and the DirectDraw surface holds only (currently empty) cockpit/HUD overlay --
     * so painting it here erased the ships every frame. Keep the 3D frame when geometry was
     * submitted; XWA_QUADALWAYS restores the old unconditional behaviour. */
    if (g_3d_since_present == 0 || getenv("XWA_QUADALWAYS")) draw_surface_quad();
    else { static int _k; if (_k < 3) { _k++;
        fprintf(stderr, "[D3D11] keeping 3D frame (%u verts this frame), not overpainting with the 2D surface\n", g_3d_since_present); fflush(stderr); } }

    d3d11_capture_frame();
    g_3d_since_present = 0;
    IDXGISwapChain_Present(g_swapchain, 1, 0);
    g_frame_count++;

    if ((g_frame_count % 300) == 0) {
        fprintf(stderr, "[D3D11] Frame %u: %u draw calls, %u triangles, %lu execute() calls\n",
                g_frame_count, g_draw_calls, g_total_triangles, g_execute_calls);
        /* ponytail: object-model ground truth — how many craft slots are populated */
        {
          extern ptrdiff_t g_mem_base;
          #define _M32(a) (*(volatile uint32_t*)((uintptr_t)(uint32_t)(a)+g_mem_base))
          unsigned valid = 0, s;
          uint32_t t;
          for (s = 0; s < 0x40; s++) { t = _M32(s*0xBCFu + 0x8B94E0u); if (t != 0xFFFFu && t != 0) valid++; }
          fprintf(stderr, "[OBJST] FGcount=%u FGtbl=0x%X objcount=0x%X 8C1CC8=%u validslots=%u | renderEnable(7828D0)=%u renderFn(9109C0)=0x%X viewCnt(8C1CE4)=%u | outQ(76E578)=%u DPsess(77330C)=0x%X msggate(A21449)=0x%X\n",
                  _M32(0x63185Cu), _M32(0x7B33C4u), _M32(0x5BA994u), _M32(0x8C1CC8u), valid,
                  _M32(0x7828D0u), _M32(0x9109C0u), _M32(0x8C1CE4u),
                  _M32(0x76E578u), _M32(0x77330Cu), _M32(0xA21449u));
          { unsigned _k; fprintf(stderr, "[SLOTS]");
            for (_k = 0; _k < 6; _k++) fprintf(stderr, " [%u]=0x%X", _k, _M32(0x8B94E0u + _k*0xBCFu));
            fprintf(stderr, "  8C1CC8=%u\n", _M32(0x8C1CC8u)); }
          { extern volatile unsigned g_w1, g_w2;
            fprintf(stderr, "[STRSET] sub_00462BE0=%u sub_00464A20=%u  ptr(0x68C89C)=0x%X\n", g_w1, g_w2, _M32(0x68C89Cu)); }
          { extern volatile unsigned g_cw[3];
            fprintf(stderr, "[CRAFTW] loader_457C20=%u sub_458DC0=%u builder_41EF60=%u\n", g_cw[0], g_cw[1], g_cw[2]); }
          fprintf(stderr, "[OBJST2] 9F702A(DDrawObj)=0x%X 773358=0x%X 7B1CE8(missState)=0x%X 7B1D3C=%u\n",
                  _M32(0x9F702Au), _M32(0x773358u), _M32(0x7B1CE8u), _M32(0x7B1D3Cu));
          #undef _M32
        }
    }
}

/* ============================================================
 * Apply render state to D3D11 pipeline
 * ============================================================ */

static void apply_blend_state(void) {
    float blend_factor[4] = { 0, 0, 0, 0 };
    if (!g_cur_alpha_blend) {
        ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_opaque, blend_factor, 0xFFFFFFFF);
        return;
    }

    /* Map D3D5 blend modes to our pre-built blend states */
    if (g_cur_src_blend == D3DBLEND_SRCALPHA && g_cur_dst_blend == D3DBLEND_INVSRCALPHA) {
        ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_alpha, blend_factor, 0xFFFFFFFF);
    } else if (g_cur_src_blend == D3DBLEND_SRCALPHA && g_cur_dst_blend == D3DBLEND_ONE) {
        ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_additive, blend_factor, 0xFFFFFFFF);
    } else if (g_cur_src_blend == D3DBLEND_ONE && g_cur_dst_blend == D3DBLEND_ONE) {
        ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_additive, blend_factor, 0xFFFFFFFF);
    } else {
        /* Default to alpha blend */
        ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_alpha, blend_factor, 0xFFFFFFFF);
    }
}

static void apply_depth_state(void) {
    if (!g_cur_z_enable) {
        ID3D11DeviceContext_OMSetDepthStencilState(g_context, g_dss_disabled, 0);
    } else if (!g_cur_z_write) {
        ID3D11DeviceContext_OMSetDepthStencilState(g_context, g_dss_nowrite, 0);
    } else {
        ID3D11DeviceContext_OMSetDepthStencilState(g_context, g_dss_enabled, 0);
    }
}

/* ============================================================
 * Execute Buffer Parsing and Rendering
 * ============================================================ */

void d3d11_execute(uint8_t* buffer_data, uint32_t vertex_offset, uint32_t vertex_count,
                   uint32_t instruction_offset, uint32_t instruction_size) {
    if (vertex_count) g_3d_since_present += vertex_count;
    g_execute_calls++;
    if (g_execute_calls <= 5) { fprintf(stderr, "[EXEC] d3d11_execute call #%lu verts=%u\n", g_execute_calls, vertex_count); fflush(stderr); }
    if (!g_d3d11_initialized) return;
    if (!buffer_data) return;

    /* Upload vertices to dynamic vertex buffer */
    D3DTLVERTEX* src_verts = (D3DTLVERTEX*)(buffer_data + vertex_offset);
    if (vertex_count > MAX_VERTICES) vertex_count = MAX_VERTICES;

    {
        D3D11_MAPPED_SUBRESOURCE mapped;
        HRESULT hr = ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_vb, 0,
                                              D3D11_MAP_WRITE_DISCARD, 0, &mapped);
        if (SUCCEEDED(hr)) {
            memcpy(mapped.pData, src_verts, vertex_count * sizeof(D3DTLVERTEX));
            /* The engine transforms to screen space itself, and with the camera/projection
             * state unbuilt it emits inf/NaN coordinates. Those rasterise as screen-filling
             * garbage that hides whatever valid geometry exists, so collapse any non-finite
             * vertex to a degenerate point -- its triangles then cover no pixels.
             * XWA_NOSANITIZE keeps the raw values. */
            if (!getenv("XWA_NOSANITIZE")) {
                D3DTLVERTEX* dv = (D3DTLVERTEX*)mapped.pData;
                uint32_t bad = 0;
                for (uint32_t i = 0; i < vertex_count; i++) {
                    float* v = (float*)&dv[i];
                    if (!(v[0] > -1e6f && v[0] < 1e6f) || !(v[1] > -1e6f && v[1] < 1e6f) ||
                        !(v[2] > -1e6f && v[2] < 1e6f) || !(v[3] > -1e6f && v[3] < 1e6f)) {
                        v[0] = v[1] = 0.0f; v[2] = 0.0f; v[3] = 1.0f; bad++;
                    }
                }
                if (bad) { static int _b; if (_b < 5) { _b++;
                    fprintf(stderr, "[SANITIZE] %u/%u vertices were inf/NaN (degenerate projection)\n", bad, vertex_count);
                    fflush(stderr); } }
            }
            ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_vb, 0);
        }
    }

    /* XWA_VERTDUMP: the engine hands D3D already-transformed screen-space vertices
     * (D3DTLVERTEX: sx, sy, sz, rhw, colour), so these coordinates ARE what lands on screen.
     * Dumping them says immediately whether the projection is sane (inside 0..640/0..480) or
     * degenerate, without guessing at the camera matrix format. */
    if (getenv("XWA_VERTDUMP") && vertex_count >= 32) {
        static int _vd; if (_vd < 3) { _vd++;
            float minx=1e30f, maxx=-1e30f, miny=1e30f, maxy=-1e30f, minz=1e30f, maxz=-1e30f;
            /* Scan the WHOLE batch, not the first 64 -- a 64-vertex sample of a 3500-vertex
             * frame reported ranges that had nothing to do with what actually rendered. */
            uint32_t scan = vertex_count;
            uint32_t offscreen = 0;
            for (uint32_t i = 0; i < scan; i++) {
                float* v = (float*)&src_verts[i];
                if (v[0]<minx) minx=v[0]; if (v[0]>maxx) maxx=v[0];
                if (v[1]<miny) miny=v[1]; if (v[1]>maxy) maxy=v[1];
                if (v[2]<minz) minz=v[2]; if (v[2]>maxz) maxz=v[2];
                if (v[0] < 0.0f || v[0] > (float)g_vp_width || v[1] < 0.0f || v[1] > (float)g_vp_height) offscreen++;
            }
            fprintf(stderr, "[VERT] n=%u (first %u)  x[%.1f..%.1f] y[%.1f..%.1f] z[%.4f..%.4f]\n",
                    vertex_count, scan, minx, maxx, miny, maxy, minz, maxz);
            for (uint32_t i = 0; i < 4 && i < vertex_count; i++) {
                float* v = (float*)&src_verts[i];
                fprintf(stderr, "[VERT]   v%u  sx=%.1f sy=%.1f sz=%.4f rhw=%.4f colour=0x%08X\n",
                        i, v[0], v[1], v[2], v[3], ((uint32_t*)v)[4]);
            }
            fflush(stderr);
        }
    }

    /* Bind vertex buffer */
    UINT stride = sizeof(D3DTLVERTEX);
    UINT offset = 0;
    ID3D11DeviceContext_IASetVertexBuffers(g_context, 0, 1, &g_vb, &stride, &offset);
    ID3D11DeviceContext_IASetInputLayout(g_context, g_input_layout);
    ID3D11DeviceContext_IASetPrimitiveTopology(g_context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ID3D11DeviceContext_VSSetShader(g_context, g_vs_tlvertex, NULL, 0);
    ID3D11DeviceContext_VSSetConstantBuffers(g_context, 0, 1, &g_cb_viewport);
    ID3D11DeviceContext_PSSetConstantBuffers(g_context, 0, 1, &g_cb_viewport);

    /* Walk instruction stream */
    uint8_t* inst_ptr = buffer_data + instruction_offset;
    uint8_t* inst_end = inst_ptr + instruction_size;

    /* Index accumulation buffer (on stack for small batches) */
    uint16_t* indices = NULL;
    uint32_t index_count = 0;
    uint32_t index_capacity = 0;
    /* Use a heap buffer for indices */
    index_capacity = 16384;
    indices = (uint16_t*)HeapAlloc(GetProcessHeap(), 0, index_capacity * sizeof(uint16_t));
    if (!indices) return;

    while (inst_ptr < inst_end) {
        D3DINSTRUCTION* inst = (D3DINSTRUCTION*)inst_ptr;
        inst_ptr += sizeof(D3DINSTRUCTION);

        if (inst->bOpcode == D3DOP_EXIT) {
            break;
        }

        uint8_t* data = inst_ptr;
        uint32_t data_size = (uint32_t)inst->bSize * (uint32_t)inst->wCount;
        inst_ptr += data_size;

        /* XWA_OPHIST: 3056 execute() calls yield only ~117 draws, so most buffers submit no
         * geometry. Histogram what the guest actually puts in them. */
        if (getenv("XWA_OPHIST")) {
            static unsigned _hist[32], _n;
            if (inst->bOpcode < 32) _hist[inst->bOpcode] += inst->wCount;
            if ((++_n % 20000u) == 0u) {
                static const char* nm[16] = {"?0","POINT","LINE","TRIANGLE","MATRIXLOAD",
                    "MATRIXMULTIPLY","STATETRANSFORM","STATELIGHT","STATERENDER","PROCESSVERTICES",
                    "TEXTURELOAD","EXIT","BRANCHFORWARD","SPAN","SETSTATUS","?15"};
                fprintf(stderr, "[OPHIST]");
                for (int _i = 1; _i < 16; _i++) if (_hist[_i]) fprintf(stderr, " %s=%u", nm[_i], _hist[_i]);
                fprintf(stderr, "\n"); fflush(stderr);
            }
        }

        switch (inst->bOpcode) {
        case D3DOP_TRIANGLE: {
            /* Collect triangle indices. On overflow, flush and KEEP GOING from the triangle we
             * stopped at -- the old code flushed and then re-collected only `wCount - 1` (the
             * last triangle in the instruction), silently dropping every triangle between the
             * overflow point and the end of the batch. */
            for (uint16_t i = 0; i < inst->wCount; i++) {
                if (index_count + 3 > index_capacity) {
                    if (index_count > 0) {
                        D3D11_MAPPED_SUBRESOURCE mapped;
                        HRESULT hr = ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_ib, 0,
                                                              D3D11_MAP_WRITE_DISCARD, 0, &mapped);
                        if (SUCCEEDED(hr)) {
                            memcpy(mapped.pData, indices, index_count * sizeof(uint16_t));
                            ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_ib, 0);
                        }
                        ID3D11DeviceContext_IASetIndexBuffer(g_context, g_ib, DXGI_FORMAT_R16_UINT, 0);
                        ID3D11DeviceContext_DrawIndexed(g_context, index_count, 0, 0);
                        g_draw_calls++;
                        g_total_triangles += index_count / 3;
                        index_count = 0;
                    }
                }
                {
                    D3DTRIANGLE* tri = (D3DTRIANGLE*)(data + i * inst->bSize);
                    indices[index_count++] = tri->v1;
                    indices[index_count++] = tri->v2;
                    indices[index_count++] = tri->v3;
                }
            }
            break;
        }

        case D3DOP_STATERENDER: {
            /* Flush triangles before state change */
            if (index_count > 0) {
                D3D11_MAPPED_SUBRESOURCE mapped;
                HRESULT hr = ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_ib, 0,
                                                      D3D11_MAP_WRITE_DISCARD, 0, &mapped);
                if (SUCCEEDED(hr)) {
                    memcpy(mapped.pData, indices, index_count * sizeof(uint16_t));
                    ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_ib, 0);
                }
                ID3D11DeviceContext_IASetIndexBuffer(g_context, g_ib, DXGI_FORMAT_R16_UINT, 0);
                ID3D11DeviceContext_DrawIndexed(g_context, index_count, 0, 0);
                g_draw_calls++;
                g_total_triangles += index_count / 3;
                index_count = 0;
            }

            /* Process state changes */
            for (uint16_t i = 0; i < inst->wCount; i++) {
                D3DSTATE* st = (D3DSTATE*)(data + i * inst->bSize);
                switch (st->drstRenderStateType) {
                case D3DRENDERSTATE_TEXTUREHANDLE:
                    g_cur_texture_handle = st->dwArg;
                    if (g_cur_texture_handle > 0 && g_cur_texture_handle < MAX_TEXTURE_HANDLES) {
                        texture_entry_t* tex = &g_textures[g_cur_texture_handle];
                        if (tex->pixels) {
                            if (!tex->tex || tex->dirty) {
                                create_texture_from_pixels(tex);
                            }
                            if (tex->srv) {
                                ID3D11DeviceContext_PSSetShaderResources(g_context, 0, 1, &tex->srv);
                                ID3D11DeviceContext_PSSetShader(g_context, g_ps_textured, NULL, 0);
                            } else {
                                ID3D11DeviceContext_PSSetShader(g_context, g_ps_solid, NULL, 0);
                            }
                        } else {
                            ID3D11DeviceContext_PSSetShader(g_context, g_ps_solid, NULL, 0);
                        }
                    } else {
                        ID3D11DeviceContext_PSSetShader(g_context, g_ps_solid, NULL, 0);
                    }
                    break;

                case D3DRENDERSTATE_ZENABLE:
                    g_cur_z_enable = st->dwArg;
                    apply_depth_state();
                    break;

                case D3DRENDERSTATE_ZWRITEENABLE:
                    g_cur_z_write = st->dwArg;
                    apply_depth_state();
                    break;

                case D3DRENDERSTATE_ALPHABLENDENABLE:
                    g_cur_alpha_blend = st->dwArg;
                    apply_blend_state();
                    break;

                case D3DRENDERSTATE_SRCBLEND:
                    g_cur_src_blend = st->dwArg;
                    if (g_cur_alpha_blend) apply_blend_state();
                    break;

                case D3DRENDERSTATE_DESTBLEND:
                    g_cur_dst_blend = st->dwArg;
                    if (g_cur_alpha_blend) apply_blend_state();
                    break;

                case D3DRENDERSTATE_COLORKEYENABLE:
                    g_cur_colorkey = st->dwArg;
                    break;

                case D3DRENDERSTATE_TEXTUREMAPBLEND:
                    g_cur_texmapblend = st->dwArg;
                    push_viewport_cb();
                    { static uint32_t _seen = 0xFFFFFFFFu;
                      if (_seen != st->dwArg && getenv("XWA_TEXBLEND")) { _seen = st->dwArg;
                        fprintf(stderr, "[TEXBLEND] TEXTUREMAPBLEND = %u\n", st->dwArg);
                        fflush(stderr); } }
                    break;

                case D3DRENDERSTATE_FILLMODE:
                    if (st->dwArg == 2) /* D3DFILL_WIREFRAME */
                        ID3D11DeviceContext_RSSetState(g_context, g_raster_wire);
                    else
                        ID3D11DeviceContext_RSSetState(g_context, g_raster_solid);
                    break;

                case D3DRENDERSTATE_TEXTUREADDRESS:
                    /* 1=wrap, 2=mirror, 3=clamp - we only have wrap/point samplers for now */
                    break;

                default:
                    /* Ignore unhandled render states */
                    break;
                }
            }
            break;
        }

        case D3DOP_PROCESSVERTICES:
            /* Usually no-op for pre-transformed vertices */
            break;

        case D3DOP_STATELIGHT:
        case D3DOP_STATETRANSFORM:
        case D3DOP_MATRIXLOAD:
        case D3DOP_MATRIXMULTIPLY:
        case D3DOP_TEXTURELOAD:
        case D3DOP_BRANCHFORWARD:
        case D3DOP_SPAN:
        case D3DOP_SETSTATUS:
            /* Ignore for now */
            break;

        default:
            fprintf(stderr, "[D3D11] Unknown D3DOP: %u\n", inst->bOpcode);
            break;
        }
    }

    /* Flush remaining triangles */
    if (index_count > 0) {
        D3D11_MAPPED_SUBRESOURCE mapped;
        HRESULT hr = ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_ib, 0,
                                              D3D11_MAP_WRITE_DISCARD, 0, &mapped);
        if (SUCCEEDED(hr)) {
            memcpy(mapped.pData, indices, index_count * sizeof(uint16_t));
            ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_ib, 0);
        }
        ID3D11DeviceContext_IASetIndexBuffer(g_context, g_ib, DXGI_FORMAT_R16_UINT, 0);
        /* XWA_DRAWPROBE: screen bounding box + span of each draw. A compact cluster of a few
         * hundred triangles is a ship model; thousands of tiny primitives smeared over the
         * whole frame are the star/particle field. Tells the two apart without guessing. */
        if (getenv("XWA_DRAWPROBE")) {
            static int _dp; if (_dp < 24) { _dp++;
                float lo_x = 1e30f, hi_x = -1e30f, lo_y = 1e30f, hi_y = -1e30f;
                uint32_t degen = 0;
                for (uint32_t i = 0; i + 2 < index_count; i += 3) {
                    float* a = (float*)&src_verts[indices[i]];
                    float* b = (float*)&src_verts[indices[i+1]];
                    float* c = (float*)&src_verts[indices[i+2]];
                    float area = (b[0]-a[0])*(c[1]-a[1]) - (c[0]-a[0])*(b[1]-a[1]);
                    if (area < 0.5f && area > -0.5f) degen++;
                    for (int k = 0; k < 3; k++) {
                        float* v = k == 0 ? a : (k == 1 ? b : c);
                        if (v[0] < lo_x) lo_x = v[0]; if (v[0] > hi_x) hi_x = v[0];
                        if (v[1] < lo_y) lo_y = v[1]; if (v[1] > hi_y) hi_y = v[1];
                    }
                }
                fprintf(stderr, "[DRAW] tris=%u  x[%.0f..%.0f] y[%.0f..%.0f]  span=%.0fx%.0f  degenerate=%u\n",
                        index_count / 3, lo_x, hi_x, lo_y, hi_y, hi_x - lo_x, hi_y - lo_y, degen);
                fflush(stderr);
            }
        }
        ID3D11DeviceContext_DrawIndexed(g_context, index_count, 0, 0);
        g_draw_calls++;
        g_total_triangles += index_count / 3;
    }

    HeapFree(GetProcessHeap(), 0, indices);
}

/* ============================================================
 * 2D Surface Upload
 * ============================================================ */

void d3d11_upload_surface(uint8_t* pixels, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp) {
    if (!g_d3d11_initialized) return;
    if (!pixels || !g_staging_tex) return;

    /* Convert RGB565 to BGRA8888 and upload */
    uint32_t* rgba = (uint32_t*)HeapAlloc(GetProcessHeap(), 0, width * height * 4);
    if (!rgba) return;

    if (bpp == 16) {
        for (uint32_t y = 0; y < height; y++) {
            uint16_t* src = (uint16_t*)(pixels + y * pitch);
            uint32_t* dst = rgba + y * width;
            for (uint32_t x = 0; x < width; x++) {
                uint16_t c = src[x];
                uint32_t r = ((c >> 11) & 0x1F) * 255 / 31;
                uint32_t g = ((c >> 5) & 0x3F) * 255 / 63;
                uint32_t b = (c & 0x1F) * 255 / 31;
                dst[x] = 0xFF000000 | (r << 16) | (g << 8) | b;
            }
        }
    } else if (bpp == 32) {
        for (uint32_t y = 0; y < height; y++) {
            memcpy(rgba + y * width, pixels + y * pitch, width * 4);
        }
    }
    ID3D11DeviceContext_UpdateSubresource(g_context, (ID3D11Resource*)g_staging_tex,
                                          0, NULL, rgba, width * 4, 0);

    HeapFree(GetProcessHeap(), 0, rgba);

    /* The surface quad is now drawn in draw_surface_quad(), called from d3d11_present().
     * This ensures the last uploaded surface is always visible even between Flips. */
}

/* ============================================================
 * Texture Management
 * ============================================================ */

void d3d11_register_texture(uint32_t handle, uint8_t* pixels, uint32_t width, uint32_t height,
                            uint32_t pitch, uint32_t bpp) {
    if (handle == 0 || handle >= MAX_TEXTURE_HANDLES) return;

    texture_entry_t* tex = &g_textures[handle];
    tex->pixels = pixels;
    tex->width = width;
    tex->height = height;
    tex->pitch = pitch;
    tex->bpp = bpp;
    tex->dirty = 1;

    /* Release old D3D11 resources if size changed */
    if (tex->tex) {
        ID3D11ShaderResourceView_Release(tex->srv);
        ID3D11Texture2D_Release(tex->tex);
        tex->tex = NULL;
        tex->srv = NULL;
    }
}

void d3d11_invalidate_texture(uint32_t handle) {
    if (handle == 0 || handle >= MAX_TEXTURE_HANDLES) return;
    g_textures[handle].dirty = 1;
}

/* ============================================================
 * Viewport
 * ============================================================ */

void d3d11_set_viewport(uint32_t x, uint32_t y, uint32_t width, uint32_t height) {
    if (!g_d3d11_initialized) return;

    g_vp_width = width;
    g_vp_height = height;

    D3D11_VIEWPORT vp = { (float)x, (float)y, (float)width, (float)height, 0.0f, 1.0f };
    ID3D11DeviceContext_RSSetViewports(g_context, 1, &vp);

    /* Update constant buffer */
    D3D11_MAPPED_SUBRESOURCE mapped;
    HRESULT hr = ID3D11DeviceContext_Map(g_context, (ID3D11Resource*)g_cb_viewport, 0,
                                          D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    if (SUCCEEDED(hr)) {
        float* data = (float*)mapped.pData;
        data[0] = (float)width;
        data[1] = (float)height;
        data[2] = 0.0f;
        data[3] = 0.0f;
        ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_cb_viewport, 0);
    }
}

int d3d11_is_initialized(void) {
    return g_d3d11_initialized;
}
