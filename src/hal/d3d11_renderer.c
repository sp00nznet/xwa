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
    rd.DepthClipEnable = TRUE;
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
    ID3D11DeviceContext_PSSetSamplers(g_context, 0, 1, &g_sampler_linear);
    ID3D11DeviceContext_RSSetState(g_context, g_raster_solid);
    ID3D11DeviceContext_OMSetDepthStencilState(g_context, g_dss_enabled, 0);

    float blend_factor[4] = { 0, 0, 0, 0 };
    ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_opaque, blend_factor, 0xFFFFFFFF);

    memset(g_textures, 0, sizeof(g_textures));

    g_d3d11_initialized = 1;
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

void d3d11_present(void) {
    if (!g_d3d11_initialized) return;

    IDXGISwapChain_Present(g_swapchain, 1, 0);
    g_frame_count++;

    if ((g_frame_count % 300) == 0) {
        fprintf(stderr, "[D3D11] Frame %u: %u draw calls, %u triangles\n",
                g_frame_count, g_draw_calls, g_total_triangles);
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
            ID3D11DeviceContext_Unmap(g_context, (ID3D11Resource*)g_vb, 0);
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

        switch (inst->bOpcode) {
        case D3DOP_TRIANGLE: {
            /* Collect triangle indices */
            for (uint16_t i = 0; i < inst->wCount; i++) {
                D3DTRIANGLE* tri = (D3DTRIANGLE*)(data + i * inst->bSize);
                if (index_count + 3 > index_capacity) {
                    /* Flush current batch */
                    goto flush_and_continue;
                }
                indices[index_count++] = tri->v1;
                indices[index_count++] = tri->v2;
                indices[index_count++] = tri->v3;
            }
            break;

        flush_and_continue:
            /* Flush accumulated triangles */
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
            /* Re-collect the triangle that caused overflow */
            {
                D3DTRIANGLE* tri = (D3DTRIANGLE*)(data + (inst->wCount - 1) * inst->bSize);
                indices[index_count++] = tri->v1;
                indices[index_count++] = tri->v2;
                indices[index_count++] = tri->v3;
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
    { static int _uc; if (_uc < 10) {
        /* Check if pixel data is non-zero */
        int nonzero = 0;
        for (uint32_t i = 0; i < width * height * (bpp/8) && i < 1000; i++) {
            if (pixels[i] != 0) { nonzero = 1; break; }
        }
        fprintf(stderr, "[D3D11] upload_surface: w=%u h=%u bpp=%u staging=%p nonzero=%d\n",
                width, height, bpp, (void*)g_staging_tex, nonzero); _uc++;
    } }
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

    /* Draw fullscreen quad with the surface texture */
    /* Disable depth, use textured shader */
    ID3D11DeviceContext_OMSetDepthStencilState(g_context, g_dss_disabled, 0);
    float blend_factor[4] = { 0, 0, 0, 0 };
    ID3D11DeviceContext_OMSetBlendState(g_context, g_blend_opaque, blend_factor, 0xFFFFFFFF);

    ID3D11DeviceContext_PSSetShader(g_context, g_ps_textured, NULL, 0);
    ID3D11DeviceContext_PSSetShaderResources(g_context, 0, 1, &g_staging_srv);
    ID3D11DeviceContext_PSSetSamplers(g_context, 0, 1, &g_sampler_point);

    UINT stride = sizeof(D3DTLVERTEX);
    UINT off = 0;
    ID3D11DeviceContext_IASetVertexBuffers(g_context, 0, 1, &g_quad_vb, &stride, &off);
    ID3D11DeviceContext_IASetIndexBuffer(g_context, g_quad_ib, DXGI_FORMAT_R16_UINT, 0);
    ID3D11DeviceContext_DrawIndexed(g_context, 6, 0, 0);
    g_draw_calls++;
    g_total_triangles += 2;

    /* Restore depth state */
    apply_depth_state();
    /* Restore sampler */
    ID3D11DeviceContext_PSSetSamplers(g_context, 0, 1, &g_sampler_linear);
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
