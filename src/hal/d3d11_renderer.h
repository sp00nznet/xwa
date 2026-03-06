/*
 * D3D11 Rendering Backend for XWA Recompilation
 *
 * Intercepts the game's Direct3D 5 execute buffer submissions and renders
 * them using Direct3D 11. Also handles 2D surface presentation (menus, HUD).
 */

#ifndef D3D11_RENDERER_H
#define D3D11_RENDERER_H

#include <stdint.h>

/* ============================================================
 * D3D5 Execute Buffer Structures
 * ============================================================ */

/* D3DTLVERTEX - Transformed & Lit vertex (32 bytes) */
typedef struct {
    float sx, sy, sz;       /* Screen-space position */
    float rhw;              /* 1/w (reciprocal homogeneous w) */
    uint32_t diffuse;       /* ARGB vertex color */
    uint32_t specular;      /* ARGB specular color */
    float tu, tv;           /* Texture coordinates */
} D3DTLVERTEX;

/* D3DINSTRUCTION header (4 bytes) */
typedef struct {
    uint8_t bOpcode;        /* D3DOP_xxx */
    uint8_t bSize;          /* Size of each data element */
    uint16_t wCount;        /* Number of data elements */
} D3DINSTRUCTION;

/* D3DTRIANGLE (8 bytes) */
typedef struct {
    uint16_t v1, v2, v3;    /* Vertex indices */
    uint16_t wFlags;        /* Edge flags */
} D3DTRIANGLE;

/* D3DLINE (4 bytes) */
typedef struct {
    uint16_t v1, v2;        /* Vertex indices */
} D3DLINE;

/* D3DSTATE (8 bytes) */
typedef struct {
    uint32_t drstRenderStateType;  /* D3DRENDERSTATE_xxx */
    uint32_t dwArg;                /* State value */
} D3DSTATE;

/* D3DPROCESSVERTICES (16 bytes) */
typedef struct {
    uint16_t dwFlags;
    uint16_t wStart;
    uint16_t wDest;
    uint32_t dwCount;
    uint32_t dwReserved;
} D3DPROCESSVERTICES;

/* D3D Execute Buffer opcodes */
#define D3DOP_POINT             1
#define D3DOP_LINE              2
#define D3DOP_TRIANGLE          3
#define D3DOP_MATRIXLOAD        4
#define D3DOP_MATRIXMULTIPLY    5
#define D3DOP_STATETRANSFORM    6
#define D3DOP_STATELIGHT        7
#define D3DOP_STATERENDER       8
#define D3DOP_PROCESSVERTICES   9
#define D3DOP_TEXTURELOAD       10
#define D3DOP_EXIT              11
#define D3DOP_BRANCHFORWARD     12
#define D3DOP_SPAN              13
#define D3DOP_SETSTATUS         14

/* D3D Render State Types (D3DRENDERSTATETYPE) */
#define D3DRENDERSTATE_TEXTUREHANDLE     1
#define D3DRENDERSTATE_ANTIALIAS         2
#define D3DRENDERSTATE_TEXTUREADDRESS    3
#define D3DRENDERSTATE_TEXTUREPERSPECTIVE 4
#define D3DRENDERSTATE_WRAPU             5
#define D3DRENDERSTATE_WRAPV             6
#define D3DRENDERSTATE_ZENABLE           7
#define D3DRENDERSTATE_FILLMODE          8
#define D3DRENDERSTATE_SHADEMODE         9
#define D3DRENDERSTATE_LINEPATTERN       10
#define D3DRENDERSTATE_ZWRITEENABLE      14
#define D3DRENDERSTATE_ALPHATESTENABLE   15
#define D3DRENDERSTATE_SRCBLEND          19
#define D3DRENDERSTATE_DESTBLEND         20
#define D3DRENDERSTATE_TEXTUREMAPBLEND   21
#define D3DRENDERSTATE_CULLMODE          22
#define D3DRENDERSTATE_ZFUNC             23
#define D3DRENDERSTATE_ALPHAREF          24
#define D3DRENDERSTATE_ALPHAFUNC         25
#define D3DRENDERSTATE_DITHERENABLE      26
#define D3DRENDERSTATE_ALPHABLENDENABLE  27
#define D3DRENDERSTATE_FOGENABLE         28
#define D3DRENDERSTATE_SPECULARENABLE    29
#define D3DRENDERSTATE_ZVISIBLE          30
#define D3DRENDERSTATE_FOGCOLOR          34
#define D3DRENDERSTATE_FOGTABLEMODE      35
#define D3DRENDERSTATE_FOGSTART          36
#define D3DRENDERSTATE_FOGEND            37
#define D3DRENDERSTATE_FOGDENSITY        38
#define D3DRENDERSTATE_COLORKEYENABLE    41
#define D3DRENDERSTATE_ZBIAS             47
#define D3DRENDERSTATE_FLUSHBATCH        50
#define D3DRENDERSTATE_TEXTUREMAG        17  /* D3DTEXTUREFILTER */
#define D3DRENDERSTATE_TEXTUREMIN        18  /* D3DTEXTUREFILTER */

/* D3DBLEND */
#define D3DBLEND_ZERO            1
#define D3DBLEND_ONE             2
#define D3DBLEND_SRCCOLOR        3
#define D3DBLEND_INVSRCCOLOR     4
#define D3DBLEND_SRCALPHA        5
#define D3DBLEND_INVSRCALPHA     6
#define D3DBLEND_DESTALPHA       7
#define D3DBLEND_INVDESTALPHA    8
#define D3DBLEND_DESTCOLOR       9
#define D3DBLEND_INVDESTCOLOR    10
#define D3DBLEND_SRCALPHASAT     11

/* D3DTEXTUREMAPBLEND */
#define D3DTBLEND_DECAL           1
#define D3DTBLEND_MODULATE        2
#define D3DTBLEND_DECALALPHA      3
#define D3DTBLEND_MODULATEALPHA   4

/* ============================================================
 * Texture Handle Table
 * ============================================================ */

#define MAX_TEXTURE_HANDLES 256

/* ============================================================
 * Renderer API
 * ============================================================ */

/* Initialize D3D11 device, swap chain, and GPU resources */
int d3d11_init(void* hwnd, uint32_t width, uint32_t height);

/* Shutdown and release all D3D11 resources */
void d3d11_shutdown(void);

/* Begin a new frame (clear render target + depth buffer) */
void d3d11_begin_scene(void);

/* End the current frame (no-op, present happens on flip) */
void d3d11_end_scene(void);

/* Execute a D3D5 execute buffer */
void d3d11_execute(uint8_t* buffer_data, uint32_t vertex_offset, uint32_t vertex_count,
                   uint32_t instruction_offset, uint32_t instruction_size);

/* Present the frame (called from IDirectDrawSurface::Flip) */
void d3d11_present(void);

/* Upload a 2D surface (16-bit RGB565) to the backbuffer for 2D rendering */
void d3d11_upload_surface(uint8_t* pixels, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);

/* Register a texture surface for a given texture handle */
void d3d11_register_texture(uint32_t handle, uint8_t* pixels, uint32_t width, uint32_t height, uint32_t pitch, uint32_t bpp);

/* Invalidate a texture (called when its surface is locked for writing) */
void d3d11_invalidate_texture(uint32_t handle);

/* Set viewport dimensions (called from IDirect3DViewport::SetViewport) */
void d3d11_set_viewport(uint32_t x, uint32_t y, uint32_t width, uint32_t height);

/* Check if renderer is initialized */
int d3d11_is_initialized(void);

#endif /* D3D11_RENDERER_H */
