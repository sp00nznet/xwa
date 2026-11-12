/* gpu: the Direct3D 11 half of the host (gpu.c has the design). */
#pragma once
#include <windows.h>
#include <stdint.h>

/* One D3DTLVERTEX, as the game's execute buffers hold it (32 bytes). */
typedef struct { float sx, sy, sz, rhw; uint32_t color, specular; float tu, tv; } gpu_vertex;

/* The 3D render state the game sets through D3DOP_STATERENDER. */
typedef struct {
    int tex;            /* gpu_texture() slot, 0 = none */
    int zenable, zwrite, zfunc;
    int blend, src, dst;            /* ALPHABLENDENABLE, SRCBLEND, DESTBLEND (D3D11 values) */
    int mapblend;                   /* TEXTUREMAPBLEND */
    int colorkey, alphatest, alpharef;
    int specular, fog;
    uint32_t fogcolor;
    int wrap;                       /* TEXTUREADDRESS: 1 wrap, 3 clamp */
} gpu_state;

enum { GPU_SHARP, GPU_SMOOTH, GPU_CRT, GPU_NEAREST, GPU_INTEGER, GPU_NMODES };
extern const char* const gpu_mode_names[GPU_NMODES];

typedef struct {
    int mode;           /* GPU_SHARP.. scaling for the 2D picture */
    int filter;         /* 3D textures: 0 nearest (the original), 1 bilinear, 2 anisotropic */
    int fullscreen;     /* borderless on the window's monitor */
    int widescreen;     /* 3D: Hor+ to the window's aspect (in flight) */
    int hd_textures;    /* mods/textures replacements */
    int dump_textures;  /* write every new texture to mods/dump */
    int msaa;           /* 3D multisampling: 1, 2, 4, 8 */
} gpu_settings;
extern gpu_settings g_gpu;

int  gpu_init(HWND w);              /* 0 if Direct3D 11 is not there (softdd falls back to GDI) */
int  gpu_ready(void);
void gpu_resize(void);              /* WM_SIZE */
void gpu_set_fullscreen(int on);

/* The 2D picture: the primary as the game drew it. key >= 0: pixels of that
 * 16-bit value are holes the 3D shows through. */
void gpu_frame_2d(const uint8_t* bits, int w, int h, int pitch, int bpp,
                  const PALETTEENTRY* pal, int key);
void gpu_present(void);
/* The frame so far, under the 3D: the first 3D draw of a frame calls it (d3d.c). */
void gpu_background(const uint8_t* bits, int w, int h, int pitch, int bpp, const PALETTEENTRY* pal);

/* 3D, in the game's 640x480 coordinates; rendered at the window's resolution. */
void gpu_clear(int x0, int y0, int x1, int y1, int target, uint32_t color, int zbuffer, float z);
void gpu_draw(const gpu_vertex* v, int nv, const uint16_t* idx, int ni, const gpu_state* st);
int  gpu_scene_count(void);         /* 3D draws since the last present */
int  gpu_in_flight(void);           /* the 3D has been on screen in the last half second or so */

/* A texture, cached by (key, version). fmt: bpp 8 (pal), or 16/32 with masks. */
typedef struct { int bpp; uint32_t r, g, b, a; const PALETTEENTRY* pal; int has_ck; uint32_t ck; } gpu_fmt;
int  gpu_texture(const void* key, uint32_t version, const uint8_t* bits, int w, int h, int pitch,
                 const gpu_fmt* f);

/* The window's client point -> the game's 640x480 point; 0 outside the picture. */
int  gpu_to_game(POINT* p);
void gpu_from_game(POINT* p);   /* and back */
/* Write the next presented frame (as shown) to path. */
int gpu_shot_pending(void);
void gpu_shot(const char* path);
/* Hor+: how much wider than 4:3 the 3D view is (1.0 = 4:3). */
float gpu_aspect_gain(void);
