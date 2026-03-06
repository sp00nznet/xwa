/*
 * COM Mock Infrastructure for DirectX Interfaces
 *
 * Provides mock IDirectDraw, IDirectDrawSurface, IDirectDrawPalette,
 * IDirect3D, IDirect3DDevice, IDirect3DViewport, IDirect3DExecuteBuffer,
 * IDirectInput, IDirectInputDevice, IDirectSound, IDirectSoundBuffer
 * objects that the recompiled game can call through its COM vtable
 * dispatch pattern.
 *
 * Since g_mem_base=0 and we're 32-bit, malloc'd pointers are directly
 * usable as MEM32 addresses.
 */

#ifndef COM_MOCKS_H
#define COM_MOCKS_H

#include <stdint.h>

/* Mock COM object tags for debugging */
#define MOCK_TAG_DDRAW          0x44445257  /* 'DDRW' */
#define MOCK_TAG_DDSURFACE      0x44445346  /* 'DDSF' */
#define MOCK_TAG_DDPALETTE      0x44445041  /* 'DDPA' */
#define MOCK_TAG_D3D            0x44334430  /* 'D3D0' */
#define MOCK_TAG_D3DDEVICE      0x44334456  /* 'D3DV' */
#define MOCK_TAG_D3DVIEWPORT    0x44335650  /* 'D3VP' */
#define MOCK_TAG_D3DEXECBUF     0x44334542  /* 'D3EB' */
#define MOCK_TAG_DINPUT         0x44494E50  /* 'DINP' */
#define MOCK_TAG_DIDEVICE       0x44494456  /* 'DIDV' */
#define MOCK_TAG_DSOUND         0x44534E44  /* 'DSND' */
#define MOCK_TAG_DSBUFFER       0x44534246  /* 'DSBF' */

/* Mock COM object structure */
typedef struct mock_com_obj {
    uint32_t lpVtbl;    /* pointer to vtable array (uint32_t[]) */
    uint32_t refcount;
    uint32_t tag;       /* debug: which interface type */
    uint32_t extra[32]; /* instance-specific data */
} mock_com_obj_t;

/* Initialize the COM mock subsystem - registers all vtable bridges */
void com_mocks_init(void);

/* Bridge implementations called from imports.c */
void bridge_DirectDrawCreate_impl(void);
void bridge_DirectInputCreateA_impl(void);
void bridge_DirectSoundCreate_impl(void);

#endif /* COM_MOCKS_H */
