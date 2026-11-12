/*
 * sound: the game's DirectSound, real, watched.
 *
 * Sound needs nothing from the host to work (the real DirectSound, the real
 * MUSIC.dll). This only keeps count, so a run that nobody listens to (a test,
 * an RDP session) can still say whether the game made sound: buffers made,
 * started, and the loudest 16-bit sample written into them. --sound-log
 * prints the counts every five seconds.
 *
 * IDirectSound::CreateSoundBuffer is slot 3; IDirectSoundBuffer::Play 12,
 * Unlock 19.
 */
#define WIN32_LEAN_AND_MEAN
#define CINTERFACE
#include <windows.h>
#include <mmsystem.h>
#include <dsound.h>
#include <stdio.h>
#include <stdint.h>

#include "sound.h"

int g_sound_log;
static volatile LONG g_buffers, g_plays, g_peak, g_unlocks;
static struct { void* b; WORD bits; } g_fmt[1024];   /* each buffer's sample size */
static int g_nfmt;
static WORD bits_of(void* b) { for (int i = 0; i < g_nfmt; i++) if (g_fmt[i].b == b) return g_fmt[i].bits; return 16; }

static void* vt_set(void** vt, int n, void* fn) {
    DWORD old;
    void* was = vt[n];
    VirtualProtect(&vt[n], sizeof vt[n], PAGE_READWRITE, &old);
    vt[n] = fn;
    VirtualProtect(&vt[n], sizeof vt[n], old, &old);
    return was;
}

typedef HRESULT (WINAPI *play_t)(void*, DWORD, DWORD, DWORD);
typedef HRESULT (WINAPI *unlock_t)(void*, void*, DWORD, void*, DWORD);
typedef HRESULT (WINAPI *create_t)(void*, LPCDSBUFFERDESC, void**, void*);
static play_t g_play;
static unlock_t g_unlock;
static create_t g_create;

static void peak(const void* p, DWORD n, WORD bits) {   /* as 16-bit: 8-bit is unsigned, centred on 128 */
    if (!p) return;
    LONG m = g_peak;
    if (bits == 8) {
        const uint8_t* s = (const uint8_t*)p;
        for (DWORD i = 0; i < n; i++) { LONG a = ((LONG)s[i] - 128) * 256; if (a < 0) a = -a; if (a > m) m = a; }
    } else {
        const int16_t* s = (const int16_t*)p;
        for (DWORD i = 0; i < n / 2; i++) { LONG a = s[i] < 0 ? -s[i] : s[i]; if (a > m) m = a; }
    }
    g_peak = m > 32767 ? 32767 : m;
}
static HRESULT WINAPI hook_Play(void* b, DWORD r, DWORD p, DWORD f) { InterlockedIncrement(&g_plays); return g_play(b, r, p, f); }
static HRESULT WINAPI hook_Unlock(void* b, void* p1, DWORD n1, void* p2, DWORD n2) {
    InterlockedIncrement(&g_unlocks);
    WORD bits = bits_of(b);
    peak(p1, n1, bits), peak(p2, n2, bits);
    return g_unlock(b, p1, n1, p2, n2);
}
static HRESULT WINAPI hook_Create(void* ds, LPCDSBUFFERDESC d, void** out, void* u) {
    HRESULT hr = g_create(ds, d, out, u);
    if (hr == DS_OK && *out) {
        InterlockedIncrement(&g_buffers);
        if (d->lpwfxFormat && g_nfmt < 1024) g_fmt[g_nfmt].b = *out, g_fmt[g_nfmt++].bits = d->lpwfxFormat->wBitsPerSample;
        void** vt = **(void****)out;
        if (vt[12] != (void*)hook_Play) g_play = (play_t)vt_set(vt, 12, hook_Play);
        if (vt[19] != (void*)hook_Unlock) g_unlock = (unlock_t)vt_set(vt, 19, hook_Unlock);
    }
    return hr;
}

void sound_watch(void* ds) {
    void** vt = *(void***)ds;
    if (vt[3] != (void*)hook_Create) g_create = (create_t)vt_set(vt, 3, hook_Create);
}

void sound_report(void) {
    printf("[sound] %ld buffers, %ld plays, %ld writes, loudest sample %ld of 32767\n",
           g_buffers, g_plays, g_unlocks, g_peak);
    g_peak = 0;
}
