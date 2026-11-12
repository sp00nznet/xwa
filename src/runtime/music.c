/*
 * music: the game's CD audio, played by the host.
 *
 * The Steam edition swaps the CD for Music\TrackNN.ogg through its own
 * winmm replacement (WIN32.dll; X-Wing and TIE ship it as MUSIC.dll). Its
 * player thread races the game's stop and play: about one run in five it
 * corrupted the heap as the front end changed track. So the game's
 * mciSendCommandA comes here instead, and the tracks are decoded with the
 * libvorbisfile-3.dll the game folder ships and played through waveOut.
 *
 * What the game sends, measured: MCI_OPEN (cdaudio), MCI_SET (TMSF time
 * format), MCI_STATUS (number of tracks; each track's type and length),
 * MCI_PLAY from one track to the next with MCI_NOTIFY, MCI_STOP, MCI_CLOSE.
 * Track 1 is the CD's data track; the music is tracks 2 and up.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
#include <stdlib.h>

#include "music.h"

#define DEVICE 0xBEEF
#define CDA_TRACK_AUDIO 1088
#define CDA_TRACK_OTHER 1089
#define CDA_STATUS_TYPE_TRACK 0x4001

typedef int (*ov_fopen_t)(const char*, void*);
typedef long (*ov_read_t)(void*, char*, int, int, int, int, int*);
typedef int (*ov_clear_t)(void*);
typedef double (*ov_time_total_t)(void*, int);
typedef struct { int version, channels; long rate; } vorbis_info;
typedef vorbis_info* (*ov_info_t)(void*, int);
static ov_fopen_t ov_fopen;
static ov_read_t ov_read;
static ov_clear_t ov_clear;
static ov_time_total_t ov_time_total;
static ov_info_t ov_info;

static int g_ntracks;            /* the last track there is a file for */
static DWORD g_len_ms[100];      /* each track's length */
static CRITICAL_SECTION g_lock;
static HANDLE g_thread;
static volatile LONG g_stop;
static volatile LONG g_playing, g_track;
static DWORD g_volume = 0xFFFFFFFF;

static int load(void) {
    static int done = -1;
    if (done >= 0) return done;
    InitializeCriticalSection(&g_lock);
    HMODULE m = LoadLibraryA("libvorbisfile-3.dll");
    if (m) {
        ov_fopen = (ov_fopen_t)GetProcAddress(m, "ov_fopen");
        ov_read = (ov_read_t)GetProcAddress(m, "ov_read");
        ov_clear = (ov_clear_t)GetProcAddress(m, "ov_clear");
        ov_time_total = (ov_time_total_t)GetProcAddress(m, "ov_time_total");
        ov_info = (ov_info_t)GetProcAddress(m, "ov_info");
    }
    done = ov_fopen && ov_read && ov_clear && ov_time_total && ov_info;
    for (int t = 2; done && t < 100; t++) {
        char path[64];
        _snprintf(path, sizeof path, "Music\\Track%02d.ogg", t);
        static char vf[4096];   /* an OggVorbis_File, with room to spare */
        if (ov_fopen(path, vf)) break;
        g_len_ms[t] = (DWORD)(ov_time_total(vf, -1) * 1000);
        ov_clear(vf);
        g_ntracks = t;
    }
    printf("[music] %s, tracks 2..%d\n", done ? "libvorbisfile" : "no libvorbisfile", g_ntracks);
    return done;
}

typedef struct { int track; HWND notify; } play_t;

static DWORD WINAPI player(LPVOID arg) {
    play_t p = *(play_t*)arg;
    free(arg);
    char path[64];
    _snprintf(path, sizeof path, "Music\\Track%02d.ogg", p.track);
    static char vf[4096];
    if (ov_fopen(path, vf)) { InterlockedExchange(&g_playing, 0); return 0; }
    vorbis_info* vi = ov_info(vf, -1);
    WAVEFORMATEX wf = { WAVE_FORMAT_PCM, (WORD)vi->channels, (DWORD)vi->rate, 0, 0, 16, 0 };
    wf.nBlockAlign = (WORD)(wf.nChannels * 2), wf.nAvgBytesPerSec = wf.nSamplesPerSec * wf.nBlockAlign;
    HWAVEOUT wo;
    HANDLE ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (waveOutOpen(&wo, WAVE_MAPPER, &wf, (DWORD_PTR)ev, 0, CALLBACK_EVENT)) { ov_clear(vf); CloseHandle(ev); InterlockedExchange(&g_playing, 0); return 0; }
    waveOutSetVolume(wo, g_volume);
    enum { NBUF = 4, BUFSZ = 32768 };
    static char data[NBUF][BUFSZ];
    WAVEHDR h[NBUF] = { 0 };
    int ended = 0, bs;
    for (;;) {
        int queued = 0;
        for (int i = 0; i < NBUF; i++) {
            if (h[i].dwFlags & WHDR_INQUEUE) { queued++; continue; }
            if (h[i].dwFlags & WHDR_PREPARED) waveOutUnprepareHeader(wo, &h[i], sizeof h[i]);
            if (ended || g_stop) continue;
            long n = 0, r;
            while (n < BUFSZ && (r = ov_read(vf, data[i] + n, BUFSZ - (int)n, 0, 2, 1, &bs)) > 0) n += r;
            if (n == 0) { ended = 1; continue; }
            h[i].lpData = data[i], h[i].dwBufferLength = (DWORD)n, h[i].dwFlags = 0;
            waveOutPrepareHeader(wo, &h[i], sizeof h[i]);
            waveOutWrite(wo, &h[i], sizeof h[i]);
            queued++;
        }
        if (g_stop) { waveOutReset(wo); }
        if (!queued) break;
        WaitForSingleObject(ev, 200);
    }
    for (int i = 0; i < NBUF; i++) if (h[i].dwFlags & WHDR_PREPARED) waveOutUnprepareHeader(wo, &h[i], sizeof h[i]);
    waveOutClose(wo);
    CloseHandle(ev);
    ov_clear(vf);
    int finished = !g_stop;
    InterlockedExchange(&g_playing, 0);
    /* The game waits to hear that the track ended, to play the next. */
    if (finished && p.notify) PostMessageA(p.notify, MM_MCINOTIFY, MCI_NOTIFY_SUCCESSFUL, DEVICE);
    return 0;
}

static void stop(void) {
    if (!g_thread) return;
    InterlockedExchange(&g_stop, 1);
    WaitForSingleObject(g_thread, 5000);
    CloseHandle(g_thread);
    g_thread = NULL;
    InterlockedExchange(&g_stop, 0);
}

void music_volume(DWORD v) { g_volume = v; }

MCIERROR music_mci(MCIDEVICEID dev, UINT msg, DWORD_PTR flags, DWORD_PTR parms) {
    if (!load()) return MCIERR_DEVICE_NOT_INSTALLED;
    EnterCriticalSection(&g_lock);
    MCIERROR r = 0;
    switch (msg) {
    case MCI_OPEN:
        if (parms) ((MCI_OPEN_PARMSA*)parms)->wDeviceID = DEVICE;
        break;
    case MCI_SET: break;   /* the time format: TMSF is what is answered anyway */
    case MCI_STATUS: {
        MCI_STATUS_PARMS* s = (MCI_STATUS_PARMS*)parms;
        int t = (int)s->dwTrack;
        switch (s->dwItem) {
        case MCI_STATUS_NUMBER_OF_TRACKS: s->dwReturn = (DWORD)g_ntracks; break;
        case CDA_STATUS_TYPE_TRACK: s->dwReturn = t >= 2 ? CDA_TRACK_AUDIO : CDA_TRACK_OTHER; break;
        case MCI_STATUS_LENGTH: {
            DWORD ms = flags & MCI_TRACK ? (t < 100 ? g_len_ms[t] : 0) : 0;
            if (!(flags & MCI_TRACK)) for (int i = 2; i <= g_ntracks; i++) ms += g_len_ms[i];
            s->dwReturn = MCI_MAKE_MSF(ms / 60000, ms / 1000 % 60, ms % 1000 * 75 / 1000);
            break;
        }
        case MCI_STATUS_MODE: s->dwReturn = g_playing ? MCI_MODE_PLAY : MCI_MODE_STOP; break;
        case MCI_STATUS_MEDIA_PRESENT: case MCI_STATUS_READY: s->dwReturn = TRUE; break;
        case MCI_STATUS_CURRENT_TRACK: s->dwReturn = (DWORD)g_track; break;
        case MCI_STATUS_POSITION: s->dwReturn = MCI_MAKE_TMSF(g_track, 0, 0, 0); break;
        default: r = MCIERR_UNSUPPORTED_FUNCTION;
        }
        break;
    }
    case MCI_PLAY: {
        MCI_PLAY_PARMS* p = (MCI_PLAY_PARMS*)parms;
        int t = p && flags & MCI_FROM ? MCI_TMSF_TRACK(p->dwFrom) : g_track;
        stop();
        if (t < 2 || t > g_ntracks) { r = MCIERR_OUTOFRANGE; break; }
        play_t* a = (play_t*)malloc(sizeof *a);
        a->track = t, a->notify = flags & MCI_NOTIFY && p ? (HWND)p->dwCallback : NULL;
        InterlockedExchange(&g_track, t);
        InterlockedExchange(&g_playing, 1);
        g_thread = CreateThread(NULL, 0, player, a, 0, NULL);
        break;
    }
    case MCI_STOP: case MCI_PAUSE: case MCI_CLOSE: stop(); break;
    default: r = 0;   /* MCI_SEEK and the like: nothing to do */
    }
    LeaveCriticalSection(&g_lock);
    return r;
}
