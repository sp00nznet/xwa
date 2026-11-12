/*
 * X-Wing Alliance (Steam) - static recompilation host. Forked from xvt-recomp, itself forked from
 * xwing-recomp: the same engine and the same remaster.
 *
 * A 32-bit host on pcrecomp's runtime/native32 (the native bridge, callbacks
 * and machine lock; see its header). Every import goes to the real DLL --
 * DirectDraw (GOG's wrapper in the game folder), DirectSound, DirectInput,
 * MUSIC.dll -- so what is
 * here is only what is specific to this game: where the image goes, the
 * command line, the calls that reach outside the game, muting, and the fault
 * report. Taken from Crazy Taxi's host (crazytaxi-recomp).
 *
 * Linked at /BASE:0x60000000 (CMakeLists.txt) so the guest's
 * image is free when main() maps the image.
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <mmsystem.h>
#include <mmdeviceapi.h>
#include <audiopolicy.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <shlwapi.h>
#include <windowsx.h>

#include "native32.h"
#include "recomp_trace.h"
#include "softdd.h"
#include "gpu.h"
#include "settings.h"
#include "flight.h"
#include "sound.h"
#include "dplay.h"
#include "music.h"

extern const uint32_t tf_entry_va;  /* recomp_dispatch.c */

#define IMAGE_BASE 0x00400000u
#define ARG(n) MEM32(g_esp + 4 + 4 * (n))

static DWORD g_watchdog_s;
static int   g_headless;
static int   g_fullscreen;   /* --fullscreen: no always-active window */

/* --shot SECONDS FILE: the next frame after SECONDS, read from the back
 * buffer in Present (hook_Present), as a .bmp. --shot can be given more than
 * once. A frame count is printed every five seconds. */
static DWORD g_shot_s[16];
static char  g_shot_file[16][MAX_PATH];
static int   g_shots, g_shot_next;
static HWND g_game_wnd;      /* the game's window */
static DWORD WINAPI shot_thread(LPVOID unused) {
    (void)unused;
    DWORD t0 = GetTickCount();
    for (int i = 0; i < g_shots; i++) {
        DWORD at = t0 + g_shot_s[i] * 1000, now = GetTickCount();
        if ((int)(at - now) > 0) Sleep(at - now);
        softdd_shot(g_shot_file[i]);
    }
    return 0;
}

/* ---- the process is the host, the module is the guest ----------------------
 * GetModuleHandleA(NULL) and GetModuleFileNameA(NULL) would name the host;
 * the game finds its own folder through them. */
static char g_guest_exe[MAX_PATH], g_guest_cmdline[MAX_PATH + 512];

static void shim_GetModuleHandleA(void) {
    g_eax = ARG(0) ? (uint32_t)(uintptr_t)GetModuleHandleA((LPCSTR)(uintptr_t)ARG(0)) : IMAGE_BASE;
    g_esp += 4 + 1 * 4;
}

static void shim_GetModuleFileNameA(void) {
    uint32_t h = ARG(0), size = ARG(2);
    char* out = (char*)(uintptr_t)ARG(1);
    if (h == 0 || h == IMAGE_BASE) {
        uint32_t n = (uint32_t)strlen(g_guest_exe);
        if (size) {
            uint32_t k = n < size ? n : size - 1;
            memcpy(out, g_guest_exe, k);
            out[k] = 0;
            n = k;
        }
        g_eax = n;
    } else {
        g_eax = GetModuleFileNameA((HMODULE)(uintptr_t)h, out, size);
    }
    g_esp += 4 + 3 * 4;
}

static void shim_GetCommandLineA(void) {
    g_eax = (uint32_t)(uintptr_t)g_guest_cmdline;
    g_esp += 4;
}

/* A shim runs holding the machine, and a window call can wait on another
 * thread answering messages: run it with the machine let go. */
#define UNLOCKED(call) do { uint32_t esp_ = g_esp; mach_leave(); \
    call; DWORD err_ = GetLastError(); mach_enter(); \
    g_esp = esp_; SetLastError(err_); } while (0)

static void shim_MessageBoxA(void) {
    const char* text = ARG(1) ? (const char*)(uintptr_t)ARG(1) : "";
    const char* cap = ARG(2) ? (const char*)(uintptr_t)ARG(2) : "";
    printf("[host] MessageBoxA \"%s\": %s\n", cap, text);
    if (g_headless || g_watchdog_s) {   /* test runs never put a box on the screen */
        uint32_t b = ARG(3) & MB_TYPEMASK;
        g_eax = (b == MB_YESNO || b == MB_YESNOCANCEL) ? IDNO
              : (b == MB_RETRYCANCEL || b == MB_OKCANCEL) ? IDCANCEL
              : b == MB_ABORTRETRYIGNORE ? IDABORT : IDOK;
    } else {
        HWND w = (HWND)(uintptr_t)ARG(0);
        UINT type = ARG(3);
        int r;
        UNLOCKED(r = MessageBoxA(w, text, cap, type));
        g_eax = r;
    }
    g_esp += 4 + 4 * 4;
}

static void shim_OutputDebugStringA(void) {
    if (ARG(0)) printf("[dbg] %s", (const char*)(uintptr_t)ARG(0));
    g_esp += 4 + 1 * 4;
}

/* SuspendThread keeps the machine lock. A native call gives the lock up, so
 * the target could be caught in lifted code holding it, and the caller then
 * waits for it for ever: XvT's movie player suspends its decoder thread
 * around every frame, and the intro hung on its first. With the lock held
 * here the target is waiting for it or in a native call, as only one thread
 * at a time runs the game's code. */
static void shim_SuspendThread(void) {
    g_eax = SuspendThread((HANDLE)(uintptr_t)ARG(0));
    g_esp += 4 + 1 * 4;
}

/* The game ends itself with ExitProcess, which skips the host's way out. */
static void shim_ExitProcess(void) {
    UINT code = ARG(0);
    printf("[host] ExitProcess(%u) from sub_%08X\n", code, g_cur_func);
    recomp_trace_flush();
    ExitProcess(code);
}

/* ---- the CD ------------------------------------------------------------------
 * The game may want its CD-ROM drive. The host makes
 * one free letter a CD-ROM whose root is the game folder, adds it to
 * GetLogicalDriveStringsA, and redirects paths on it. Real CD drives are
 * hidden, so a disc left in one is never preferred. From HotD 1's host, by way of HotD2. */
static char g_game_dir[MAX_PATH];
static char g_cd = 0;

static const char* cd_path(const char* in, char* out, size_t n) {
    if (in && g_cd && (in[0] & ~0x20) == g_cd && in[1] == ':') {
        const char* rest = in + 2;
        while (*rest == '\\' || *rest == '/') rest++;
        _snprintf(out, n - 1, "%s\\%s", g_game_dir, rest);
        out[n - 1] = 0;
        return out;
    }
    return in;
}

static void cd_pick(const char* game_dir) {
    lstrcpynA(g_game_dir, game_dir, MAX_PATH);
    DWORD used = GetLogicalDrives();
    for (char c = 'D'; c <= 'Z' && !g_cd; c++)
        if (!(used & (1u << (c - 'A')))) g_cd = c;
    printf("  CD drive: %c: -> %s\n", g_cd ? g_cd : '?', g_game_dir);
}

static void shim_GetLogicalDriveStringsA(void) {
    DWORD n = ARG(0);
    char* out = (char*)(uintptr_t)ARG(1);
    char all[512];
    DWORD k = GetLogicalDriveStringsA(sizeof all - 8, all);
    if (g_cd && k + 5 < sizeof all) { all[k] = g_cd; memcpy(all + k + 1, ":\\", 3); k += 4; all[k] = 0; }
    if (k + 1 <= n) memcpy(out, all, k + 1);
    g_eax = k + 1 <= n ? k : k + 1;
    g_esp += 4 + 2 * 4;
}

static void shim_GetDriveTypeA(void) {
    const char* root = (const char*)(uintptr_t)ARG(0);
    UINT t = GetDriveTypeA(root);
    if (root && g_cd && (root[0] & ~0x20) == g_cd) t = DRIVE_CDROM;
    else if (t == DRIVE_CDROM) t = DRIVE_NO_ROOT_DIR;
    g_eax = t;
    g_esp += 4 + 1 * 4;
}

static void shim_GetLogicalDrives(void) {
    g_eax = GetLogicalDrives() | (g_cd ? 1u << (g_cd - 'A') : 0);
    g_esp += 4;
}

/* The game folder, as a CD. */
static void shim_GetVolumeInformationA(void) {
    const char* root = (const char*)(uintptr_t)ARG(0);
    if (root && g_cd && (root[0] & ~0x20) == g_cd) {
        char* label = (char*)(uintptr_t)ARG(1);
        char* fs = (char*)(uintptr_t)ARG(6);
        if (label && ARG(2)) lstrcpynA(label, "XWING", ARG(2));
        if (ARG(3)) MEM32(ARG(3)) = 0x12345678u;
        if (ARG(4)) MEM32(ARG(4)) = 110;
        if (ARG(5)) MEM32(ARG(5)) = FILE_READ_ONLY_VOLUME;
        if (fs && ARG(7)) lstrcpynA(fs, "CDFS", ARG(7));
        g_eax = TRUE;
    } else {
        g_eax = GetVolumeInformationA(root, (LPSTR)(uintptr_t)ARG(1), ARG(2), (LPDWORD)(uintptr_t)ARG(3),
                                      (LPDWORD)(uintptr_t)ARG(4), (LPDWORD)(uintptr_t)ARG(5),
                                      (LPSTR)(uintptr_t)ARG(6), ARG(7));
    }
    g_esp += 4 + 8 * 4;
}

/* "on:NAME" waits until the game opens a file whose name has NAME in it
 * (a screen's resources), and the times after it count from then. */
static char g_wait_file[64];
static HANDLE g_file_seen;

/* The game's file opens, logged: the milestones a run is read by. */
/* Mods: a file at the same relative path under mods\files replaces the
 * game's, for reading (ship models, resources, missions). The game's copy is
 * never changed. */
static const char* mod_path(const char* name, char* out, size_t n) {
    if (!g_mods || !name || name[0] == '\\' || strchr(name, ':')) return name;
    while (name[0] == '.' && (name[1] == '\\' || name[1] == '/')) {
        name += 2;
        while (*name == '\\' || *name == '/') name++;
    }
    _snprintf(out, n - 1, "mods\\files\\%s", name);
    out[n - 1] = 0;
    if (GetFileAttributesA(out) == INVALID_FILE_ATTRIBUTES) return NULL;
    return out;
}

static void shim_CreateFileA(void) {
    char buf[MAX_PATH * 2], mod[MAX_PATH * 2];
    const char* name = cd_path((const char*)(uintptr_t)ARG(0), buf, sizeof buf);
    if (!(ARG(1) & GENERIC_WRITE)) {
        const char* m = mod_path(name, mod, sizeof mod);
        if (m && m != name) { printf("[mods] %s\n", m); name = m; }
    }
    g_eax = (uint32_t)(uintptr_t)CreateFileA(name, ARG(1), ARG(2), (LPSECURITY_ATTRIBUTES)(uintptr_t)ARG(3),
                                             ARG(4), ARG(5), (HANDLE)(uintptr_t)ARG(6));
    printf("[host] open %s -> %s\n", name ? name : "(null)",
           g_eax == (uint32_t)(uintptr_t)INVALID_HANDLE_VALUE ? "missing" : "ok");
    if (g_wait_file[0] && name && StrStrIA(name, g_wait_file)) { g_wait_file[0] = 0; SetEvent(g_file_seen); }
    g_esp += 4 + 7 * 4;
}

/* A C++ throw, logged: the object's type and first words (D3DX's carry an
 * HRESULT), then raised for real so the lifted handlers see it. */
static void shim_RaiseException(void) {
    DWORD code = ARG(0), flags = ARG(1), n = ARG(2);
    const ULONG_PTR* a = (const ULONG_PTR*)(uintptr_t)ARG(3);
    if (code == 0xE06D7363u && n >= 3) {
        const uint32_t* obj = (const uint32_t*)a[1];
        const uint32_t* ti = (const uint32_t*)a[2];
        const uint32_t* cta = ti ? (const uint32_t*)(uintptr_t)ti[3] : NULL;
        const uint32_t* ct = cta && cta[0] ? (const uint32_t*)(uintptr_t)cta[1] : NULL;
        const char* name = ct ? (const char*)(uintptr_t)(ct[1] + 8) : "?";
        printf("[throw] %s from sub_%08X: %08X %08X %08X %08X\n", name, g_cur_func,
               obj ? obj[0] : 0, obj ? obj[1] : 0, obj ? obj[2] : 0, obj ? obj[3] : 0);
        if (obj && !IsBadStringPtrA((LPCSTR)obj, 300) && ((const char*)obj)[0] >= ' ')
            printf("[throw]   \"%.300s\"\n", (const char*)obj);
        else if (obj && obj[1] > 0x400000 && obj[1] < 0x10000000 && !IsBadStringPtrA((LPCSTR)(uintptr_t)obj[1], 200))
            printf("[throw]   \"%s\"\n", (const char*)(uintptr_t)obj[1]);
        recomp_dump_trace("throw");
    }
    UNLOCKED(RaiseException(code, flags, n, a));
    g_esp += 4 + 4 * 4;
}

/* Fullscreen flips fail unless the game's window is in front; started from a
 * console it is not, so it is brought forward when shown. */
static void shim_ShowWindow(void) {
    HWND w = (HWND)(uintptr_t)ARG(0);
    int cmd = (int)ARG(1);
    printf("[host] ShowWindow %p %d from sub_%08X\n", (void*)w, cmd, g_cur_func);
    BOOL r;
    /* Windows refuses SetForegroundWindow to a process started in the
     * background; a tapped Alt lifts the lock (the usual workaround). */
    UNLOCKED(r = ShowWindow(w, cmd);
             if (cmd != SW_HIDE && !g_headless && g_fullscreen) {
                 keybd_event(VK_MENU, 0, 0, 0);
                 SetForegroundWindow(w);
                 keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0);
             });
    g_eax = r;
    g_esp += 4 + 2 * 4;
}

/* The game pauses (draws nothing) while its window is inactive. Windowed, it
 * is told it is always active, as HotD 1's online play does. */
static WNDPROC g_game_proc;
static int g_scripted;   /* --keys (below) */
static LRESULT CALLBACK host_wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_ACTIVATEAPP: case WM_NCACTIVATE: w = TRUE; break;
    case WM_ACTIVATE: w = MAKEWPARAM(WA_ACTIVE, HIWORD(w)); break;
    case WM_KILLFOCUS: return 0;
    /* the presenter's: the window is the player's to size */
    case WM_SIZE: gpu_resize(); return 0;
    case WM_WINDOWPOSCHANGING: case WM_WINDOWPOSCHANGED: case WM_GETMINMAXINFO:
    case WM_NCCALCSIZE: case WM_STYLECHANGED: case WM_STYLECHANGING:
        return DefWindowProcA(h, m, w, l);
    case WM_ERASEBKGND: return 1;
    case WM_KEYDOWN: case WM_SYSKEYDOWN:
        if (settings_key(h, (UINT)w, m == WM_SYSKEYDOWN)) return 0;
        break;
    case WM_SYSKEYUP: if (w == VK_F10) return 0; break;
    case WM_SYSCHAR: if (w == VK_RETURN) return 0; break;
    case WM_RBUTTONUP: {   /* outside the picture: the settings menu */
        POINT p = { GET_X_LPARAM(l), GET_Y_LPARAM(l) }, q = p;
        if (gpu_ready() && !gpu_to_game(&q)) { settings_menu(h, p.x, p.y); return 0; }
        break;
    }
    }
    /* mouse messages carry window pixels; the game expects its 640x480 */
    if (m >= WM_MOUSEFIRST && m <= WM_MOUSELAST && m != WM_MOUSEWHEEL && gpu_ready() && !g_scripted) {
        POINT p = { GET_X_LPARAM(l), GET_Y_LPARAM(l) };
        gpu_to_game(&p);
        l = MAKELPARAM(p.x, p.y);
    }
    return CallWindowProcA(g_game_proc, h, m, w, l);
}

static void shim_CreateWindowExA(void) {
    uint32_t a[12];
    for (int i = 0; i < 12; i++) a[i] = ARG(i);
    if (g_headless) a[3] &= ~WS_VISIBLE;
    /* A fullscreen popup over the whole desktop: windowed, it starts at the
     * mode size (softdd fits it when the mode is set). */
    if (!a[8] && !g_fullscreen && (a[3] & WS_POPUP)) { a[4] = a[5] = 64; a[6] = 640; a[7] = 480; }
    printf("[host] CreateWindowExA \"%s\" style %08X at %d,%d %dx%d parent %08X\n",
           a[2] ? (const char*)(uintptr_t)a[2] : "", a[3], a[4], a[5], a[6], a[7], a[8]);
    HWND h;
    UNLOCKED(h = CreateWindowExA(a[0], (LPCSTR)(uintptr_t)a[1], (LPCSTR)(uintptr_t)a[2], a[3],
                                 a[4], a[5], a[6], a[7], (HWND)(uintptr_t)a[8],
                                 (HMENU)(uintptr_t)a[9], (HINSTANCE)(uintptr_t)a[10], (LPVOID)(uintptr_t)a[11]));
    DWORD err = h ? 0 : GetLastError();
    if (h && !a[8] && !g_game_wnd) g_game_wnd = h;
    if (h && !a[8] && !g_game_proc && !g_fullscreen) {
        /* The game's procedure is guest code: Windows' call to it faults on
         * the non-executable page and native32 runs the lifted body. */
        g_game_proc = (WNDPROC)SetWindowLongPtrA(h, GWLP_WNDPROC, (LONG_PTR)host_wndproc);
        g_game_wnd = h;
        PostMessageA(h, WM_ACTIVATEAPP, TRUE, 0);
    }
    SetLastError(err);
    g_eax = (uint32_t)(uintptr_t)h;
    g_esp += 4 + 12 * 4;
}

/* Before its main loop the game waits in GetMessage until its window is in
 * front (sub_0040A730), and minimizes it meanwhile. Windowed, it always is. */
static void shim_GetForegroundWindow(void) {
    g_eax = (uint32_t)(uintptr_t)(g_game_wnd ? g_game_wnd : GetForegroundWindow());
    g_esp += 4;
}

/* CloseWindow minimizes. The game does it to its window whenever another
 * window is in front (sub_0040A730); windowed, it never does. */
static void shim_CloseWindow(void) {
    static int once;
    if (!once++) printf("[host] CloseWindow from sub_%08X%s\n", g_cur_func, g_fullscreen ? "" : ": ignored");
    if (g_fullscreen) UNLOCKED(CloseWindow((HWND)(uintptr_t)ARG(0)));
    g_eax = TRUE;
    g_esp += 4 + 1 * 4;
}

/* ---- the joystick -------------------------------------------------------------
 * The game will not start without one (MUSIC.dll's joy* calls, which are
 * winmm's). A real one is used when present; otherwise a virtual one,
 * centred, buttons up. */
static int g_real_joy = -1;
static int real_joy(void) {
    if (g_real_joy < 0) { JOYINFOEX ji = { sizeof ji, JOY_RETURNALL }; g_real_joy = joyGetPosEx(0, &ji) == JOYERR_NOERROR; }
    return g_real_joy;
}
static void shim_joyGetNumDevs(void) { g_eax = real_joy() ? joyGetNumDevs() : 1; g_esp += 4; }
static void shim_joyGetDevCapsA(void) {
    UINT id = ARG(0), n = ARG(2);
    JOYCAPSA* c = (JOYCAPSA*)(uintptr_t)ARG(1);
    if (real_joy()) g_eax = joyGetDevCapsA(id, c, n);
    else if (id != 0 || !c) g_eax = JOYERR_PARMS;
    else {
        memset(c, 0, n);
        lstrcpynA(c->szPname, "Virtual joystick", MAXPNAMELEN);
        c->wXmax = c->wYmax = c->wZmax = c->wRmax = 0xFFFF;
        c->wNumButtons = c->wMaxButtons = 4;
        c->wNumAxes = c->wMaxAxes = 3;
        c->wCaps = JOYCAPS_HASZ;
        c->wPeriodMin = 10; c->wPeriodMax = 1000;
        g_eax = JOYERR_NOERROR;
    }
    g_esp += 4 + 3 * 4;
}
static void shim_joyGetPosEx(void) {
    UINT id = ARG(0);
    JOYINFOEX* j = (JOYINFOEX*)(uintptr_t)ARG(1);
    if (real_joy()) g_eax = joyGetPosEx(id, j);
    else if (id != 0 || !j) g_eax = JOYERR_UNPLUGGED;
    else {
        DWORD size = j->dwSize, flags = j->dwFlags;
        memset(j, 0, size < sizeof *j ? size : sizeof *j);
        j->dwSize = size; j->dwFlags = flags;
        flight_joystick(g_game_wnd, g_scripted, j);
        g_eax = JOYERR_NOERROR;
    }
    g_esp += 4 + 2 * 4;
}

/* ---- DirectDraw and DirectInput ---------------------------------------------
 * DirectDraw is softdd (softdd.c): the game's 640x480x8 fullscreen mode in a
 * window, the desktop left alone. DirectInput checks the instance handle; the
 * game passes its own image base, which Windows never loaded. */
static void shim_DirectDrawCreate(void) {
    g_eax = (uint32_t)softdd_create((void**)(uintptr_t)ARG(1));
    g_esp += 4 + 3 * 4;
}

/* ---- scripted input (--keys) ---------------------------------------------------
 * "SECONDS:what,..." where what is a key name (esc, enter, space, up, down,
 * left, right, tab, f1..f10, a letter or digit), "click:X:Y" (game pixels,
 * 640x480), "move:X:Y", or "press:X:Y" ... "release:X:Y" for a drag. A key is held for 150 ms. While a script runs, the
 * real keyboard and mouse are not read: only the script reaches the game. */
typedef struct { DWORD at; int dik, vk, x, y, click, move; char on[64], shot[MAX_PATH]; } step_t;

static step_t g_steps[512];
static int g_nsteps, g_scripted;
static volatile DWORD g_key_until[256];      /* DIK code -> tick it is held until */
static volatile DWORD g_vk_until[256];       /* the same, by virtual key */
/* Key presses and releases for buffered reads (GetDeviceData). */
static CRITICAL_SECTION g_evq_lock;
static struct { DWORD ofs, data, t; } g_evq[64];
static int g_evq_n;
static void evq_push(DWORD dik, DWORD data) {
    EnterCriticalSection(&g_evq_lock);
    if (g_evq_n < 64) { g_evq[g_evq_n].ofs = dik; g_evq[g_evq_n].data = data; g_evq[g_evq_n].t = GetTickCount(); g_evq_n++; }
    LeaveCriticalSection(&g_evq_lock);
}
static volatile LONG g_cur_x = 320, g_cur_y = 240;
static volatile DWORD g_button_until;

static const struct { const char* n; int dik, vk; } g_keynames[] = {
    { "esc", 0x01, VK_ESCAPE }, { "enter", 0x1C, VK_RETURN }, { "space", 0x39, VK_SPACE },
    { "tab", 0x0F, VK_TAB }, { "up", 0xC8, VK_UP }, { "down", 0xD0, VK_DOWN },
    { "left", 0xCB, VK_LEFT }, { "right", 0xCD, VK_RIGHT }, { "bksp", 0x0E, VK_BACK },
    { "f1", 0x3B, VK_F1 }, { "f2", 0x3C, VK_F2 }, { "f3", 0x3D, VK_F3 }, { "f4", 0x3E, VK_F4 },
    { "f5", 0x3F, VK_F5 }, { "f6", 0x40, VK_F6 }, { "f7", 0x41, VK_F7 }, { "f8", 0x42, VK_F8 },
    { "f9", 0x43, VK_F9 }, { "f10", 0x44, VK_F10 },
};
static const char g_dik_letters[] = "qwertyuiop\0\0\0\0asdfghjkl\0\0\0\0\0zxcvbnm";   /* from 0x10 */

static int key_by_name(const char* n, int* vk) {
    for (int i = 0; i < (int)(sizeof g_keynames / sizeof g_keynames[0]); i++)
        if (!_stricmp(n, g_keynames[i].n)) { *vk = g_keynames[i].vk; return g_keynames[i].dik; }
    if (n[0] && !n[1]) {
        char c = (char)tolower((unsigned char)n[0]);
        if (c >= '1' && c <= '9') { *vk = c; return 0x02 + (c - '1'); }
        if (c == '0') { *vk = '0'; return 0x0B; }
        for (int i = 0; i < (int)sizeof g_dik_letters; i++)
            if (g_dik_letters[i] == c) { *vk = toupper((unsigned char)c); return 0x10 + i; }
    }
    return 0;
}

static void parse_keys(const char* spec) {
    static char buf[32768];
    lstrcpynA(buf, spec, sizeof buf);
    for (char* tok = strtok(buf, ","); tok && g_nsteps < 512; tok = strtok(NULL, ",")) {
        step_t st = { 0 };
        char* c = strchr(tok, ':');
        if (!c) continue;
        st.at = (DWORD)(atof(tok) * 1000);
        char* what = c + 1;
        if (!strncmp(tok, "on:", 3)) {
            lstrcpynA(st.on, tok + 3, sizeof st.on);
            g_steps[g_nsteps++] = st;
            continue;
        }
        if (!strncmp(what, "shot=", 5)) { GetFullPathNameA(what + 5, MAX_PATH, st.shot, NULL); g_steps[g_nsteps++] = st; continue; }
        if (!strncmp(what, "stick:", 6)) {
            st.move = 2;
            sscanf(what + 6, "%d:%d", &st.x, &st.y);
            g_steps[g_nsteps++] = st;
            continue;
        }
        if (!strcmp(what, "fire") || !strcmp(what, "nofire")) {
            st.move = 3, st.click = what[0] == 'f';
            g_steps[g_nsteps++] = st;
            continue;
        }
        if (!strncmp(what, "click:", 6) || !strncmp(what, "move:", 5) || !strncmp(what, "press:", 6) || !strncmp(what, "release:", 8)) {
            st.click = what[0] == 'c' ? 1 : what[0] == 'p' ? 2 : what[0] == 'r' ? 3 : 0;
            st.move = 1;
            sscanf(strchr(what, ':') + 1, "%d:%d", &st.x, &st.y);
        } else if (!(st.dik = key_by_name(what, &st.vk))) {
            fprintf(stderr, "--keys: unknown key \"%s\"\n", what);
            exit(1);
        }
        g_steps[g_nsteps++] = st;
    }
    g_scripted = 1;
}

static DWORD WINAPI keys_thread(LPVOID unused) {
    (void)unused;
    DWORD t0 = GetTickCount();
    for (int i = 0; i < g_nsteps; i++) {
        step_t* st = &g_steps[i];
        if (st->on[0]) {
            if (!st->x) { lstrcpynA(g_wait_file, st->on, sizeof g_wait_file); st->x = 1; }
            WaitForSingleObject(g_file_seen, INFINITE);   /* armed here, or by the step before it */
            t0 = GetTickCount();
            printf("[keys] %s opened: times count from here\n", st->on);
            continue;
        }
        /* The next wait listens from now: a key can open the screen it waits for. */
        for (int j = i + 1; j < g_nsteps; j++)
            if (g_steps[j].on[0]) {
                if (!g_steps[j].x) { lstrcpynA(g_wait_file, g_steps[j].on, sizeof g_wait_file); g_steps[j].x = 1; }
                break;
            }
        DWORD at = t0 + st->at, now = GetTickCount();
        if ((int)(at - now) > 0) Sleep(at - now);
        if (st->shot[0]) { softdd_shot(st->shot); continue; }
        if (st->move >= 2) {   /* the virtual joystick (flight.c) */
            static int sx, sy, fire;
            if (st->move == 2) sx = st->x, sy = st->y; else fire = st->click;
            flight_script(sx, sy, fire);
            printf("[keys] %.1fs stick %d,%d fire %d\n", st->at / 1000.0, sx, sy, fire);
            continue;
        }
        HWND w = g_game_wnd;
        if (st->move) {
            g_cur_x = st->x, g_cur_y = st->y;
            if (w) PostMessageA(w, WM_MOUSEMOVE, g_button_until - GetTickCount() < 3600000 ? MK_LBUTTON : 0, MAKELPARAM(st->x, st->y));
            if (st->click == 2) {   /* held until a release step */
                g_button_until = GetTickCount() + 3600000;
                if (w) PostMessageA(w, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(st->x, st->y));
            } else if (st->click == 3) {
                g_button_until = GetTickCount();
                if (w) PostMessageA(w, WM_LBUTTONUP, 0, MAKELPARAM(st->x, st->y));
            } else if (st->click) {
                g_button_until = GetTickCount() + 150;
                if (w) PostMessageA(w, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(st->x, st->y));
                Sleep(150);
                if (w) PostMessageA(w, WM_LBUTTONUP, 0, MAKELPARAM(st->x, st->y));
            }
            printf("[keys] %.1fs %s %d,%d\n", st->at / 1000.0, st->click == 1 ? "click" : st->click == 2 ? "press" : st->click == 3 ? "release" : "move", st->x, st->y);
        } else {
            g_key_until[st->dik] = g_vk_until[st->vk & 0xFF] = GetTickCount() + 150;
            evq_push(st->dik, 0x80);
            UINT sc = st->dik & 0x7F;
            if (w) PostMessageA(w, WM_KEYDOWN, st->vk, 1 | (sc << 16));
            Sleep(150);
            if (w) PostMessageA(w, WM_KEYUP, st->vk, 1 | (sc << 16) | 0xC0000000u);
            evq_push(st->dik, 0);
            printf("[keys] %.1fs key %02X\n", st->at / 1000.0, st->dik);
        }
    }
    return 0;
}

/* Posted key messages do not change the thread's key state, which the game
 * reads too: the script's held keys are added (and, scripted, are all of it). */
static void shim_GetKeyboardState(void) {
    uint8_t* b = (uint8_t*)(uintptr_t)ARG(0);
    BOOL r = TRUE;
    if (g_scripted) memset(b, 0, 256);
    else r = GetKeyboardState(b);
    DWORD now = GetTickCount();
    for (int i = 0; i < 256; i++)
        if ((int)(g_vk_until[i] - now) > 0) b[i] |= 0x80;
    g_eax = r;
    g_esp += 4 + 1 * 4;
}

/* The cursor, in game pixels: the window's client area is the 640x480 mode
 * (softdd sizes it). Scripted, it is wherever the script put it. */
static void shim_GetCursorPos(void) {
    POINT* pt = (POINT*)(uintptr_t)ARG(0);
    if (g_scripted || !g_game_wnd) { pt->x = g_cur_x; pt->y = g_cur_y; }
    else { GetCursorPos(pt); ScreenToClient(g_game_wnd, pt); gpu_to_game(pt); }
    g_eax = TRUE;
    g_esp += 4 + 1 * 4;
}
static void shim_SetCursorPos(void) {
    POINT pt = { (LONG)ARG(0), (LONG)ARG(1) };
    g_cur_x = pt.x, g_cur_y = pt.y;
    if (!g_scripted && g_game_wnd && GetForegroundWindow() == g_game_wnd) {
        gpu_from_game(&pt);
        ClientToScreen(g_game_wnd, &pt);
        SetCursorPos(pt.x, pt.y);
    }
    g_eax = TRUE;
    g_esp += 4 + 2 * 4;
}

/* The game takes its devices exclusive and foreground, and Acquire fails
 * while another window is in front: devices are made background,
 * non-exclusive. IDirectInput::CreateDevice is slot 3, the device's
 * SetCooperativeLevel 13 (Crazy Taxi's hooks). */
static void* vt_hook(void** vt, int n, void* fn) {
    DWORD old;
    void* was = vt[n];
    VirtualProtect(&vt[n], sizeof vt[n], PAGE_READWRITE, &old);
    vt[n] = fn;
    VirtualProtect(&vt[n], sizeof vt[n], old, &old);
    return was;
}
typedef HRESULT (WINAPI *coop_t)(void*, HWND, DWORD);
typedef HRESULT (WINAPI *di_create_dev_t)(void*, const GUID*, void**, void*);
static coop_t g_coop;
static di_create_dev_t g_di_create_dev;
static HRESULT WINAPI hook_SetCooperativeLevel(void* dev, HWND w, DWORD flags) {
    if (!g_fullscreen) flags = 0x8 | 0x2;   /* DISCL_BACKGROUND | DISCL_NONEXCLUSIVE */
    return g_coop(dev, w, flags);
}
/* GetDeviceState (slot 9): the keyboard's 256 bytes and the mouse's buttons
 * get the script's; scripted, the real devices are not read at all. */
typedef HRESULT (WINAPI *state_t)(void*, DWORD, void*);
static state_t g_state;
static HRESULT WINAPI hook_GetDeviceState(void* dev, DWORD n, void* data) {
    HRESULT hr = g_state(dev, n, data);
    { static int seen[64]; if (n < 64 && !seen[n]++) printf("[di] GetDeviceState %lu bytes -> %08lX\n", n, hr); }
    uint8_t* b = (uint8_t*)data;
    DWORD now = GetTickCount();
    if (g_scripted && hr == 0) memset(data, 0, n);
    if (n == 256) {
        for (int i = 0; i < 256; i++)
            if ((int)(g_key_until[i] - now) > 0) b[i] = 0x80;
        if (g_scripted) hr = 0;
    } else if (n == 16 || n == 20) {          /* DIMOUSESTATE(2): lX lY lZ, buttons */
        if ((int)(g_button_until - now) > 0) b[12] = 0x80;
        if (g_scripted) hr = 0;
    }
    return hr;
}

typedef HRESULT (WINAPI *data_t)(void*, DWORD, void*, DWORD*, DWORD);
static data_t g_data;
static void* g_keyboard;   /* the keyboard device, for its buffered reads */
static HRESULT WINAPI hook_GetDeviceData(void* dev, DWORD size, void* od, DWORD* n, DWORD flags) {
    static int once;
    static DWORD seq = 0x10000;
    DWORD room = n ? *n : 0;
    HRESULT hr = g_data(dev, size, od, n, flags);
    if (!once++) printf("[di] GetDeviceData %lu-byte records -> %08lX\n", size, hr);
    if (g_scripted && n) { *n = 0; hr = 0; }
    if (dev == g_keyboard && n && od && size >= 16 && !g_scripted) {   /* F10-F12 are the host's */
        DWORD k = 0;
        for (DWORD i = 0; i < *n; i++) {
            DWORD ofs = *(DWORD*)((uint8_t*)od + i * size);
            if (ofs == 0x44 || ofs == 0x57 || ofs == 0x58) continue;
            if (k != i) memmove((uint8_t*)od + k * size, (uint8_t*)od + i * size, size);
            k++;
        }
        *n = k;
    }
    /* The script's key events, after what the device had (DIDEVICEOBJECTDATA:
     * offset, data, time, sequence). Only removed when they are read. */
    if (dev == g_keyboard && n && od && size >= 16) {   /* a peek (DIGDD_PEEK) leaves them queued */
        EnterCriticalSection(&g_evq_lock);
        int k = 0;
        while (k < g_evq_n && *n < room) {
            /* A key from a screen that never read the buffer (XWA's front end)
             * is stale: it would open the in-flight menu at launch. */
            if (GetTickCount() - g_evq[k].t > 1000) { k++; continue; }
            DWORD* r = (DWORD*)((uint8_t*)od + *n * size);
            r[0] = g_evq[k].ofs; r[1] = g_evq[k].data; r[2] = GetTickCount(); r[3] = seq++;
            (*n)++, k++;
        }
        if (!(flags & 1)) { memmove(g_evq, g_evq + k, (g_evq_n - k) * sizeof g_evq[0]); g_evq_n -= k; }
        LeaveCriticalSection(&g_evq_lock);
    }
    return hr;
}

static HRESULT WINAPI hook_DI_CreateDevice(void* di, const GUID* g, void** out, void* outer) {
    HRESULT hr = g_di_create_dev(di, g, out, outer);
    if (hr == 0 && *out) {
        void** vt = **(void****)out;
        if (vt[13] != (void*)hook_SetCooperativeLevel) g_coop = (coop_t)vt_hook(vt, 13, hook_SetCooperativeLevel);
        if (vt[9] != (void*)hook_GetDeviceState) g_state = (state_t)vt_hook(vt, 9, hook_GetDeviceState);
        if (vt[10] != (void*)hook_GetDeviceData) g_data = (data_t)vt_hook(vt, 10, hook_GetDeviceData);
        printf("[di] CreateDevice {%08lX}\n", g->Data1);
        if (g->Data1 == 0x6F1D2B61u) g_keyboard = *out;   /* GUID_SysKeyboard */
    }
    return hr;
}

static void shim_DirectInputCreateA(void) {
    typedef HRESULT (WINAPI *create_t)(HINSTANCE, DWORD, void**, void*);
    static create_t create;
    if (!create) create = (create_t)GetProcAddress(LoadLibraryA("dinput.dll"), "DirectInputCreateA");
    uint32_t ver = ARG(1), out = ARG(2), outer = ARG(3);
    HRESULT hr;
    UNLOCKED(hr = create(GetModuleHandleA(NULL), ver, (void**)(uintptr_t)out, (void*)(uintptr_t)outer));
    printf("[host] DirectInputCreateA(0x%X) -> %08lX\n", ver, hr);
    if (hr == 0 && MEM32(out)) {
        void** vt = **(void****)(uintptr_t)out;
        if (vt[3] != (void*)hook_DI_CreateDevice) g_di_create_dev = (di_create_dev_t)vt_hook(vt, 3, hook_DI_CreateDevice);
    }
    g_eax = (uint32_t)hr;
    g_esp += 4 + 4 * 4;
}

/* ---- sound: the real DirectSound and MUSIC.dll, counted (sound.c) ---- */
static void shim_DirectSoundCreate(void) {
    typedef HRESULT (WINAPI *create_t)(const GUID*, void**, void*);
    static create_t create;
    if (!create) create = (create_t)GetProcAddress(LoadLibraryA("dsound.dll"), "DirectSoundCreate");
    void** out = (void**)(uintptr_t)ARG(1);
    HRESULT hr;
    UNLOCKED(hr = create((const GUID*)(uintptr_t)ARG(0), out, (void*)(uintptr_t)ARG(2)));
    printf("[sound] DirectSoundCreate -> %08lX\n", hr);
    if (hr == 0 && out && *out) sound_watch(*out);
    g_eax = (uint32_t)hr;
    g_esp += 4 + 3 * 4;
}

/* ---- DirectPlay: the host's own (dplay.c), not Windows' ---- */
static void shim_DirectPlayCreate(void) {   /* (sp guid, IDirectPlay**, outer) */
    g_eax = (uint32_t)dplay_create((void**)(uintptr_t)ARG(1));
    g_esp += 4 + 3 * 4;
}
static void shim_DirectPlayLobbyCreateA(void) {   /* (sp guid, IDirectPlayLobbyA**, outer, data, size) */
    g_eax = (uint32_t)dplay_lobby_create((void**)(uintptr_t)ARG(1));
    g_esp += 4 + 5 * 4;
}

/* The CD music: the host's own player (music.c), not the Steam edition's
 * WIN32.dll, whose player thread raced the game's stop and play. */
static void shim_mciSendCommandA(void) {
    MCIERROR r = music_mci(ARG(0), ARG(1), ARG(2), ARG(3));
    if (g_sound_log) printf("[sound] mci %u msg %04X flags %08X -> %u\n", ARG(0), ARG(1), ARG(2), (unsigned)r);
    g_eax = r;
    g_esp += 4 + 4 * 4;
}
static void shim_auxSetVolume(void) {   /* the music volume, for the CD */
    music_volume(ARG(1));
    g_eax = 0;
    g_esp += 4 + 2 * 4;
}

static DWORD WINAPI sound_thread(LPVOID unused) {
    (void)unused;
    for (;;) { Sleep(5000); sound_report(); }
}

/* LoadIconA/LoadCursorA with the game's own instance: Windows would read the
 * resource out of the mapped image, which is not laid out as a loaded module
 * (TIE Fighter's cursor faulted in DefWindowProc). They come from the game's
 * executable on disk, loaded as data; the standard ones if that fails. */
static HMODULE game_resources(void) {
    static HMODULE h;
    if (!h) h = LoadLibraryExA(g_guest_exe, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    return h;
}
static void shim_LoadIconA(void) {
    HINSTANCE inst = (HINSTANCE)(uintptr_t)ARG(0);
    LPCSTR name = (LPCSTR)(uintptr_t)ARG(1);
    HICON h = NULL;
    if ((uint32_t)(uintptr_t)inst == IMAGE_BASE) { if (game_resources()) h = LoadIconA(game_resources(), name); if (!h) h = LoadIconA(NULL, IDI_APPLICATION); }
    else h = LoadIconA(inst, name);
    g_eax = (uint32_t)(uintptr_t)h;
    g_esp += 4 + 2 * 4;
}
static void shim_LoadCursorA(void) {
    HINSTANCE inst = (HINSTANCE)(uintptr_t)ARG(0);
    LPCSTR name = (LPCSTR)(uintptr_t)ARG(1);
    HCURSOR h = NULL;
    if ((uint32_t)(uintptr_t)inst == IMAGE_BASE) { if (game_resources()) h = LoadCursorA(game_resources(), name); if (!h) h = LoadCursorA(NULL, IDC_ARROW); }
    else h = LoadCursorA(inst, name);
    g_eax = (uint32_t)(uintptr_t)h;
    g_esp += 4 + 2 * 4;
}

static native32_shim_t g_shims[] = {
    { "SuspendThread", shim_SuspendThread },
    { "LoadIconA", shim_LoadIconA },
    { "LoadCursorA", shim_LoadCursorA },
    { "DirectSoundCreate", shim_DirectSoundCreate },
    { "mciSendCommandA", shim_mciSendCommandA },
    { "auxSetVolume", shim_auxSetVolume },
    { "GetCursorPos", shim_GetCursorPos },
    { "GetKeyboardState", shim_GetKeyboardState },
    { "SetCursorPos", shim_SetCursorPos },
    { "DirectDrawCreate", shim_DirectDrawCreate },
    { "DirectInputCreateA", shim_DirectInputCreateA },
    { "joyGetNumDevs", shim_joyGetNumDevs },
    { "joyGetDevCapsA", shim_joyGetDevCapsA },
    { "joyGetPosEx", shim_joyGetPosEx },
    { "CloseWindow", shim_CloseWindow },
    { "DPLAYX.dll#1", shim_DirectPlayCreate },
    { "DPLAYX.dll#4", shim_DirectPlayLobbyCreateA },
    { "GetForegroundWindow", shim_GetForegroundWindow },
    { "ShowWindow", shim_ShowWindow },
    { "CreateWindowExA", shim_CreateWindowExA },
    { "RaiseException", shim_RaiseException },
    { "GetLogicalDriveStringsA", shim_GetLogicalDriveStringsA },
    { "GetDriveTypeA", shim_GetDriveTypeA },
    { "GetLogicalDrives", shim_GetLogicalDrives },
    { "GetVolumeInformationA", shim_GetVolumeInformationA },
    { "CreateFileA", shim_CreateFileA },
    { "MessageBoxA", shim_MessageBoxA },
    { "OutputDebugStringA", shim_OutputDebugStringA },
    { "ExitProcess", shim_ExitProcess },
    { "GetModuleHandleA", shim_GetModuleHandleA },
    { "GetModuleFileNameA", shim_GetModuleFileNameA },
    { "GetCommandLineA", shim_GetCommandLineA },
};

/* ---- muted by default -------------------------------------------------------
 * Every run is silent until sound is being tested (--sound). */
static const GUID kCLSID_MMDeviceEnumerator =
    { 0xBCDE0395, 0xE52F, 0x467C, { 0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E } };
static const GUID kIID_IMMDeviceEnumerator =
    { 0xA95664D2, 0x9614, 0x4F35, { 0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6 } };
static const GUID kIID_IAudioSessionManager =
    { 0xBFA971F1, 0x4D5E, 0x40BB, { 0x93, 0x5E, 0x96, 0x70, 0x39, 0xBF, 0xBE, 0xE4 } };

/* 1: muted; 2: there is no audio device; 0: failed. */
static int mute_process(void) {
    IMMDeviceEnumerator* en = NULL;
    IMMDevice* dev = NULL;
    IAudioSessionManager* mgr = NULL;
    ISimpleAudioVolume* vol = NULL;
    HRESULT hr = CoCreateInstance(&kCLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
                                  &kIID_IMMDeviceEnumerator, (void**)&en);
    if (SUCCEEDED(hr)) hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(en, eRender, eConsole, &dev);
    if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND)) { IMMDeviceEnumerator_Release(en); return 2; }
    if (SUCCEEDED(hr)) hr = IMMDevice_Activate(dev, &kIID_IAudioSessionManager, CLSCTX_ALL, NULL, (void**)&mgr);
    if (SUCCEEDED(hr)) hr = IAudioSessionManager_GetSimpleAudioVolume(mgr, &GUID_NULL, FALSE, &vol);
    if (SUCCEEDED(hr)) hr = ISimpleAudioVolume_SetMute(vol, TRUE, NULL);
    if (vol) ISimpleAudioVolume_Release(vol);
    if (mgr) IAudioSessionManager_Release(mgr);
    if (dev) IMMDevice_Release(dev);
    if (en) IMMDeviceEnumerator_Release(en);
    return SUCCEEDED(hr);
}

/* ---- reports ---------------------------------------------------------------- */
recomp_func_t recomp_lookup_manual(uint32_t va) {
    (void)va;
    return NULL;
}

void recomp_not_lifted(uint32_t va) {
    fprintf(stderr, "\n[not-lifted] sub_%08X  (called from 0x%08X)\n", va, g_cur_func);
    recomp_dump_trace("not-lifted");
    native32_dump_icalls(8);
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 2);
}

/* Added after native32's own handler, so callbacks are resolved first and only
 * real faults get here. */
static char g_crash_buf[4096];
static int g_crash_len;
static void crash_emit(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf(g_crash_buf + g_crash_len, sizeof g_crash_buf - 1 - g_crash_len, fmt, ap);
    va_end(ap);
    if (n > 0) g_crash_len += n;
}

static LONG CALLBACK crash(EXCEPTION_POINTERS* ep) {
    static volatile LONG once;
    EXCEPTION_RECORD* r = ep->ExceptionRecord;
    if ((r->ExceptionCode & 0xF0000000u) != 0xC0000000u) return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedExchange(&once, 1)) TerminateProcess(GetCurrentProcess(), 3);
    crash_emit("\n=== fault 0x%08lX at 0x%p, thread %lu ===\n", r->ExceptionCode,
               r->ExceptionAddress, GetCurrentThreadId());
    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && r->NumberParameters >= 2) {
        ULONG_PTR op = r->ExceptionInformation[0];
        uint32_t at = (uint32_t)r->ExceptionInformation[1];
        crash_emit("  %s of 0x%08X%s\n", op == 0 ? "read" : op == 1 ? "write" : "execute", at,
                   native32_in_guest(at) ? " (inside the guest image)" : at < 0x10000 ? " (null/low)" : "");
    }
    {   HMODULE mod = NULL;
        char mn[MAX_PATH] = "?";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)r->ExceptionAddress, &mod) && mod) {
            GetModuleFileNameA(mod, mn, sizeof mn);
            crash_emit("  at %s+0x%X\n", mn, (unsigned)((uintptr_t)r->ExceptionAddress - (uintptr_t)mod));
        }
        if (r->NumberParameters >= 2) {
            MEMORY_BASIC_INFORMATION mb;
            void* at = (void*)r->ExceptionInformation[1];
            if (VirtualQuery(at, &mb, sizeof mb))
                crash_emit("  that address: region %p+%lX alloc %p state %lX protect %lX type %lX\n", mb.BaseAddress,
                           (unsigned long)mb.RegionSize, mb.AllocationBase, mb.State, mb.Protect, mb.Type);
        }
        /* the native stack: return addresses found on it, by module */
        const uint32_t* sp = (const uint32_t*)(uintptr_t)ep->ContextRecord->Esp;
        int shown = 0;
        for (int i = 0; i < 2048 && shown < 16; i++) {
            if (IsBadReadPtr(sp + i, 4)) break;
            uint32_t v = sp[i];
            HMODULE m2 = NULL;
            char n2[MAX_PATH];
            if (v > 0x10000 && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                                  (LPCSTR)(uintptr_t)v, &m2) && m2 && GetModuleFileNameA(m2, n2, sizeof n2)) {
                const char* b = strrchr(n2, '\\');
                crash_emit("    [sp+%03X] %s+0x%X\n", i * 4, b ? b + 1 : n2, (unsigned)(v - (uint32_t)(uintptr_t)m2));
                shown++;
            }
        }
    }
    crash_emit("  in lifted sub_%08X, last native call %s\n", g_cur_func, g_cur_import);
    crash_emit("  eax=%08X ecx=%08X edx=%08X ebx=%08X esp=%08X ebp=%08X esi=%08X edi=%08X\n",
               g_eax, g_ecx, g_edx, g_ebx, g_esp, g_ebp, g_esi, g_edi);
    crash_emit("last indirect calls (newest first):\n");
    for (int i = 1; i <= 12 && i <= (int)g_icall_trace_idx; i++) {
        uint32_t k = (g_icall_trace_idx - i) & (ICALL_TRACE_SIZE - 1);
        const char* nm = native32_name(g_icall_trace[k]);
        crash_emit("  0x%08X  from 0x%08X  %s\n", g_icall_trace[k], g_icall_from[k], nm ? nm : "");
    }
    DWORD w;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), g_crash_buf, (DWORD)g_crash_len, &w, NULL);
    recomp_trace_flush();
    TerminateProcess(GetCurrentProcess(), 3);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* --sample: the lifted function running, ten times a second, for a while. */
static int g_sample;
static DWORD WINAPI sampler(LPVOID unused) {
    (void)unused;
    for (int i = 0; i < 400; i++) {
        Sleep(100);
        printf("[sample] %5.1fs sub_%08X %s\n", i / 10.0, g_cur_func, g_cur_import ? g_cur_import : "");
    }
    return 0;
}

static DWORD WINAPI watchdog(LPVOID unused) {
    (void)unused;
    Sleep(g_watchdog_s * 1000);
    fprintf(stderr, "\n[watchdog] %lu s: in sub_%08X, last native call %s, %u indirect calls\n",
            g_watchdog_s, g_cur_func, g_cur_import, g_icall_count);
    native32_dump_icalls(8);
    recomp_trace_flush();
    fflush(stdout);
    fflush(stderr);
    TerminateProcess(GetCurrentProcess(), 4);
    return 0;
}

int main(int argc, char** argv) {
    const char* exe = "work\\XWA.EXE";
    const char* game = "game";
    char exe_full[MAX_PATH], game_full[MAX_PATH], guest_args[512] = "";
    int run = 0, sound = 0;
    setvbuf(stdout, NULL, _IONBF, 0);   /* a fault ends the run with TerminateProcess */
    settings_load();   /* xwa.ini; the switches below override it */
    for (int i = 1; i < argc; i++) {
        int n = recomp_trace_arg(argc, argv, i);
        if (n) { i += n - 1; continue; }
        if (!strcmp(argv[i], "--run")) run = 1;
        else if (!strcmp(argv[i], "--sound")) sound = 1;
        else if (!strcmp(argv[i], "--sound-log")) g_sound_log = 1;
        else if (!strcmp(argv[i], "--headless")) g_headless = softdd_headless = 1;
        else if (!strcmp(argv[i], "--fullscreen")) g_gpu.fullscreen = 1;   /* borderless (F11) */
        else if (!strcmp(argv[i], "--windowed")) g_gpu.fullscreen = 0;
        else if (!strcmp(argv[i], "--software-3d")) g_hw3d = 0;
        else if (!strcmp(argv[i], "--dump-textures")) g_gpu.dump_textures = 1;
        else if (!strcmp(argv[i], "--scale") && i + 1 < argc) softdd_scale = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sample")) g_sample = 1;
        else if (!strcmp(argv[i], "--shot") && i + 2 < argc && g_shots < 16) {
            g_shot_s[g_shots] = strtoul(argv[++i], NULL, 0);
            GetFullPathNameA(argv[++i], MAX_PATH, g_shot_file[g_shots++], NULL);
        }
        else if (!strcmp(argv[i], "--exe") && i + 1 < argc) exe = argv[++i];
        else if (!strcmp(argv[i], "--game") && i + 1 < argc) game = argv[++i];
        else if (!strcmp(argv[i], "--args") && i + 1 < argc) _snprintf(guest_args, sizeof guest_args - 1, " %s", argv[++i]);
        else if (!strcmp(argv[i], "--keys") && i + 1 < argc) parse_keys(argv[++i]);
        else if (!strcmp(argv[i], "--watchdog") && i + 1 < argc) g_watchdog_s = strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--callbacks")) native32_trace_callbacks = 1;
        else if (!strcmp(argv[i], "--native-trace")) native32_trace_native = 1;
        else {
            printf("usage: xwarecomp [--run] [--headless] [--sound] [--exe work\\XWA.EXE] [--game game]\n"
                   "             [--args \"<game switches>\"] [--watchdog S] [--callbacks] [--native-trace]\n");
            recomp_trace_help();
            return argv[i][1] == 'h' || argv[i][2] == 'h' ? 0 : 1;
        }
    }
    GetFullPathNameA(exe, MAX_PATH, exe_full, NULL);
    GetFullPathNameA(game, MAX_PATH, game_full, NULL);
    cd_pick(game_full);
    _snprintf(g_guest_exe, sizeof g_guest_exe - 1, "%s\\XWINGALLIANCE.EXE", game_full);
    _snprintf(g_guest_cmdline, sizeof g_guest_cmdline - 1, "\"%s\"%s", g_guest_exe, guest_args);

    native32_init();
    AddVectoredExceptionHandler(0, crash);
    printf("X-Wing Alliance recomp host\n  lifted functions in dispatch: %u\n", recomp_dispatch_count);

    uint32_t span = native32_map(exe_full, IMAGE_BASE);
    if (!span) { fprintf(stderr, "cannot map %s at 0x%08X\n", exe_full, IMAGE_BASE); return 1; }
    printf("  mapped %s: 0x%08X-0x%08X\n", exe, IMAGE_BASE, IMAGE_BASE + span);
    /* MUSIC.dll comes from the game folder. */
    SetDllDirectoryA(game_full);
    if (native32_bind(IMAGE_BASE, g_shims, (int)(sizeof g_shims / sizeof g_shims[0]))) return 1;
    printf("  guest command line %s\n", g_guest_cmdline);
    if (!run) {
        printf("\n(dry run: image mapped and bound; --run enters 0x%08X)\n", tf_entry_va);
        return 0;
    }
    /* The game opens its data relative to its working directory. */
    if (!SetCurrentDirectoryA(game_full)) { fprintf(stderr, "cannot enter %s\n", game_full); return 1; }
    settings_apply_prefs();
    CoInitialize(NULL);
    /* Playing: sound on. Test runs (a script or a watchdog) are muted unless --sound. */
    if (!g_nsteps && !g_watchdog_s) sound = 1;
    int m = sound ? 1 : mute_process();
    if (!m) {
        fprintf(stderr, "cannot mute the process audio session; pass --sound to run with sound\n");
        return 1;
    }
    printf("  audio: %s\n", sound ? "on" : m == 2 ? "muted (no audio device)" : "muted (a test run; --sound to hear it)");
    if (g_watchdog_s) CloseHandle(CreateThread(NULL, 0, watchdog, NULL, 0, NULL));
    if (g_sample) CloseHandle(CreateThread(NULL, 0, sampler, NULL, 0, NULL));
    if (g_shots) CloseHandle(CreateThread(NULL, 0, shot_thread, NULL, 0, NULL));
    InitializeCriticalSection(&g_evq_lock);
    g_file_seen = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (g_sound_log) CloseHandle(CreateThread(NULL, 0, sound_thread, NULL, 0, NULL));
    if (g_nsteps) CloseHandle(CreateThread(NULL, 0, keys_thread, NULL, 0, NULL));
    printf("  entering 0x%08X\n\n", tf_entry_va);
    native32_call_guest(tf_entry_va, 0, NULL);
    printf("\nentry returned eax=%08X\n", g_eax);
    return (int)g_eax;
}

