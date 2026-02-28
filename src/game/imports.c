/* Auto-generated import bridges - DO NOT EDIT */
/*
 * Each bridge reads arguments from the simulated stack,
 * calls the real Win32 API, and returns the result in g_eax.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <shellapi.h>
#include <stdio.h>
#include "recomp/recomp_types.h"

/* Generic stdcall function pointer types by arg count */
typedef uint32_t (__stdcall *STDFN0)(void);
typedef uint32_t (__stdcall *STDFN1)(uint32_t);
typedef uint32_t (__stdcall *STDFN2)(uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN3)(uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN4)(uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN5)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN6)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN7)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN8)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN9)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN10)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN11)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN12)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN13)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN14)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

/* ======== ADVAPI32.dll ======== */

static void bridge_RegSetValueExA_005A9000(void) { /* ADVAPI32.dll:RegSetValueExA (6 args) */
    static STDFN6 fn = NULL;
    if (!fn) fn = (STDFN6)GetProcAddress(GetModuleHandleA("ADVAPI32.dll"), "RegSetValueExA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5);
    g_esp += 28;
}

static void bridge_RegOpenKeyExA_005A9004(void) { /* ADVAPI32.dll:RegOpenKeyExA (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("ADVAPI32.dll"), "RegOpenKeyExA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_RegQueryValueExA_005A9008(void) { /* ADVAPI32.dll:RegQueryValueExA (6 args) */
    static STDFN6 fn = NULL;
    if (!fn) fn = (STDFN6)GetProcAddress(GetModuleHandleA("ADVAPI32.dll"), "RegQueryValueExA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5);
    g_esp += 28;
}

static void bridge_RegCloseKey_005A900C(void) { /* ADVAPI32.dll:RegCloseKey (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("ADVAPI32.dll"), "RegCloseKey");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

/* ======== DDRAW.dll ======== */

static void bridge_DirectDrawEnumerateExA_005A9014(void) { /* DDRAW.dll:DirectDrawEnumerateExA */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: DDRAW.dll:DirectDrawEnumerateExA\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

static void bridge_DirectDrawCreate_005A9018(void) { /* DDRAW.dll:DirectDrawCreate */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: DDRAW.dll:DirectDrawCreate\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

/* ======== DINPUT.dll ======== */

static void bridge_DirectInputCreateA_005A9020(void) { /* DINPUT.dll:DirectInputCreateA */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: DINPUT.dll:DirectInputCreateA\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

/* ======== DPLAYX.dll ======== */

static void bridge_ordinal_1_005A9028(void) { /* DPLAYX.dll:ordinal_1 */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: DPLAYX.dll:ordinal_1\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

/* ======== DSOUND.dll ======== */

static void bridge_ordinal_1_005A9030(void) { /* DSOUND.dll:ordinal_1 */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: DSOUND.dll:ordinal_1\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

/* ======== GDI32.dll ======== */

static void bridge_SetMapMode_005A9038(void) { /* GDI32.dll:SetMapMode (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("GDI32.dll"), "SetMapMode");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_ExtTextOutA_005A903C(void) { /* GDI32.dll:ExtTextOutA (8 args) */
    static STDFN8 fn = NULL;
    if (!fn) fn = (STDFN8)GetProcAddress(GetModuleHandleA("GDI32.dll"), "ExtTextOutA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    uint32_t a6 = MEM32(g_esp + 28);
    uint32_t a7 = MEM32(g_esp + 32);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5, a6, a7);
    g_esp += 36;
}

static void bridge_Rectangle_005A9040(void) { /* GDI32.dll:Rectangle (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("GDI32.dll"), "Rectangle");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_GetStockObject_005A9044(void) { /* GDI32.dll:GetStockObject (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("GDI32.dll"), "GetStockObject");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_SetBkMode_005A9048(void) { /* GDI32.dll:SetBkMode (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("GDI32.dll"), "SetBkMode");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_SetBkColor_005A904C(void) { /* GDI32.dll:SetBkColor (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("GDI32.dll"), "SetBkColor");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_SetTextColor_005A9050(void) { /* GDI32.dll:SetTextColor (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("GDI32.dll"), "SetTextColor");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_CreateDCA_005A9054(void) { /* GDI32.dll:CreateDCA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("GDI32.dll"), "CreateDCA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_GetTextExtentPoint32A_005A9058(void) { /* GDI32.dll:GetTextExtentPoint32A (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("GDI32.dll"), "GetTextExtentPoint32A");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_SelectObject_005A905C(void) { /* GDI32.dll:SelectObject (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("GDI32.dll"), "SelectObject");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_CreateFontA_005A9060(void) { /* GDI32.dll:CreateFontA (14 args) */
    static STDFN14 fn = NULL;
    if (!fn) fn = (STDFN14)GetProcAddress(GetModuleHandleA("GDI32.dll"), "CreateFontA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    uint32_t a6 = MEM32(g_esp + 28);
    uint32_t a7 = MEM32(g_esp + 32);
    uint32_t a8 = MEM32(g_esp + 36);
    uint32_t a9 = MEM32(g_esp + 40);
    uint32_t a10 = MEM32(g_esp + 44);
    uint32_t a11 = MEM32(g_esp + 48);
    uint32_t a12 = MEM32(g_esp + 52);
    uint32_t a13 = MEM32(g_esp + 56);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
    g_esp += 60;
}

static void bridge_DeleteObject_005A9064(void) { /* GDI32.dll:DeleteObject (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("GDI32.dll"), "DeleteObject");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_SetTextCharacterExtra_005A9068(void) { /* GDI32.dll:SetTextCharacterExtra (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("GDI32.dll"), "SetTextCharacterExtra");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_DeleteDC_005A906C(void) { /* GDI32.dll:DeleteDC (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("GDI32.dll"), "DeleteDC");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

/* ======== KERNEL32.dll ======== */

static void bridge_Sleep_005A9074(void) { /* KERNEL32.dll:Sleep (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "Sleep");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GlobalUnlock_005A9078(void) { /* KERNEL32.dll:GlobalUnlock (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GlobalUnlock");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GlobalReAlloc_005A907C(void) { /* KERNEL32.dll:GlobalReAlloc (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GlobalReAlloc");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge__hread_005A9080(void) { /* KERNEL32.dll:_hread (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "_hread");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge__llseek_005A9084(void) { /* KERNEL32.dll:_llseek (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "_llseek");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_GlobalLock_005A9088(void) { /* KERNEL32.dll:GlobalLock (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GlobalLock");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GlobalAlloc_005A908C(void) { /* KERNEL32.dll:GlobalAlloc (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GlobalAlloc");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_QueryPerformanceCounter_005A9090(void) { /* KERNEL32.dll:QueryPerformanceCounter (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "QueryPerformanceCounter");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_QueryPerformanceFrequency_005A9094(void) { /* KERNEL32.dll:QueryPerformanceFrequency (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "QueryPerformanceFrequency");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_CreateProcessA_005A9098(void) { /* KERNEL32.dll:CreateProcessA (10 args) */
    static STDFN10 fn = NULL;
    if (!fn) fn = (STDFN10)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CreateProcessA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    uint32_t a6 = MEM32(g_esp + 28);
    uint32_t a7 = MEM32(g_esp + 32);
    uint32_t a8 = MEM32(g_esp + 36);
    uint32_t a9 = MEM32(g_esp + 40);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    g_esp += 44;
}

static void bridge_GlobalFree_005A909C(void) { /* KERNEL32.dll:GlobalFree (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GlobalFree");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge__lopen_005A90A0(void) { /* KERNEL32.dll:_lopen (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "_lopen");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge__lread_005A90A4(void) { /* KERNEL32.dll:_lread (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "_lread");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge__lclose_005A90A8(void) { /* KERNEL32.dll:_lclose (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "_lclose");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_VirtualProtect_005A90AC(void) { /* KERNEL32.dll:VirtualProtect (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "VirtualProtect");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_GetLocalTime_005A90B0(void) { /* KERNEL32.dll:GetLocalTime (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetLocalTime");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_OutputDebugStringA_005A90B4(void) { /* KERNEL32.dll:OutputDebugStringA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "OutputDebugStringA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetCPInfo_005A90B8(void) { /* KERNEL32.dll:GetCPInfo (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetCPInfo");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_UnhandledExceptionFilter_005A90BC(void) { /* KERNEL32.dll:UnhandledExceptionFilter (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "UnhandledExceptionFilter");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetModuleFileNameA_005A90C0(void) { /* KERNEL32.dll:GetModuleFileNameA (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetModuleFileNameA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_GetFileType_005A90C4(void) { /* KERNEL32.dll:GetFileType (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetFileType");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_WideCharToMultiByte_005A90C8(void) { /* KERNEL32.dll:WideCharToMultiByte (8 args) */
    static STDFN8 fn = NULL;
    if (!fn) fn = (STDFN8)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "WideCharToMultiByte");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    uint32_t a6 = MEM32(g_esp + 28);
    uint32_t a7 = MEM32(g_esp + 32);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5, a6, a7);
    g_esp += 36;
}

static void bridge_LCMapStringA_005A90CC(void) { /* KERNEL32.dll:LCMapStringA (6 args) */
    static STDFN6 fn = NULL;
    if (!fn) fn = (STDFN6)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "LCMapStringA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5);
    g_esp += 28;
}

static void bridge_RaiseException_005A90D0(void) { /* KERNEL32.dll:RaiseException (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "RaiseException");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_GetLocaleInfoW_005A90D4(void) { /* KERNEL32.dll:GetLocaleInfoW (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetLocaleInfoW");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_GlobalMemoryStatus_005A90D8(void) { /* KERNEL32.dll:GlobalMemoryStatus (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GlobalMemoryStatus");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetDriveTypeA_005A90DC(void) { /* KERNEL32.dll:GetDriveTypeA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetDriveTypeA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetLogicalDriveStringsA_005A90E0(void) { /* KERNEL32.dll:GetLogicalDriveStringsA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetLogicalDriveStringsA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_TerminateProcess_005A90E4(void) { /* KERNEL32.dll:TerminateProcess (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "TerminateProcess");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_GetCurrentProcess_005A90E8(void) { /* KERNEL32.dll:GetCurrentProcess (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetCurrentProcess");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_ExitProcess_005A90EC(void) { /* KERNEL32.dll:ExitProcess (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "ExitProcess");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GlobalHandle_005A90F0(void) { /* KERNEL32.dll:GlobalHandle (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GlobalHandle");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_lstrlenA_005A90F4(void) { /* KERNEL32.dll:lstrlenA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "lstrlenA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetTickCount_005A90F8(void) { /* KERNEL32.dll:GetTickCount (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetTickCount");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_GetProcAddress_005A90FC(void) { /* KERNEL32.dll:GetProcAddress (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetProcAddress");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_GetModuleHandleA_005A9100(void) { /* KERNEL32.dll:GetModuleHandleA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetModuleHandleA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_lstrcpyA_005A9104(void) { /* KERNEL32.dll:lstrcpyA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "lstrcpyA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_FindNextFileA_005A9108(void) { /* KERNEL32.dll:FindNextFileA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "FindNextFileA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_FindClose_005A910C(void) { /* KERNEL32.dll:FindClose (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "FindClose");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_FindFirstFileA_005A9110(void) { /* KERNEL32.dll:FindFirstFileA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "FindFirstFileA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_LockResource_005A9114(void) { /* KERNEL32.dll:LockResource (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "LockResource");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_LoadResource_005A9118(void) { /* KERNEL32.dll:LoadResource (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "LoadResource");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_FindResourceA_005A911C(void) { /* KERNEL32.dll:FindResourceA (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "FindResourceA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_LeaveCriticalSection_005A9120(void) { /* KERNEL32.dll:LeaveCriticalSection (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "LeaveCriticalSection");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_EnterCriticalSection_005A9124(void) { /* KERNEL32.dll:EnterCriticalSection (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "EnterCriticalSection");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_InitializeCriticalSection_005A9128(void) { /* KERNEL32.dll:InitializeCriticalSection (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "InitializeCriticalSection");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_CloseHandle_005A912C(void) { /* KERNEL32.dll:CloseHandle (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CloseHandle");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_DeleteCriticalSection_005A9130(void) { /* KERNEL32.dll:DeleteCriticalSection (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "DeleteCriticalSection");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_InterlockedDecrement_005A9134(void) { /* KERNEL32.dll:InterlockedDecrement (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "InterlockedDecrement");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_InterlockedIncrement_005A9138(void) { /* KERNEL32.dll:InterlockedIncrement (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "InterlockedIncrement");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetLastError_005A913C(void) { /* KERNEL32.dll:GetLastError (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetLastError");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_DeleteFileA_005A9140(void) { /* KERNEL32.dll:DeleteFileA */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: KERNEL32.dll:DeleteFileA\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

static void bridge_MoveFileA_005A9144(void) { /* KERNEL32.dll:MoveFileA */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: KERNEL32.dll:MoveFileA\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

static void bridge_HeapAlloc_005A9148(void) { /* KERNEL32.dll:HeapAlloc (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "HeapAlloc");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_HeapReAlloc_005A914C(void) { /* KERNEL32.dll:HeapReAlloc (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "HeapReAlloc");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_HeapFree_005A9150(void) { /* KERNEL32.dll:HeapFree (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "HeapFree");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_GetStartupInfoA_005A9154(void) { /* KERNEL32.dll:GetStartupInfoA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetStartupInfoA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetCommandLineA_005A9158(void) { /* KERNEL32.dll:GetCommandLineA (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetCommandLineA");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_GetVersion_005A915C(void) { /* KERNEL32.dll:GetVersion (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetVersion");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_SetEnvironmentVariableA_005A9160(void) { /* KERNEL32.dll:SetEnvironmentVariableA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "SetEnvironmentVariableA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_GetCurrentDirectoryA_005A9164(void) { /* KERNEL32.dll:GetCurrentDirectoryA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetCurrentDirectoryA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_SetCurrentDirectoryA_005A9168(void) { /* KERNEL32.dll:SetCurrentDirectoryA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "SetCurrentDirectoryA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetFullPathNameA_005A916C(void) { /* KERNEL32.dll:GetFullPathNameA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetFullPathNameA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_MultiByteToWideChar_005A9170(void) { /* KERNEL32.dll:MultiByteToWideChar (6 args) */
    static STDFN6 fn = NULL;
    if (!fn) fn = (STDFN6)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "MultiByteToWideChar");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5);
    g_esp += 28;
}

static void bridge_GetStdHandle_005A9174(void) { /* KERNEL32.dll:GetStdHandle (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetStdHandle");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_LCMapStringW_005A9178(void) { /* KERNEL32.dll:LCMapStringW (6 args) */
    static STDFN6 fn = NULL;
    if (!fn) fn = (STDFN6)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "LCMapStringW");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5);
    g_esp += 28;
}

static void bridge_SetEndOfFile_005A917C(void) { /* KERNEL32.dll:SetEndOfFile (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "SetEndOfFile");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_IsValidLocale_005A9180(void) { /* KERNEL32.dll:IsValidLocale (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "IsValidLocale");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_IsValidCodePage_005A9184(void) { /* KERNEL32.dll:IsValidCodePage (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "IsValidCodePage");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetLocaleInfoA_005A9188(void) { /* KERNEL32.dll:GetLocaleInfoA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetLocaleInfoA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_EnumSystemLocalesA_005A918C(void) { /* KERNEL32.dll:EnumSystemLocalesA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "EnumSystemLocalesA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_GetUserDefaultLCID_005A9190(void) { /* KERNEL32.dll:GetUserDefaultLCID (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetUserDefaultLCID");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_GetVersionExA_005A9194(void) { /* KERNEL32.dll:GetVersionExA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetVersionExA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_SetFilePointer_005A9198(void) { /* KERNEL32.dll:SetFilePointer (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "SetFilePointer");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_ReadFile_005A919C(void) { /* KERNEL32.dll:ReadFile (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "ReadFile");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_WriteFile_005A91A0(void) { /* KERNEL32.dll:WriteFile (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "WriteFile");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_GetCurrentThreadId_005A91A4(void) { /* KERNEL32.dll:GetCurrentThreadId (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetCurrentThreadId");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_TlsSetValue_005A91A8(void) { /* KERNEL32.dll:TlsSetValue (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "TlsSetValue");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_TlsAlloc_005A91AC(void) { /* KERNEL32.dll:TlsAlloc (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "TlsAlloc");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_SetLastError_005A91B0(void) { /* KERNEL32.dll:SetLastError (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "SetLastError");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_TlsGetValue_005A91B4(void) { /* KERNEL32.dll:TlsGetValue (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "TlsGetValue");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_HeapSize_005A91B8(void) { /* KERNEL32.dll:HeapSize (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "HeapSize");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_SetHandleCount_005A91BC(void) { /* KERNEL32.dll:SetHandleCount (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "SetHandleCount");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_LoadLibraryA_005A91C0(void) { /* KERNEL32.dll:LoadLibraryA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "LoadLibraryA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetStringTypeA_005A91C4(void) { /* KERNEL32.dll:GetStringTypeA (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetStringTypeA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_GetStringTypeW_005A91C8(void) { /* KERNEL32.dll:GetStringTypeW (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetStringTypeW");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_FlushFileBuffers_005A91CC(void) { /* KERNEL32.dll:FlushFileBuffers (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "FlushFileBuffers");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_HeapDestroy_005A91D0(void) { /* KERNEL32.dll:HeapDestroy (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "HeapDestroy");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_HeapCreate_005A91D4(void) { /* KERNEL32.dll:HeapCreate (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "HeapCreate");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_VirtualFree_005A91D8(void) { /* KERNEL32.dll:VirtualFree (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "VirtualFree");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_VirtualAlloc_005A91DC(void) { /* KERNEL32.dll:VirtualAlloc (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "VirtualAlloc");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_FreeEnvironmentStringsA_005A91E0(void) { /* KERNEL32.dll:FreeEnvironmentStringsA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "FreeEnvironmentStringsA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_FreeEnvironmentStringsW_005A91E4(void) { /* KERNEL32.dll:FreeEnvironmentStringsW (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "FreeEnvironmentStringsW");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetEnvironmentStrings_005A91E8(void) { /* KERNEL32.dll:GetEnvironmentStrings (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetEnvironmentStrings");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_GetEnvironmentStringsW_005A91EC(void) { /* KERNEL32.dll:GetEnvironmentStringsW (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetEnvironmentStringsW");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_GetACP_005A91F0(void) { /* KERNEL32.dll:GetACP (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetACP");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_GetOEMCP_005A91F4(void) { /* KERNEL32.dll:GetOEMCP (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetOEMCP");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_RtlUnwind_005A91F8(void) { /* KERNEL32.dll:RtlUnwind (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "RtlUnwind");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_SetStdHandle_005A91FC(void) { /* KERNEL32.dll:SetStdHandle (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "SetStdHandle");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_CreateFileA_005A9200(void) { /* KERNEL32.dll:CreateFileA (7 args) */
    static STDFN7 fn = NULL;
    if (!fn) fn = (STDFN7)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CreateFileA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    uint32_t a6 = MEM32(g_esp + 28);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5, a6);
    g_esp += 32;
}

/* ======== SHELL32.dll ======== */

static void bridge_ShellExecuteA_005A9208(void) { /* SHELL32.dll:ShellExecuteA (6 args) */
    static STDFN6 fn = NULL;
    if (!fn) fn = (STDFN6)GetProcAddress(GetModuleHandleA("SHELL32.dll"), "ShellExecuteA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5);
    g_esp += 28;
}

/* ======== USER32.dll ======== */

static void bridge_UpdateWindow_005A9210(void) { /* USER32.dll:UpdateWindow (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "UpdateWindow");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_SetFocus_005A9214(void) { /* USER32.dll:SetFocus (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "SetFocus");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_DispatchMessageA_005A9218(void) { /* USER32.dll:DispatchMessageA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "DispatchMessageA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_SetWindowTextA_005A921C(void) { /* USER32.dll:SetWindowTextA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("USER32.dll"), "SetWindowTextA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_GetAsyncKeyState_005A9220(void) { /* USER32.dll:GetAsyncKeyState (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "GetAsyncKeyState");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_DestroyWindow_005A9224(void) { /* USER32.dll:DestroyWindow (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "DestroyWindow");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_PostMessageA_005A9228(void) { /* USER32.dll:PostMessageA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("USER32.dll"), "PostMessageA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_SetCursor_005A922C(void) { /* USER32.dll:SetCursor (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "SetCursor");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_ReleaseCapture_005A9230(void) { /* USER32.dll:ReleaseCapture (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("USER32.dll"), "ReleaseCapture");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_SetCapture_005A9234(void) { /* USER32.dll:SetCapture (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "SetCapture");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_PostQuitMessage_005A9238(void) { /* USER32.dll:PostQuitMessage (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "PostQuitMessage");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_GetKeyboardState_005A923C(void) { /* USER32.dll:GetKeyboardState (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "GetKeyboardState");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_CreateWindowExA_005A9240(void) { /* USER32.dll:CreateWindowExA (12 args) */
    static STDFN12 fn = NULL;
    if (!fn) fn = (STDFN12)GetProcAddress(GetModuleHandleA("USER32.dll"), "CreateWindowExA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    uint32_t a5 = MEM32(g_esp + 24);
    uint32_t a6 = MEM32(g_esp + 28);
    uint32_t a7 = MEM32(g_esp + 32);
    uint32_t a8 = MEM32(g_esp + 36);
    uint32_t a9 = MEM32(g_esp + 40);
    uint32_t a10 = MEM32(g_esp + 44);
    uint32_t a11 = MEM32(g_esp + 48);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
    g_esp += 52;
}

static void bridge_GetSystemMetrics_005A9244(void) { /* USER32.dll:GetSystemMetrics (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "GetSystemMetrics");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_RegisterClassA_005A9248(void) { /* USER32.dll:RegisterClassA (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "RegisterClassA");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_LoadCursorA_005A924C(void) { /* USER32.dll:LoadCursorA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("USER32.dll"), "LoadCursorA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_LoadIconA_005A9250(void) { /* USER32.dll:LoadIconA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("USER32.dll"), "LoadIconA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_ShowWindowAsync_005A9254(void) { /* USER32.dll:ShowWindowAsync (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("USER32.dll"), "ShowWindowAsync");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_FindWindowA_005A9258(void) { /* USER32.dll:FindWindowA (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("USER32.dll"), "FindWindowA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_DrawTextA_005A925C(void) { /* USER32.dll:DrawTextA (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("USER32.dll"), "DrawTextA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_SetRect_005A9260(void) { /* USER32.dll:SetRect (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("USER32.dll"), "SetRect");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_ReleaseDC_005A9264(void) { /* USER32.dll:ReleaseDC (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("USER32.dll"), "ReleaseDC");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_GetDC_005A9268(void) { /* USER32.dll:GetDC (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "GetDC");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_wsprintfA_005A926C(void) { /* USER32.dll:wsprintfA */
    /* wsprintfA is cdecl varargs */
    uint32_t buf = MEM32(g_esp + 4);
    uint32_t fmt = MEM32(g_esp + 8);
    g_eax = (uint32_t)wvsprintfA((LPSTR)(uintptr_t)buf, (LPCSTR)(uintptr_t)fmt, (va_list)(void*)ADDR(g_esp + 12));
    g_esp += 4; /* cdecl: caller cleans */
}

static void bridge_SystemParametersInfoA_005A9270(void) { /* USER32.dll:SystemParametersInfoA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("USER32.dll"), "SystemParametersInfoA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_SetCursorPos_005A9274(void) { /* USER32.dll:SetCursorPos (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("USER32.dll"), "SetCursorPos");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_PeekMessageA_005A9278(void) { /* USER32.dll:PeekMessageA (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("USER32.dll"), "PeekMessageA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_ShowCursor_005A927C(void) { /* USER32.dll:ShowCursor (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "ShowCursor");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_TranslateMessage_005A9280(void) { /* USER32.dll:TranslateMessage (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "TranslateMessage");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_MessageBoxA_005A9284(void) { /* USER32.dll:MessageBoxA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("USER32.dll"), "MessageBoxA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_GetForegroundWindow_005A9288(void) { /* USER32.dll:GetForegroundWindow (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("USER32.dll"), "GetForegroundWindow");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_DefWindowProcA_005A928C(void) { /* USER32.dll:DefWindowProcA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("USER32.dll"), "DefWindowProcA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_GetMessageA_005A9290(void) { /* USER32.dll:GetMessageA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("USER32.dll"), "GetMessageA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_SetForegroundWindow_005A9294(void) { /* USER32.dll:SetForegroundWindow (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("USER32.dll"), "SetForegroundWindow");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

/* ======== WINMM.dll ======== */

static void bridge_timeGetDevCaps_005A929C(void) { /* WINMM.dll:timeGetDevCaps (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("WINMM.dll"), "timeGetDevCaps");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_timeSetEvent_005A92A0(void) { /* WINMM.dll:timeSetEvent (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("WINMM.dll"), "timeSetEvent");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_joyGetPosEx_005A92A4(void) { /* WINMM.dll:joyGetPosEx (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("WINMM.dll"), "joyGetPosEx");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_joyGetDevCapsA_005A92A8(void) { /* WINMM.dll:joyGetDevCapsA (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("WINMM.dll"), "joyGetDevCapsA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_timeGetTime_005A92AC(void) { /* WINMM.dll:timeGetTime (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("WINMM.dll"), "timeGetTime");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_timeBeginPeriod_005A92B0(void) { /* WINMM.dll:timeBeginPeriod (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("WINMM.dll"), "timeBeginPeriod");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_joyGetNumDevs_005A92B4(void) { /* WINMM.dll:joyGetNumDevs (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("WINMM.dll"), "joyGetNumDevs");
    if (fn) g_eax = fn();
    g_esp += 4;
}

static void bridge_mciSendCommandA_005A92B8(void) { /* WINMM.dll:mciSendCommandA (4 args) */
    static STDFN4 fn = NULL;
    if (!fn) fn = (STDFN4)GetProcAddress(GetModuleHandleA("WINMM.dll"), "mciSendCommandA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    if (fn) g_eax = fn(a0, a1, a2, a3);
    g_esp += 20;
}

static void bridge_timeEndPeriod_005A92BC(void) { /* WINMM.dll:timeEndPeriod (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("WINMM.dll"), "timeEndPeriod");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_auxSetVolume_005A92C0(void) { /* WINMM.dll:auxSetVolume (2 args) */
    static STDFN2 fn = NULL;
    if (!fn) fn = (STDFN2)GetProcAddress(GetModuleHandleA("WINMM.dll"), "auxSetVolume");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    if (fn) g_eax = fn(a0, a1);
    g_esp += 12;
}

static void bridge_auxGetDevCapsA_005A92C4(void) { /* WINMM.dll:auxGetDevCapsA (3 args) */
    static STDFN3 fn = NULL;
    if (!fn) fn = (STDFN3)GetProcAddress(GetModuleHandleA("WINMM.dll"), "auxGetDevCapsA");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    if (fn) g_eax = fn(a0, a1, a2);
    g_esp += 16;
}

static void bridge_timeKillEvent_005A92C8(void) { /* WINMM.dll:timeKillEvent (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("WINMM.dll"), "timeKillEvent");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_auxGetNumDevs_005A92CC(void) { /* WINMM.dll:auxGetNumDevs (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("WINMM.dll"), "auxGetNumDevs");
    if (fn) g_eax = fn();
    g_esp += 4;
}

/* ======== ole32.dll ======== */

static void bridge_CoCreateInstance_005A92D4(void) { /* ole32.dll:CoCreateInstance (5 args) */
    static STDFN5 fn = NULL;
    if (!fn) fn = (STDFN5)GetProcAddress(GetModuleHandleA("ole32.dll"), "CoCreateInstance");
    uint32_t a0 = MEM32(g_esp + 4);
    uint32_t a1 = MEM32(g_esp + 8);
    uint32_t a2 = MEM32(g_esp + 12);
    uint32_t a3 = MEM32(g_esp + 16);
    uint32_t a4 = MEM32(g_esp + 20);
    if (fn) g_eax = fn(a0, a1, a2, a3, a4);
    g_esp += 24;
}

static void bridge_CoInitialize_005A92D8(void) { /* ole32.dll:CoInitialize (1 args) */
    static STDFN1 fn = NULL;
    if (!fn) fn = (STDFN1)GetProcAddress(GetModuleHandleA("ole32.dll"), "CoInitialize");
    uint32_t a0 = MEM32(g_esp + 4);
    if (fn) g_eax = fn(a0);
    g_esp += 8;
}

static void bridge_CoUninitialize_005A92DC(void) { /* ole32.dll:CoUninitialize (0 args) */
    static STDFN0 fn = NULL;
    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("ole32.dll"), "CoUninitialize");
    if (fn) g_eax = fn();
    g_esp += 4;
}

/* ======== tgsmush.dll ======== */

static void bridge_SmushShutdown_005A92E4(void) { /* tgsmush.dll:SmushShutdown */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: tgsmush.dll:SmushShutdown\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

static void bridge_SmushStartup_005A92E8(void) { /* tgsmush.dll:SmushStartup */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: tgsmush.dll:SmushStartup\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

static void bridge_SmushPlay_005A92EC(void) { /* tgsmush.dll:SmushPlay */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: tgsmush.dll:SmushPlay\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

static void bridge_SmushSetVolume_005A92F0(void) { /* tgsmush.dll:SmushSetVolume */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: tgsmush.dll:SmushSetVolume\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

static void bridge_SmushGetFrameCount_005A92F4(void) { /* tgsmush.dll:SmushGetFrameCount */
    static int w = 0;
    if (!w) { fprintf(stderr, "STUB: tgsmush.dll:SmushGetFrameCount\n"); w = 1; }
    g_eax = 0; g_esp += 4;
}

/* ======== Bridge Registration ======== */

extern recomp_dispatch_entry_t g_import_bridges[];
extern int g_import_bridge_count;

void register_import_bridges(void) {
    /* 179 import bridges */
    MEM32(0x005A9000) = 0xBB000001u;
    g_import_bridges[0].address = 0xBB000001u;
    g_import_bridges[0].func = bridge_RegSetValueExA_005A9000;
    MEM32(0x005A9004) = 0xBB000002u;
    g_import_bridges[1].address = 0xBB000002u;
    g_import_bridges[1].func = bridge_RegOpenKeyExA_005A9004;
    MEM32(0x005A9008) = 0xBB000003u;
    g_import_bridges[2].address = 0xBB000003u;
    g_import_bridges[2].func = bridge_RegQueryValueExA_005A9008;
    MEM32(0x005A900C) = 0xBB000004u;
    g_import_bridges[3].address = 0xBB000004u;
    g_import_bridges[3].func = bridge_RegCloseKey_005A900C;
    MEM32(0x005A9014) = 0xBB000005u;
    g_import_bridges[4].address = 0xBB000005u;
    g_import_bridges[4].func = bridge_DirectDrawEnumerateExA_005A9014;
    MEM32(0x005A9018) = 0xBB000006u;
    g_import_bridges[5].address = 0xBB000006u;
    g_import_bridges[5].func = bridge_DirectDrawCreate_005A9018;
    MEM32(0x005A9020) = 0xBB000007u;
    g_import_bridges[6].address = 0xBB000007u;
    g_import_bridges[6].func = bridge_DirectInputCreateA_005A9020;
    MEM32(0x005A9028) = 0xBB000008u;
    g_import_bridges[7].address = 0xBB000008u;
    g_import_bridges[7].func = bridge_ordinal_1_005A9028;
    MEM32(0x005A9030) = 0xBB000009u;
    g_import_bridges[8].address = 0xBB000009u;
    g_import_bridges[8].func = bridge_ordinal_1_005A9030;
    MEM32(0x005A9038) = 0xBB00000Au;
    g_import_bridges[9].address = 0xBB00000Au;
    g_import_bridges[9].func = bridge_SetMapMode_005A9038;
    MEM32(0x005A903C) = 0xBB00000Bu;
    g_import_bridges[10].address = 0xBB00000Bu;
    g_import_bridges[10].func = bridge_ExtTextOutA_005A903C;
    MEM32(0x005A9040) = 0xBB00000Cu;
    g_import_bridges[11].address = 0xBB00000Cu;
    g_import_bridges[11].func = bridge_Rectangle_005A9040;
    MEM32(0x005A9044) = 0xBB00000Du;
    g_import_bridges[12].address = 0xBB00000Du;
    g_import_bridges[12].func = bridge_GetStockObject_005A9044;
    MEM32(0x005A9048) = 0xBB00000Eu;
    g_import_bridges[13].address = 0xBB00000Eu;
    g_import_bridges[13].func = bridge_SetBkMode_005A9048;
    MEM32(0x005A904C) = 0xBB00000Fu;
    g_import_bridges[14].address = 0xBB00000Fu;
    g_import_bridges[14].func = bridge_SetBkColor_005A904C;
    MEM32(0x005A9050) = 0xBB000010u;
    g_import_bridges[15].address = 0xBB000010u;
    g_import_bridges[15].func = bridge_SetTextColor_005A9050;
    MEM32(0x005A9054) = 0xBB000011u;
    g_import_bridges[16].address = 0xBB000011u;
    g_import_bridges[16].func = bridge_CreateDCA_005A9054;
    MEM32(0x005A9058) = 0xBB000012u;
    g_import_bridges[17].address = 0xBB000012u;
    g_import_bridges[17].func = bridge_GetTextExtentPoint32A_005A9058;
    MEM32(0x005A905C) = 0xBB000013u;
    g_import_bridges[18].address = 0xBB000013u;
    g_import_bridges[18].func = bridge_SelectObject_005A905C;
    MEM32(0x005A9060) = 0xBB000014u;
    g_import_bridges[19].address = 0xBB000014u;
    g_import_bridges[19].func = bridge_CreateFontA_005A9060;
    MEM32(0x005A9064) = 0xBB000015u;
    g_import_bridges[20].address = 0xBB000015u;
    g_import_bridges[20].func = bridge_DeleteObject_005A9064;
    MEM32(0x005A9068) = 0xBB000016u;
    g_import_bridges[21].address = 0xBB000016u;
    g_import_bridges[21].func = bridge_SetTextCharacterExtra_005A9068;
    MEM32(0x005A906C) = 0xBB000017u;
    g_import_bridges[22].address = 0xBB000017u;
    g_import_bridges[22].func = bridge_DeleteDC_005A906C;
    MEM32(0x005A9074) = 0xBB000018u;
    g_import_bridges[23].address = 0xBB000018u;
    g_import_bridges[23].func = bridge_Sleep_005A9074;
    MEM32(0x005A9078) = 0xBB000019u;
    g_import_bridges[24].address = 0xBB000019u;
    g_import_bridges[24].func = bridge_GlobalUnlock_005A9078;
    MEM32(0x005A907C) = 0xBB00001Au;
    g_import_bridges[25].address = 0xBB00001Au;
    g_import_bridges[25].func = bridge_GlobalReAlloc_005A907C;
    MEM32(0x005A9080) = 0xBB00001Bu;
    g_import_bridges[26].address = 0xBB00001Bu;
    g_import_bridges[26].func = bridge__hread_005A9080;
    MEM32(0x005A9084) = 0xBB00001Cu;
    g_import_bridges[27].address = 0xBB00001Cu;
    g_import_bridges[27].func = bridge__llseek_005A9084;
    MEM32(0x005A9088) = 0xBB00001Du;
    g_import_bridges[28].address = 0xBB00001Du;
    g_import_bridges[28].func = bridge_GlobalLock_005A9088;
    MEM32(0x005A908C) = 0xBB00001Eu;
    g_import_bridges[29].address = 0xBB00001Eu;
    g_import_bridges[29].func = bridge_GlobalAlloc_005A908C;
    MEM32(0x005A9090) = 0xBB00001Fu;
    g_import_bridges[30].address = 0xBB00001Fu;
    g_import_bridges[30].func = bridge_QueryPerformanceCounter_005A9090;
    MEM32(0x005A9094) = 0xBB000020u;
    g_import_bridges[31].address = 0xBB000020u;
    g_import_bridges[31].func = bridge_QueryPerformanceFrequency_005A9094;
    MEM32(0x005A9098) = 0xBB000021u;
    g_import_bridges[32].address = 0xBB000021u;
    g_import_bridges[32].func = bridge_CreateProcessA_005A9098;
    MEM32(0x005A909C) = 0xBB000022u;
    g_import_bridges[33].address = 0xBB000022u;
    g_import_bridges[33].func = bridge_GlobalFree_005A909C;
    MEM32(0x005A90A0) = 0xBB000023u;
    g_import_bridges[34].address = 0xBB000023u;
    g_import_bridges[34].func = bridge__lopen_005A90A0;
    MEM32(0x005A90A4) = 0xBB000024u;
    g_import_bridges[35].address = 0xBB000024u;
    g_import_bridges[35].func = bridge__lread_005A90A4;
    MEM32(0x005A90A8) = 0xBB000025u;
    g_import_bridges[36].address = 0xBB000025u;
    g_import_bridges[36].func = bridge__lclose_005A90A8;
    MEM32(0x005A90AC) = 0xBB000026u;
    g_import_bridges[37].address = 0xBB000026u;
    g_import_bridges[37].func = bridge_VirtualProtect_005A90AC;
    MEM32(0x005A90B0) = 0xBB000027u;
    g_import_bridges[38].address = 0xBB000027u;
    g_import_bridges[38].func = bridge_GetLocalTime_005A90B0;
    MEM32(0x005A90B4) = 0xBB000028u;
    g_import_bridges[39].address = 0xBB000028u;
    g_import_bridges[39].func = bridge_OutputDebugStringA_005A90B4;
    MEM32(0x005A90B8) = 0xBB000029u;
    g_import_bridges[40].address = 0xBB000029u;
    g_import_bridges[40].func = bridge_GetCPInfo_005A90B8;
    MEM32(0x005A90BC) = 0xBB00002Au;
    g_import_bridges[41].address = 0xBB00002Au;
    g_import_bridges[41].func = bridge_UnhandledExceptionFilter_005A90BC;
    MEM32(0x005A90C0) = 0xBB00002Bu;
    g_import_bridges[42].address = 0xBB00002Bu;
    g_import_bridges[42].func = bridge_GetModuleFileNameA_005A90C0;
    MEM32(0x005A90C4) = 0xBB00002Cu;
    g_import_bridges[43].address = 0xBB00002Cu;
    g_import_bridges[43].func = bridge_GetFileType_005A90C4;
    MEM32(0x005A90C8) = 0xBB00002Du;
    g_import_bridges[44].address = 0xBB00002Du;
    g_import_bridges[44].func = bridge_WideCharToMultiByte_005A90C8;
    MEM32(0x005A90CC) = 0xBB00002Eu;
    g_import_bridges[45].address = 0xBB00002Eu;
    g_import_bridges[45].func = bridge_LCMapStringA_005A90CC;
    MEM32(0x005A90D0) = 0xBB00002Fu;
    g_import_bridges[46].address = 0xBB00002Fu;
    g_import_bridges[46].func = bridge_RaiseException_005A90D0;
    MEM32(0x005A90D4) = 0xBB000030u;
    g_import_bridges[47].address = 0xBB000030u;
    g_import_bridges[47].func = bridge_GetLocaleInfoW_005A90D4;
    MEM32(0x005A90D8) = 0xBB000031u;
    g_import_bridges[48].address = 0xBB000031u;
    g_import_bridges[48].func = bridge_GlobalMemoryStatus_005A90D8;
    MEM32(0x005A90DC) = 0xBB000032u;
    g_import_bridges[49].address = 0xBB000032u;
    g_import_bridges[49].func = bridge_GetDriveTypeA_005A90DC;
    MEM32(0x005A90E0) = 0xBB000033u;
    g_import_bridges[50].address = 0xBB000033u;
    g_import_bridges[50].func = bridge_GetLogicalDriveStringsA_005A90E0;
    MEM32(0x005A90E4) = 0xBB000034u;
    g_import_bridges[51].address = 0xBB000034u;
    g_import_bridges[51].func = bridge_TerminateProcess_005A90E4;
    MEM32(0x005A90E8) = 0xBB000035u;
    g_import_bridges[52].address = 0xBB000035u;
    g_import_bridges[52].func = bridge_GetCurrentProcess_005A90E8;
    MEM32(0x005A90EC) = 0xBB000036u;
    g_import_bridges[53].address = 0xBB000036u;
    g_import_bridges[53].func = bridge_ExitProcess_005A90EC;
    MEM32(0x005A90F0) = 0xBB000037u;
    g_import_bridges[54].address = 0xBB000037u;
    g_import_bridges[54].func = bridge_GlobalHandle_005A90F0;
    MEM32(0x005A90F4) = 0xBB000038u;
    g_import_bridges[55].address = 0xBB000038u;
    g_import_bridges[55].func = bridge_lstrlenA_005A90F4;
    MEM32(0x005A90F8) = 0xBB000039u;
    g_import_bridges[56].address = 0xBB000039u;
    g_import_bridges[56].func = bridge_GetTickCount_005A90F8;
    MEM32(0x005A90FC) = 0xBB00003Au;
    g_import_bridges[57].address = 0xBB00003Au;
    g_import_bridges[57].func = bridge_GetProcAddress_005A90FC;
    MEM32(0x005A9100) = 0xBB00003Bu;
    g_import_bridges[58].address = 0xBB00003Bu;
    g_import_bridges[58].func = bridge_GetModuleHandleA_005A9100;
    MEM32(0x005A9104) = 0xBB00003Cu;
    g_import_bridges[59].address = 0xBB00003Cu;
    g_import_bridges[59].func = bridge_lstrcpyA_005A9104;
    MEM32(0x005A9108) = 0xBB00003Du;
    g_import_bridges[60].address = 0xBB00003Du;
    g_import_bridges[60].func = bridge_FindNextFileA_005A9108;
    MEM32(0x005A910C) = 0xBB00003Eu;
    g_import_bridges[61].address = 0xBB00003Eu;
    g_import_bridges[61].func = bridge_FindClose_005A910C;
    MEM32(0x005A9110) = 0xBB00003Fu;
    g_import_bridges[62].address = 0xBB00003Fu;
    g_import_bridges[62].func = bridge_FindFirstFileA_005A9110;
    MEM32(0x005A9114) = 0xBB000040u;
    g_import_bridges[63].address = 0xBB000040u;
    g_import_bridges[63].func = bridge_LockResource_005A9114;
    MEM32(0x005A9118) = 0xBB000041u;
    g_import_bridges[64].address = 0xBB000041u;
    g_import_bridges[64].func = bridge_LoadResource_005A9118;
    MEM32(0x005A911C) = 0xBB000042u;
    g_import_bridges[65].address = 0xBB000042u;
    g_import_bridges[65].func = bridge_FindResourceA_005A911C;
    MEM32(0x005A9120) = 0xBB000043u;
    g_import_bridges[66].address = 0xBB000043u;
    g_import_bridges[66].func = bridge_LeaveCriticalSection_005A9120;
    MEM32(0x005A9124) = 0xBB000044u;
    g_import_bridges[67].address = 0xBB000044u;
    g_import_bridges[67].func = bridge_EnterCriticalSection_005A9124;
    MEM32(0x005A9128) = 0xBB000045u;
    g_import_bridges[68].address = 0xBB000045u;
    g_import_bridges[68].func = bridge_InitializeCriticalSection_005A9128;
    MEM32(0x005A912C) = 0xBB000046u;
    g_import_bridges[69].address = 0xBB000046u;
    g_import_bridges[69].func = bridge_CloseHandle_005A912C;
    MEM32(0x005A9130) = 0xBB000047u;
    g_import_bridges[70].address = 0xBB000047u;
    g_import_bridges[70].func = bridge_DeleteCriticalSection_005A9130;
    MEM32(0x005A9134) = 0xBB000048u;
    g_import_bridges[71].address = 0xBB000048u;
    g_import_bridges[71].func = bridge_InterlockedDecrement_005A9134;
    MEM32(0x005A9138) = 0xBB000049u;
    g_import_bridges[72].address = 0xBB000049u;
    g_import_bridges[72].func = bridge_InterlockedIncrement_005A9138;
    MEM32(0x005A913C) = 0xBB00004Au;
    g_import_bridges[73].address = 0xBB00004Au;
    g_import_bridges[73].func = bridge_GetLastError_005A913C;
    MEM32(0x005A9140) = 0xBB00004Bu;
    g_import_bridges[74].address = 0xBB00004Bu;
    g_import_bridges[74].func = bridge_DeleteFileA_005A9140;
    MEM32(0x005A9144) = 0xBB00004Cu;
    g_import_bridges[75].address = 0xBB00004Cu;
    g_import_bridges[75].func = bridge_MoveFileA_005A9144;
    MEM32(0x005A9148) = 0xBB00004Du;
    g_import_bridges[76].address = 0xBB00004Du;
    g_import_bridges[76].func = bridge_HeapAlloc_005A9148;
    MEM32(0x005A914C) = 0xBB00004Eu;
    g_import_bridges[77].address = 0xBB00004Eu;
    g_import_bridges[77].func = bridge_HeapReAlloc_005A914C;
    MEM32(0x005A9150) = 0xBB00004Fu;
    g_import_bridges[78].address = 0xBB00004Fu;
    g_import_bridges[78].func = bridge_HeapFree_005A9150;
    MEM32(0x005A9154) = 0xBB000050u;
    g_import_bridges[79].address = 0xBB000050u;
    g_import_bridges[79].func = bridge_GetStartupInfoA_005A9154;
    MEM32(0x005A9158) = 0xBB000051u;
    g_import_bridges[80].address = 0xBB000051u;
    g_import_bridges[80].func = bridge_GetCommandLineA_005A9158;
    MEM32(0x005A915C) = 0xBB000052u;
    g_import_bridges[81].address = 0xBB000052u;
    g_import_bridges[81].func = bridge_GetVersion_005A915C;
    MEM32(0x005A9160) = 0xBB000053u;
    g_import_bridges[82].address = 0xBB000053u;
    g_import_bridges[82].func = bridge_SetEnvironmentVariableA_005A9160;
    MEM32(0x005A9164) = 0xBB000054u;
    g_import_bridges[83].address = 0xBB000054u;
    g_import_bridges[83].func = bridge_GetCurrentDirectoryA_005A9164;
    MEM32(0x005A9168) = 0xBB000055u;
    g_import_bridges[84].address = 0xBB000055u;
    g_import_bridges[84].func = bridge_SetCurrentDirectoryA_005A9168;
    MEM32(0x005A916C) = 0xBB000056u;
    g_import_bridges[85].address = 0xBB000056u;
    g_import_bridges[85].func = bridge_GetFullPathNameA_005A916C;
    MEM32(0x005A9170) = 0xBB000057u;
    g_import_bridges[86].address = 0xBB000057u;
    g_import_bridges[86].func = bridge_MultiByteToWideChar_005A9170;
    MEM32(0x005A9174) = 0xBB000058u;
    g_import_bridges[87].address = 0xBB000058u;
    g_import_bridges[87].func = bridge_GetStdHandle_005A9174;
    MEM32(0x005A9178) = 0xBB000059u;
    g_import_bridges[88].address = 0xBB000059u;
    g_import_bridges[88].func = bridge_LCMapStringW_005A9178;
    MEM32(0x005A917C) = 0xBB00005Au;
    g_import_bridges[89].address = 0xBB00005Au;
    g_import_bridges[89].func = bridge_SetEndOfFile_005A917C;
    MEM32(0x005A9180) = 0xBB00005Bu;
    g_import_bridges[90].address = 0xBB00005Bu;
    g_import_bridges[90].func = bridge_IsValidLocale_005A9180;
    MEM32(0x005A9184) = 0xBB00005Cu;
    g_import_bridges[91].address = 0xBB00005Cu;
    g_import_bridges[91].func = bridge_IsValidCodePage_005A9184;
    MEM32(0x005A9188) = 0xBB00005Du;
    g_import_bridges[92].address = 0xBB00005Du;
    g_import_bridges[92].func = bridge_GetLocaleInfoA_005A9188;
    MEM32(0x005A918C) = 0xBB00005Eu;
    g_import_bridges[93].address = 0xBB00005Eu;
    g_import_bridges[93].func = bridge_EnumSystemLocalesA_005A918C;
    MEM32(0x005A9190) = 0xBB00005Fu;
    g_import_bridges[94].address = 0xBB00005Fu;
    g_import_bridges[94].func = bridge_GetUserDefaultLCID_005A9190;
    MEM32(0x005A9194) = 0xBB000060u;
    g_import_bridges[95].address = 0xBB000060u;
    g_import_bridges[95].func = bridge_GetVersionExA_005A9194;
    MEM32(0x005A9198) = 0xBB000061u;
    g_import_bridges[96].address = 0xBB000061u;
    g_import_bridges[96].func = bridge_SetFilePointer_005A9198;
    MEM32(0x005A919C) = 0xBB000062u;
    g_import_bridges[97].address = 0xBB000062u;
    g_import_bridges[97].func = bridge_ReadFile_005A919C;
    MEM32(0x005A91A0) = 0xBB000063u;
    g_import_bridges[98].address = 0xBB000063u;
    g_import_bridges[98].func = bridge_WriteFile_005A91A0;
    MEM32(0x005A91A4) = 0xBB000064u;
    g_import_bridges[99].address = 0xBB000064u;
    g_import_bridges[99].func = bridge_GetCurrentThreadId_005A91A4;
    MEM32(0x005A91A8) = 0xBB000065u;
    g_import_bridges[100].address = 0xBB000065u;
    g_import_bridges[100].func = bridge_TlsSetValue_005A91A8;
    MEM32(0x005A91AC) = 0xBB000066u;
    g_import_bridges[101].address = 0xBB000066u;
    g_import_bridges[101].func = bridge_TlsAlloc_005A91AC;
    MEM32(0x005A91B0) = 0xBB000067u;
    g_import_bridges[102].address = 0xBB000067u;
    g_import_bridges[102].func = bridge_SetLastError_005A91B0;
    MEM32(0x005A91B4) = 0xBB000068u;
    g_import_bridges[103].address = 0xBB000068u;
    g_import_bridges[103].func = bridge_TlsGetValue_005A91B4;
    MEM32(0x005A91B8) = 0xBB000069u;
    g_import_bridges[104].address = 0xBB000069u;
    g_import_bridges[104].func = bridge_HeapSize_005A91B8;
    MEM32(0x005A91BC) = 0xBB00006Au;
    g_import_bridges[105].address = 0xBB00006Au;
    g_import_bridges[105].func = bridge_SetHandleCount_005A91BC;
    MEM32(0x005A91C0) = 0xBB00006Bu;
    g_import_bridges[106].address = 0xBB00006Bu;
    g_import_bridges[106].func = bridge_LoadLibraryA_005A91C0;
    MEM32(0x005A91C4) = 0xBB00006Cu;
    g_import_bridges[107].address = 0xBB00006Cu;
    g_import_bridges[107].func = bridge_GetStringTypeA_005A91C4;
    MEM32(0x005A91C8) = 0xBB00006Du;
    g_import_bridges[108].address = 0xBB00006Du;
    g_import_bridges[108].func = bridge_GetStringTypeW_005A91C8;
    MEM32(0x005A91CC) = 0xBB00006Eu;
    g_import_bridges[109].address = 0xBB00006Eu;
    g_import_bridges[109].func = bridge_FlushFileBuffers_005A91CC;
    MEM32(0x005A91D0) = 0xBB00006Fu;
    g_import_bridges[110].address = 0xBB00006Fu;
    g_import_bridges[110].func = bridge_HeapDestroy_005A91D0;
    MEM32(0x005A91D4) = 0xBB000070u;
    g_import_bridges[111].address = 0xBB000070u;
    g_import_bridges[111].func = bridge_HeapCreate_005A91D4;
    MEM32(0x005A91D8) = 0xBB000071u;
    g_import_bridges[112].address = 0xBB000071u;
    g_import_bridges[112].func = bridge_VirtualFree_005A91D8;
    MEM32(0x005A91DC) = 0xBB000072u;
    g_import_bridges[113].address = 0xBB000072u;
    g_import_bridges[113].func = bridge_VirtualAlloc_005A91DC;
    MEM32(0x005A91E0) = 0xBB000073u;
    g_import_bridges[114].address = 0xBB000073u;
    g_import_bridges[114].func = bridge_FreeEnvironmentStringsA_005A91E0;
    MEM32(0x005A91E4) = 0xBB000074u;
    g_import_bridges[115].address = 0xBB000074u;
    g_import_bridges[115].func = bridge_FreeEnvironmentStringsW_005A91E4;
    MEM32(0x005A91E8) = 0xBB000075u;
    g_import_bridges[116].address = 0xBB000075u;
    g_import_bridges[116].func = bridge_GetEnvironmentStrings_005A91E8;
    MEM32(0x005A91EC) = 0xBB000076u;
    g_import_bridges[117].address = 0xBB000076u;
    g_import_bridges[117].func = bridge_GetEnvironmentStringsW_005A91EC;
    MEM32(0x005A91F0) = 0xBB000077u;
    g_import_bridges[118].address = 0xBB000077u;
    g_import_bridges[118].func = bridge_GetACP_005A91F0;
    MEM32(0x005A91F4) = 0xBB000078u;
    g_import_bridges[119].address = 0xBB000078u;
    g_import_bridges[119].func = bridge_GetOEMCP_005A91F4;
    MEM32(0x005A91F8) = 0xBB000079u;
    g_import_bridges[120].address = 0xBB000079u;
    g_import_bridges[120].func = bridge_RtlUnwind_005A91F8;
    MEM32(0x005A91FC) = 0xBB00007Au;
    g_import_bridges[121].address = 0xBB00007Au;
    g_import_bridges[121].func = bridge_SetStdHandle_005A91FC;
    MEM32(0x005A9200) = 0xBB00007Bu;
    g_import_bridges[122].address = 0xBB00007Bu;
    g_import_bridges[122].func = bridge_CreateFileA_005A9200;
    MEM32(0x005A9208) = 0xBB00007Cu;
    g_import_bridges[123].address = 0xBB00007Cu;
    g_import_bridges[123].func = bridge_ShellExecuteA_005A9208;
    MEM32(0x005A9210) = 0xBB00007Du;
    g_import_bridges[124].address = 0xBB00007Du;
    g_import_bridges[124].func = bridge_UpdateWindow_005A9210;
    MEM32(0x005A9214) = 0xBB00007Eu;
    g_import_bridges[125].address = 0xBB00007Eu;
    g_import_bridges[125].func = bridge_SetFocus_005A9214;
    MEM32(0x005A9218) = 0xBB00007Fu;
    g_import_bridges[126].address = 0xBB00007Fu;
    g_import_bridges[126].func = bridge_DispatchMessageA_005A9218;
    MEM32(0x005A921C) = 0xBB000080u;
    g_import_bridges[127].address = 0xBB000080u;
    g_import_bridges[127].func = bridge_SetWindowTextA_005A921C;
    MEM32(0x005A9220) = 0xBB000081u;
    g_import_bridges[128].address = 0xBB000081u;
    g_import_bridges[128].func = bridge_GetAsyncKeyState_005A9220;
    MEM32(0x005A9224) = 0xBB000082u;
    g_import_bridges[129].address = 0xBB000082u;
    g_import_bridges[129].func = bridge_DestroyWindow_005A9224;
    MEM32(0x005A9228) = 0xBB000083u;
    g_import_bridges[130].address = 0xBB000083u;
    g_import_bridges[130].func = bridge_PostMessageA_005A9228;
    MEM32(0x005A922C) = 0xBB000084u;
    g_import_bridges[131].address = 0xBB000084u;
    g_import_bridges[131].func = bridge_SetCursor_005A922C;
    MEM32(0x005A9230) = 0xBB000085u;
    g_import_bridges[132].address = 0xBB000085u;
    g_import_bridges[132].func = bridge_ReleaseCapture_005A9230;
    MEM32(0x005A9234) = 0xBB000086u;
    g_import_bridges[133].address = 0xBB000086u;
    g_import_bridges[133].func = bridge_SetCapture_005A9234;
    MEM32(0x005A9238) = 0xBB000087u;
    g_import_bridges[134].address = 0xBB000087u;
    g_import_bridges[134].func = bridge_PostQuitMessage_005A9238;
    MEM32(0x005A923C) = 0xBB000088u;
    g_import_bridges[135].address = 0xBB000088u;
    g_import_bridges[135].func = bridge_GetKeyboardState_005A923C;
    MEM32(0x005A9240) = 0xBB000089u;
    g_import_bridges[136].address = 0xBB000089u;
    g_import_bridges[136].func = bridge_CreateWindowExA_005A9240;
    MEM32(0x005A9244) = 0xBB00008Au;
    g_import_bridges[137].address = 0xBB00008Au;
    g_import_bridges[137].func = bridge_GetSystemMetrics_005A9244;
    MEM32(0x005A9248) = 0xBB00008Bu;
    g_import_bridges[138].address = 0xBB00008Bu;
    g_import_bridges[138].func = bridge_RegisterClassA_005A9248;
    MEM32(0x005A924C) = 0xBB00008Cu;
    g_import_bridges[139].address = 0xBB00008Cu;
    g_import_bridges[139].func = bridge_LoadCursorA_005A924C;
    MEM32(0x005A9250) = 0xBB00008Du;
    g_import_bridges[140].address = 0xBB00008Du;
    g_import_bridges[140].func = bridge_LoadIconA_005A9250;
    MEM32(0x005A9254) = 0xBB00008Eu;
    g_import_bridges[141].address = 0xBB00008Eu;
    g_import_bridges[141].func = bridge_ShowWindowAsync_005A9254;
    MEM32(0x005A9258) = 0xBB00008Fu;
    g_import_bridges[142].address = 0xBB00008Fu;
    g_import_bridges[142].func = bridge_FindWindowA_005A9258;
    MEM32(0x005A925C) = 0xBB000090u;
    g_import_bridges[143].address = 0xBB000090u;
    g_import_bridges[143].func = bridge_DrawTextA_005A925C;
    MEM32(0x005A9260) = 0xBB000091u;
    g_import_bridges[144].address = 0xBB000091u;
    g_import_bridges[144].func = bridge_SetRect_005A9260;
    MEM32(0x005A9264) = 0xBB000092u;
    g_import_bridges[145].address = 0xBB000092u;
    g_import_bridges[145].func = bridge_ReleaseDC_005A9264;
    MEM32(0x005A9268) = 0xBB000093u;
    g_import_bridges[146].address = 0xBB000093u;
    g_import_bridges[146].func = bridge_GetDC_005A9268;
    MEM32(0x005A926C) = 0xBB000094u;
    g_import_bridges[147].address = 0xBB000094u;
    g_import_bridges[147].func = bridge_wsprintfA_005A926C;
    MEM32(0x005A9270) = 0xBB000095u;
    g_import_bridges[148].address = 0xBB000095u;
    g_import_bridges[148].func = bridge_SystemParametersInfoA_005A9270;
    MEM32(0x005A9274) = 0xBB000096u;
    g_import_bridges[149].address = 0xBB000096u;
    g_import_bridges[149].func = bridge_SetCursorPos_005A9274;
    MEM32(0x005A9278) = 0xBB000097u;
    g_import_bridges[150].address = 0xBB000097u;
    g_import_bridges[150].func = bridge_PeekMessageA_005A9278;
    MEM32(0x005A927C) = 0xBB000098u;
    g_import_bridges[151].address = 0xBB000098u;
    g_import_bridges[151].func = bridge_ShowCursor_005A927C;
    MEM32(0x005A9280) = 0xBB000099u;
    g_import_bridges[152].address = 0xBB000099u;
    g_import_bridges[152].func = bridge_TranslateMessage_005A9280;
    MEM32(0x005A9284) = 0xBB00009Au;
    g_import_bridges[153].address = 0xBB00009Au;
    g_import_bridges[153].func = bridge_MessageBoxA_005A9284;
    MEM32(0x005A9288) = 0xBB00009Bu;
    g_import_bridges[154].address = 0xBB00009Bu;
    g_import_bridges[154].func = bridge_GetForegroundWindow_005A9288;
    MEM32(0x005A928C) = 0xBB00009Cu;
    g_import_bridges[155].address = 0xBB00009Cu;
    g_import_bridges[155].func = bridge_DefWindowProcA_005A928C;
    MEM32(0x005A9290) = 0xBB00009Du;
    g_import_bridges[156].address = 0xBB00009Du;
    g_import_bridges[156].func = bridge_GetMessageA_005A9290;
    MEM32(0x005A9294) = 0xBB00009Eu;
    g_import_bridges[157].address = 0xBB00009Eu;
    g_import_bridges[157].func = bridge_SetForegroundWindow_005A9294;
    MEM32(0x005A929C) = 0xBB00009Fu;
    g_import_bridges[158].address = 0xBB00009Fu;
    g_import_bridges[158].func = bridge_timeGetDevCaps_005A929C;
    MEM32(0x005A92A0) = 0xBB0000A0u;
    g_import_bridges[159].address = 0xBB0000A0u;
    g_import_bridges[159].func = bridge_timeSetEvent_005A92A0;
    MEM32(0x005A92A4) = 0xBB0000A1u;
    g_import_bridges[160].address = 0xBB0000A1u;
    g_import_bridges[160].func = bridge_joyGetPosEx_005A92A4;
    MEM32(0x005A92A8) = 0xBB0000A2u;
    g_import_bridges[161].address = 0xBB0000A2u;
    g_import_bridges[161].func = bridge_joyGetDevCapsA_005A92A8;
    MEM32(0x005A92AC) = 0xBB0000A3u;
    g_import_bridges[162].address = 0xBB0000A3u;
    g_import_bridges[162].func = bridge_timeGetTime_005A92AC;
    MEM32(0x005A92B0) = 0xBB0000A4u;
    g_import_bridges[163].address = 0xBB0000A4u;
    g_import_bridges[163].func = bridge_timeBeginPeriod_005A92B0;
    MEM32(0x005A92B4) = 0xBB0000A5u;
    g_import_bridges[164].address = 0xBB0000A5u;
    g_import_bridges[164].func = bridge_joyGetNumDevs_005A92B4;
    MEM32(0x005A92B8) = 0xBB0000A6u;
    g_import_bridges[165].address = 0xBB0000A6u;
    g_import_bridges[165].func = bridge_mciSendCommandA_005A92B8;
    MEM32(0x005A92BC) = 0xBB0000A7u;
    g_import_bridges[166].address = 0xBB0000A7u;
    g_import_bridges[166].func = bridge_timeEndPeriod_005A92BC;
    MEM32(0x005A92C0) = 0xBB0000A8u;
    g_import_bridges[167].address = 0xBB0000A8u;
    g_import_bridges[167].func = bridge_auxSetVolume_005A92C0;
    MEM32(0x005A92C4) = 0xBB0000A9u;
    g_import_bridges[168].address = 0xBB0000A9u;
    g_import_bridges[168].func = bridge_auxGetDevCapsA_005A92C4;
    MEM32(0x005A92C8) = 0xBB0000AAu;
    g_import_bridges[169].address = 0xBB0000AAu;
    g_import_bridges[169].func = bridge_timeKillEvent_005A92C8;
    MEM32(0x005A92CC) = 0xBB0000ABu;
    g_import_bridges[170].address = 0xBB0000ABu;
    g_import_bridges[170].func = bridge_auxGetNumDevs_005A92CC;
    MEM32(0x005A92D4) = 0xBB0000ACu;
    g_import_bridges[171].address = 0xBB0000ACu;
    g_import_bridges[171].func = bridge_CoCreateInstance_005A92D4;
    MEM32(0x005A92D8) = 0xBB0000ADu;
    g_import_bridges[172].address = 0xBB0000ADu;
    g_import_bridges[172].func = bridge_CoInitialize_005A92D8;
    MEM32(0x005A92DC) = 0xBB0000AEu;
    g_import_bridges[173].address = 0xBB0000AEu;
    g_import_bridges[173].func = bridge_CoUninitialize_005A92DC;
    MEM32(0x005A92E4) = 0xBB0000AFu;
    g_import_bridges[174].address = 0xBB0000AFu;
    g_import_bridges[174].func = bridge_SmushShutdown_005A92E4;
    MEM32(0x005A92E8) = 0xBB0000B0u;
    g_import_bridges[175].address = 0xBB0000B0u;
    g_import_bridges[175].func = bridge_SmushStartup_005A92E8;
    MEM32(0x005A92EC) = 0xBB0000B1u;
    g_import_bridges[176].address = 0xBB0000B1u;
    g_import_bridges[176].func = bridge_SmushPlay_005A92EC;
    MEM32(0x005A92F0) = 0xBB0000B2u;
    g_import_bridges[177].address = 0xBB0000B2u;
    g_import_bridges[177].func = bridge_SmushSetVolume_005A92F0;
    MEM32(0x005A92F4) = 0xBB0000B3u;
    g_import_bridges[178].address = 0xBB0000B3u;
    g_import_bridges[178].func = bridge_SmushGetFrameCount_005A92F4;
    g_import_bridge_count = 179;
    printf("[*] Registered %d import bridges\n", g_import_bridge_count);
}
