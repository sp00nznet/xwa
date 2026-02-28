"""
Generate Win32 import bridge functions for the recompiled binary.

Uses a generic stdcall dispatcher approach: for each import, generates a bridge
that reads N args from the simulated stack, calls the real function via
GetProcAddress, and writes the result to g_eax.
"""

import json
import sys

# arg count for each import: name -> (nargs, is_void_return, notes)
FUNC_ARGS = {
    # KERNEL32.dll
    'Sleep': 1, 'GlobalUnlock': 1, 'GlobalReAlloc': 3,
    '_hread': 3, '_llseek': 3, 'GlobalLock': 1, 'GlobalAlloc': 2,
    'QueryPerformanceCounter': 1, 'QueryPerformanceFrequency': 1,
    'CreateProcessA': 10, 'GlobalFree': 1, '_lopen': 2, '_lread': 3,
    '_lclose': 1, 'VirtualProtect': 4, 'GetLocalTime': 1,
    'OutputDebugStringA': 1, 'GetCPInfo': 2, 'UnhandledExceptionFilter': 1,
    'GetModuleFileNameA': 3, 'GetFileType': 1, 'WideCharToMultiByte': 8,
    'LCMapStringA': 6, 'RaiseException': 4, 'GetLocaleInfoW': 4,
    'GlobalMemoryStatus': 1, 'GetDriveTypeA': 1, 'GetLogicalDriveStringsA': 2,
    'TerminateProcess': 2, 'GetCurrentProcess': 0, 'ExitProcess': 1,
    'GlobalHandle': 1, 'lstrlenA': 1, 'GetTickCount': 0,
    'GetProcAddress': 2, 'GetModuleHandleA': 1, 'lstrcpyA': 2,
    'FindNextFileA': 2, 'FindClose': 1, 'FindFirstFileA': 2,
    'LockResource': 1, 'LoadResource': 2, 'FindResourceA': 3,
    'LeaveCriticalSection': 1, 'EnterCriticalSection': 1,
    'InitializeCriticalSection': 1, 'CloseHandle': 1,
    'DeleteCriticalSection': 1, 'InterlockedDecrement': 1,
    'InterlockedIncrement': 1, 'HeapAlloc': 3, 'HeapReAlloc': 4,
    'HeapFree': 3, 'FreeLibrary': 1, 'CreateThread': 6,
    'WaitForSingleObject': 2, 'lstrcmpiA': 2, 'IsBadReadPtr': 2,
    'CompareStringA': 6, 'GetProcessHeap': 0, 'SetEvent': 1,
    'CreateEventA': 4, 'GetLastError': 0,
    'WritePrivateProfileStringA': 4, 'GetPrivateProfileStringA': 6,
    'lstrcatA': 2, 'GetPrivateProfileIntA': 4,
    'GetStartupInfoA': 1, 'GetCommandLineA': 0, 'GetVersion': 0,
    'SetEnvironmentVariableA': 2, 'GetCurrentDirectoryA': 2,
    'SetCurrentDirectoryA': 1, 'GetFullPathNameA': 4,
    'MultiByteToWideChar': 6, 'GetStdHandle': 1, 'LCMapStringW': 6,
    'SetEndOfFile': 1, 'IsValidLocale': 2, 'IsValidCodePage': 1,
    'GetLocaleInfoA': 4, 'EnumSystemLocalesA': 2, 'GetUserDefaultLCID': 0,
    'GetVersionExA': 1, 'SetFilePointer': 4, 'ReadFile': 5,
    'WriteFile': 5, 'GetCurrentThreadId': 0, 'TlsSetValue': 2,
    'TlsAlloc': 0, 'SetLastError': 1, 'TlsGetValue': 1,
    'HeapSize': 3, 'SetHandleCount': 1, 'LoadLibraryA': 1,
    'GetStringTypeA': 5, 'GetStringTypeW': 4, 'FlushFileBuffers': 1,
    'HeapDestroy': 1, 'HeapCreate': 3, 'VirtualFree': 3,
    'VirtualAlloc': 4, 'FreeEnvironmentStringsA': 1,
    'FreeEnvironmentStringsW': 1, 'GetEnvironmentStrings': 0,
    'GetEnvironmentStringsW': 0, 'GetACP': 0, 'GetOEMCP': 0,
    'RtlUnwind': 4, 'SetStdHandle': 2, 'CreateFileA': 7,

    # USER32.dll
    'UpdateWindow': 1, 'SetFocus': 1, 'DispatchMessageA': 1,
    'SetWindowTextA': 2, 'GetAsyncKeyState': 1, 'DestroyWindow': 1,
    'PostMessageA': 4, 'SetCursor': 1, 'ReleaseCapture': 0,
    'SetCapture': 1, 'PostQuitMessage': 1, 'GetKeyboardState': 1,
    'CreateWindowExA': 12, 'GetSystemMetrics': 1, 'RegisterClassA': 1,
    'LoadCursorA': 2, 'LoadIconA': 2, 'ShowWindowAsync': 2,
    'FindWindowA': 2, 'DrawTextA': 5, 'SetRect': 5, 'ReleaseDC': 2,
    'GetDC': 1, 'wsprintfA': -1,  # varargs, special
    'SystemParametersInfoA': 4, 'SetCursorPos': 2, 'PeekMessageA': 5,
    'ShowCursor': 1, 'TranslateMessage': 1, 'MessageBoxA': 4,
    'GetForegroundWindow': 0, 'DefWindowProcA': 4, 'GetMessageA': 4,
    'SetForegroundWindow': 1, 'GetCursorPos': 1, 'SetWindowPos': 7,

    # GDI32.dll
    'SetMapMode': 2, 'ExtTextOutA': 8, 'Rectangle': 5,
    'GetStockObject': 1, 'SetBkMode': 2, 'SetBkColor': 2,
    'SetTextColor': 2, 'CreateDCA': 4, 'GetTextExtentPoint32A': 4,
    'SelectObject': 2, 'CreateFontA': 14, 'DeleteObject': 1,
    'SetTextCharacterExtra': 2, 'DeleteDC': 1,

    # WINMM.dll
    'timeGetDevCaps': 2, 'timeSetEvent': 5, 'joyGetPosEx': 2,
    'joyGetDevCapsA': 3, 'timeGetTime': 0, 'timeBeginPeriod': 1,
    'joyGetNumDevs': 0, 'mciSendCommandA': 4, 'timeEndPeriod': 1,
    'auxSetVolume': 2, 'auxGetDevCapsA': 3, 'timeKillEvent': 1,
    'auxGetNumDevs': 0,

    # ADVAPI32.dll
    'RegSetValueExA': 6, 'RegOpenKeyExA': 5, 'RegQueryValueExA': 6,
    'RegCloseKey': 1,

    # ole32.dll
    'CoCreateInstance': 5, 'CoInitialize': 1, 'CoUninitialize': 0,

    # SHELL32.dll
    'ShellExecuteA': 6,

    # DirectX / special - use stubs for now
    'DirectDrawCreate': -2,
    'DirectDrawEnumerateExA': -2,
    'DirectInputCreateA': -2,
}


def main():
    pe_json = sys.argv[1] if len(sys.argv) > 1 else 'config/pe_analysis.json'
    output = sys.argv[2] if len(sys.argv) > 2 else 'src/game/imports.c'

    with open(pe_json) as f:
        data = json.load(f)

    image_base = data['image_base']
    imports_list = data['imports']

    lines = []
    lines.append('/* Auto-generated import bridges - DO NOT EDIT */')
    lines.append('/*')
    lines.append(' * Each bridge reads arguments from the simulated stack,')
    lines.append(' * calls the real Win32 API, and returns the result in g_eax.')
    lines.append(' */')
    lines.append('')
    lines.append('#define WIN32_LEAN_AND_MEAN')
    lines.append('#include <windows.h>')
    lines.append('#include <mmsystem.h>')
    lines.append('#include <shellapi.h>')
    lines.append('#include <stdio.h>')
    lines.append('#include "recomp/recomp_types.h"')
    lines.append('')
    lines.append('/* Generic stdcall function pointer types by arg count */')
    for n in range(15):
        params = ', '.join(['uint32_t'] * n) if n > 0 else 'void'
        lines.append(f'typedef uint32_t (__stdcall *STDFN{n})({params});')
    lines.append('')

    # Collect all bridge entries
    bridge_entries = []
    bridge_idx = 0

    # Group by DLL
    dll_groups = {}
    for imp in imports_list:
        dll = imp['dll']
        if dll not in dll_groups:
            dll_groups[dll] = []
        name = imp['name'] or f'ordinal_{imp["ordinal"]}'
        va = image_base + imp['iat_rva']
        dll_groups[dll].append((va, name, imp.get('ordinal')))

    for dll in sorted(dll_groups.keys()):
        lines.append(f'/* ======== {dll} ======== */')
        lines.append('')

        for va, name, ordinal in sorted(dll_groups[dll]):
            bridge_idx += 1
            bridge_va = 0xBB000000 + bridge_idx
            safe_name = f'bridge_{name}_{va:08X}'

            nargs = FUNC_ARGS.get(name, -2)

            if nargs == -2:
                # Unknown or DirectX - stub
                lines.append(f'static void {safe_name}(void) {{ /* {dll}:{name} */')
                lines.append(f'    static int w = 0;')
                lines.append(f'    if (!w) {{ fprintf(stderr, "STUB: {dll}:{name}\\n"); w = 1; }}')
                lines.append(f'    g_eax = 0; g_esp += 4;')
                lines.append(f'}}')
            elif nargs == -1:
                # wsprintfA varargs - special
                lines.append(f'static void {safe_name}(void) {{ /* {dll}:{name} */')
                lines.append(f'    /* wsprintfA is cdecl varargs */')
                lines.append(f'    uint32_t buf = MEM32(g_esp + 4);')
                lines.append(f'    uint32_t fmt = MEM32(g_esp + 8);')
                lines.append(f'    g_eax = (uint32_t)wvsprintfA((LPSTR)(uintptr_t)buf, (LPCSTR)(uintptr_t)fmt, (va_list)(void*)ADDR(g_esp + 12));')
                lines.append(f'    g_esp += 4; /* cdecl: caller cleans */')
                lines.append(f'}}')
            else:
                # Standard bridge using GetProcAddress + generic call
                lines.append(f'static void {safe_name}(void) {{ /* {dll}:{name} ({nargs} args) */')

                if nargs == 0:
                    lines.append(f'    static STDFN0 fn = NULL;')
                    lines.append(f'    if (!fn) fn = (STDFN0)GetProcAddress(GetModuleHandleA("{dll}"), "{name}");')
                    lines.append(f'    if (fn) g_eax = fn();')
                    lines.append(f'    g_esp += 4;')
                else:
                    lines.append(f'    static STDFN{nargs} fn = NULL;')
                    lines.append(f'    if (!fn) fn = (STDFN{nargs})GetProcAddress(GetModuleHandleA("{dll}"), "{name}");')
                    # Read args
                    for i in range(nargs):
                        lines.append(f'    uint32_t a{i} = MEM32(g_esp + {4 + i*4});')
                    args = ', '.join(f'a{i}' for i in range(nargs))
                    lines.append(f'    if (fn) g_eax = fn({args});')
                    lines.append(f'    g_esp += {4 + nargs * 4};')

                lines.append(f'}}')

            lines.append('')
            bridge_entries.append((va, bridge_va, safe_name))

    # Registration function
    lines.append('/* ======== Bridge Registration ======== */')
    lines.append('')
    lines.append('extern recomp_dispatch_entry_t g_import_bridges[];')
    lines.append('extern int g_import_bridge_count;')
    lines.append('')
    lines.append('void register_import_bridges(void) {')
    lines.append(f'    /* {len(bridge_entries)} import bridges */')

    for i, (iat_va, bridge_va, func_name) in enumerate(sorted(bridge_entries)):
        lines.append(f'    MEM32(0x{iat_va:08X}) = 0x{bridge_va:08X}u;')
        lines.append(f'    g_import_bridges[{i}].address = 0x{bridge_va:08X}u;')
        lines.append(f'    g_import_bridges[{i}].func = {func_name};')

    lines.append(f'    g_import_bridge_count = {len(bridge_entries)};')
    lines.append(f'    printf("[*] Registered %d import bridges\\n", g_import_bridge_count);')
    lines.append('}')

    with open(output, 'w') as f:
        f.write('\n'.join(lines) + '\n')

    print(f'[*] Generated {len(bridge_entries)} bridges to {output}')


if __name__ == '__main__':
    main()
