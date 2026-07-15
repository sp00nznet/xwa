"""
Live-debug the REAL (decrypted) XWA game via the Win32 debug API, to observe what
the real functions do at runtime (ground truth to fix the recomp against). Since the
recomp uses g_mem_base=0, real-game globals live at the same VAs as the recomp.

Logs: process/DLL loads, exceptions (where it crashes/exits), OutputDebugString.
Optional: software breakpoints (0xCC) at addresses -> dumps EAX/ECX/.../ESP + memory.

Usage: py -3.11 tools/dbg_real.py [0xBPADDR ...]
Run from anywhere; it launches xwa_real.exe in the game dir.
"""
import ctypes, sys, os, shutil
from ctypes import wintypes, Structure, Union, POINTER, byref, sizeof, c_void_p, c_char

GAME = r'D:\recomp\pc\xwa\Star Wars X-Wing Alliance'
SRC_EXE = r'E:\ida\work\xwa\xwa_decrypted.exe'
k = ctypes.windll.kernel32
k.WaitForDebugEvent.argtypes = [c_void_p, wintypes.DWORD]

class EXCEPTION_RECORD(Structure):
    _fields_ = [("ExceptionCode", wintypes.DWORD), ("ExceptionFlags", wintypes.DWORD),
                ("ExceptionRecord", c_void_p), ("ExceptionAddress", c_void_p),
                ("NumberParameters", wintypes.DWORD), ("ExceptionInformation", c_void_p * 15)]
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]
class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [("hFile", wintypes.HANDLE), ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("lpBaseOfImage", c_void_p), ("dwDebugInfoFileOffset", wintypes.DWORD), ("nDebugInfoSize", wintypes.DWORD),
                ("lpThreadLocalBase", c_void_p), ("lpStartAddress", c_void_p), ("lpImageName", c_void_p), ("fUnicode", wintypes.WORD)]
class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [("hFile", wintypes.HANDLE), ("lpBaseOfDll", c_void_p), ("dwDebugInfoFileOffset", wintypes.DWORD),
                ("nDebugInfoSize", wintypes.DWORD), ("lpImageName", c_void_p), ("fUnicode", wintypes.WORD)]
class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]
class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [("lpDebugStringData", c_void_p), ("fUnicode", wintypes.WORD), ("nDebugStringLength", wintypes.WORD)]
class DBG_U(Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                ("LoadDll", LOAD_DLL_DEBUG_INFO), ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
                ("DebugString", OUTPUT_DEBUG_STRING_INFO), ("_pad", c_char * 200)]
class DEBUG_EVENT(Structure):
    _fields_ = [("dwDebugEventCode", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD), ("u", DBG_U)]
class STARTUPINFO(Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", c_void_p), ("lpDesktop", c_void_p), ("lpTitle", c_void_p),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD), ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", c_void_p), ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]
class PROCESS_INFORMATION(Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]
# CONTEXT (x86) -- only need the integer regs; use a raw buffer + offsets
class CONTEXT(Structure):
    _fields_ = [("ContextFlags", wintypes.DWORD)] + [("Dr%d"%i, wintypes.DWORD) for i in range(7)] + \
               [("FloatSave", c_char * 112), ("SegGs", wintypes.DWORD), ("SegFs", wintypes.DWORD),
                ("SegEs", wintypes.DWORD), ("SegDs", wintypes.DWORD),
                ("Edi", wintypes.DWORD), ("Esi", wintypes.DWORD), ("Ebx", wintypes.DWORD), ("Edx", wintypes.DWORD),
                ("Ecx", wintypes.DWORD), ("Eax", wintypes.DWORD), ("Ebp", wintypes.DWORD), ("Eip", wintypes.DWORD),
                ("SegCs", wintypes.DWORD), ("EFlags", wintypes.DWORD), ("Esp", wintypes.DWORD), ("SegSs", wintypes.DWORD),
                ("Extended", c_char * 512)]
CONTEXT_FULL = 0x10007

def rpm(hproc, addr, n):
    buf = (c_char * n)(); read = ctypes.c_size_t(0)
    k.ReadProcessMemory(hproc, c_void_p(addr), buf, n, byref(read))
    return buf.raw[:read.value]
def wpm(hproc, addr, data):
    written = ctypes.c_size_t(0)
    k.WriteProcessMemory(hproc, c_void_p(addr), data, len(data), byref(written))

def main():
    bps = [int(a, 16) for a in sys.argv[1:]]
    real = os.path.join(GAME, 'xwa_real.exe'); shutil.copy(SRC_EXE, real)
    si = STARTUPINFO(); si.cb = sizeof(si); pi = PROCESS_INFORMATION()
    DEBUG_PROCESS = 0x1  # follow child processes too (in case the launcher spawns the game)
    cmd = ctypes.create_string_buffer(b'xwa_real.exe')
    ok = k.CreateProcessA(real.encode(), cmd, None, None, False,
                          DEBUG_PROCESS, None, GAME.encode(), byref(si), byref(pi))
    if not ok:
        print('CreateProcess failed', ctypes.get_last_error()); return
    print(f'launched real game pid={pi.dwProcessId}; breakpoints={[hex(b) for b in bps]}')
    de = DEBUG_EVENT(); hproc = None; saved = {}; nev = 0; nexc = 0
    import time; t0 = time.time(); last_idle = 0
    while time.time() - t0 < 600:
        if not k.WaitForDebugEvent(byref(de), 1000):
            el = int(time.time() - t0)
            if el - last_idle >= 30:   # heartbeat every ~30s while idle at launcher/menus
                print(f'(idle {el}s -- navigate the game; breakpoints armed)'); last_idle = el; sys.stdout.flush()
            continue
        code = de.dwDebugEventCode; cont = 0x00010002  # DBG_CONTINUE
        if code == 3:  # CREATE_PROCESS
            hproc = de.u.CreateProcessInfo.hProcess
            base = de.u.CreateProcessInfo.lpBaseOfImage or 0
            print(f'CREATE_PROCESS base=0x{base:X}')
            for b in bps:
                orig = rpm(hproc, b, 1)
                if orig: saved[b] = orig; wpm(hproc, b, b'\xCC')
            if bps: print(f'  set {len(saved)} breakpoints')
        elif code == 6:  # LOAD_DLL
            nm = ''
            p = de.u.LoadDll.lpImageName
            if p:
                pa = int.from_bytes(rpm(hproc, p, 4), 'little')
                if pa:
                    raw = rpm(hproc, pa, 260)
                    nm = raw.split(b'\x00\x00')[0].replace(b'\x00', b'').decode('latin1', 'ignore') if de.u.LoadDll.fUnicode else raw.split(b'\x00')[0].decode('latin1', 'ignore')
            b = de.u.LoadDll.lpBaseOfDll or 0
            if any(x in nm.lower() for x in ('ddraw', 'd3d', 'dplay', 'dinput', 'dsound', 'glide', 'a3d')) or not nm:
                print(f'  LOAD_DLL 0x{b:X} {nm}')
        elif code == 8:  # OUTPUT_DEBUG_STRING
            p = de.u.DebugString.lpDebugStringData; n = de.u.DebugString.nDebugStringLength
            s = rpm(hproc, p, min(n, 200)).split(b'\x00')[0].decode('latin1', 'ignore')
            print(f'  ODS: {s.strip()}')
        elif code == 1:  # EXCEPTION
            exc = de.u.Exception.ExceptionRecord; ec = exc.ExceptionCode & 0xFFFFFFFF; ea = exc.ExceptionAddress or 0
            if ec == 0x80000003 and ea in saved:  # our breakpoint
                hth = k.OpenThread(0x1F03FF, False, de.dwThreadId)  # THREAD_ALL_ACCESS
                ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
                k.GetThreadContext(hth, byref(ctx))
                # for a stdcall fn at entry, args are at [esp+4], [esp+8], ...; dump a few + try strings
                a1 = int.from_bytes(rpm(hproc, ctx.Esp + 4, 4) or b'\0\0\0\0', 'little')
                def s(p):
                    if 0x10000 < p < 0x10000000:
                        r = rpm(hproc, p, 64).split(b'\x00')[0]
                        if r and all(32 <= c < 127 for c in r[:8]): return r.decode('latin1','ignore')
                    return ''
                a2 = int.from_bytes(rpm(hproc, ctx.Esp + 8, 4) or b'\0\0\0\0', 'little')
                a3 = int.from_bytes(rpm(hproc, ctx.Esp + 12, 4) or b'\0\0\0\0', 'little')
                import time as _t
                print(f'  *** BP 0x{ea:X} @{int(_t.time()-t0)}s: eax=0x{ctx.Eax:X}({s(ctx.Eax)}) ecx=0x{ctx.Ecx:X} edx=0x{ctx.Edx:X} ebx=0x{ctx.Ebx:X} esi=0x{ctx.Esi:X}({s(ctx.Esi)}) edi=0x{ctx.Edi:X} esp=0x{ctx.Esp:X}\n        args=[0x{a1:X}({s(a1)}), 0x{a2:X}({s(a2)}), 0x{a3:X}({s(a3)})]')
                sys.stdout.flush()
                # ONE-SHOT: restore byte, back up EIP, continue (do not re-arm)
                wpm(hproc, ea, saved[ea]); ctx.Eip = ea
                k.SetThreadContext(hth, byref(ctx)); k.CloseHandle(hth)
                del saved[ea]
            else:
                nexc += 1
                if nexc <= 12:
                    fc = de.u.Exception.dwFirstChance
                    print(f'  EXCEPTION 0x{ec:08X} at 0x{ea:X} firstChance={fc}')
                cont = 0x80010001  # DBG_EXCEPTION_NOT_HANDLED (let the app handle/crash)
        elif code == 5:  # EXIT_PROCESS
            print(f'EXIT_PROCESS code={de.u.ExitProcess.dwExitCode}'); break
        nev += 1
        k.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)
    print(f'done: {nev} events, {nexc} non-bp exceptions')
    try: k.TerminateProcess(pi.hProcess, 0)
    except Exception: pass
    try: os.remove(real)
    except Exception: pass

if __name__ == '__main__':
    main()
