"""
NON-INTRUSIVE memory poller for the REAL (Steam) XWA game. Opens the running
xwingalliance.exe with PROCESS_VM_READ only (NOT a debugger -> does not trip the
SteamStub anti-debug) and polls the key globals the recomp uses (same VAs, since
g_mem_base=0). Run it, then fly a mission in the game; it logs the real values
(session string, descriptor, object count, session handle, active screen, ...).

Usage: py -3.11 tools/poll_real.py            # auto-find xwingalliance.exe
"""
import ctypes, sys, time
from ctypes import wintypes, byref, c_char, c_size_t, c_void_p
k = ctypes.windll.kernel32

TH32CS_SNAPPROCESS = 0x2
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", c_void_p), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                ("szExeFile", c_char * 260)]

def find_pid(name=b'xwingalliance.exe'):
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32(); pe.dwSize = ctypes.sizeof(pe)
    found = None
    if k.Process32First(snap, byref(pe)):
        while True:
            if pe.szExeFile.lower() == name.lower(): found = pe.th32ProcessID; break
            if not k.Process32Next(snap, byref(pe)): break
    k.CloseHandle(snap); return found

def main():
    pid = None
    for _ in range(120):                    # wait up to ~2min for the game to be launched
        pid = find_pid()
        if pid: break
        time.sleep(1)
    if not pid:
        print('xwingalliance.exe not running -- launch it via Steam first.'); return
    PROCESS_VM_READ = 0x10; PROCESS_QUERY_INFORMATION = 0x400
    h = k.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print('OpenProcess failed', ctypes.get_last_error()); return
    print(f'attached (read-only) to xwingalliance.exe pid={pid}; polling globals -- fly a mission now')

    def rd(addr, n):
        buf = (c_char * n)(); got = c_size_t(0)
        k.ReadProcessMemory(h, c_void_p(addr), buf, n, byref(got))
        return buf.raw[:got.value]
    def u32(a):
        b = rd(a, 4); return int.from_bytes(b, 'little') if len(b) == 4 else 0
    def u16(a):
        b = rd(a, 2); return int.from_bytes(b, 'little') if len(b) == 2 else 0
    def s(a, n=72):
        b = rd(a, n).split(b'\x00')[0]
        return b.decode('latin1', 'ignore') if b and all(9 <= c < 127 for c in b) else ''
    def sp(a):           # follow ptr-at-a then read string
        p = u32(a); return s(p) if 0x10000 < p < 0x10000000 else ''

    last = None
    t0 = time.time()
    while time.time() - t0 < 1200:
        idx = u32(0xAE2A8A)
        snapshot = (
            s(0x783ED8),                       # session string
            idx, u16(idx * 4 + 0xAE2A8E),       # descriptor index + mission id
            u32(0x7B4C00),                      # object count
            u32(0xA21481), u32(0xA21449),       # session handle, loopback gate
            u32(0x9F4B98), u32(0x9F5EC0),       # mission list ptr + count
            u32(0xABD7B4), u32(0x782FFC),       # game mode + combat-sim view
            u32(0xA1C8D5 + 0x850 * (u32(0xA1C089) & 7)),  # active screen cb
            s(0x7732F0), s(0x773308), u32(0x782878),       # world-build path fields
        )
        if snapshot != last:
            cb = snapshot[10]
            print(f'[{int(time.time()-t0)}s] cb=0x{cb:X} ABD7B4={snapshot[8]} 782FFC={snapshot[9]} | '
                  f'session="{snapshot[0]}" AE2A8A={snapshot[1]} missID=0x{snapshot[2]:04X} '
                  f'objcount={snapshot[3]} A21481=0x{snapshot[4]:X} A21449=0x{snapshot[5]:X} '
                  f'list=0x{snapshot[6]:X}/{snapshot[7]} | f0="{snapshot[11]}" f6="{snapshot[12]}" 782878={snapshot[13]}')
            sys.stdout.flush()
            last = snapshot
        time.sleep(0.5)
    print('poll window ended')

if __name__ == '__main__':
    main()
