"""Read the partition / spawn globals out of the RUNNING retail game.

Read-only (PROCESS_VM_READ, no debugger -> does not trip the SteamStub anti-debug), and retail VAs
equal the recomp's because the image has no relocations and g_mem_base = 0.

The port's force-launch runs partition 1 with base 632 while the mission's real objects sit at
indices 0..6 (partition 0), which stalls both the render walk and the craft-create loop. This says
what the real game has in those same globals.

Usage:  py tools/peek_partition.py [seconds]     (fly a mission, then run it)
"""
import ctypes, sys, time
from ctypes import byref, c_char, c_size_t, c_void_p

sys.path.insert(0, 'tools')
from poll_real import find_pid

k = ctypes.windll.kernel32
CANDIDATES = [b'xwingalliance.exe', b'XWingAlliance.exe', b'xwa_recomp.exe']

GLOBALS = [
    (0x8C1CD8, 4, 'partition index (written by sub_004154A0)'),
    (0x8D9624, 4, 'partition divisor'),
    (0x7D5240, 4, 'total slots'),
    (0x917E40, 4, 'partition base  <- create loop start'),
    (0x8BF378, 4, 'partition base (copy)'),
    (0x8BF380, 4, 'craft count     <- create loop end'),
    (0x7CA3B4, 4, 'object walk start'),
    (0x7CA3B8, 4, 'object walk end'),
    (0x917E64, 4, 'object table count'),
    (0x80B61C, 2, 'pending-create cursor'),
    (0x7B33C4, 4, 'object table pointer'),
    (0x8B94D4, 4, 'sim last-simulated time'),
    (0x7D4B8C, 4, 'frame timer'),
    (0x8C1CC8, 4, 'player slot'),
]

def main():
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    pid = name = None
    for nm in CANDIDATES:
        pid = find_pid(nm)
        if pid:
            name = nm.decode()
            break
    if not pid:
        print('no XWA process found (tried %s)' % ', '.join(c.decode() for c in CANDIDATES))
        return 1
    h = k.OpenProcess(0x10 | 0x400, False, pid)   # VM_READ | QUERY_INFORMATION
    if not h:
        print('OpenProcess failed for pid %d' % pid)
        return 1
    print('attached to %s (pid %d)\n' % (name, pid))

    def rd(a, n):
        buf = (c_char * n)(); got = c_size_t(0)
        k.ReadProcessMemory(h, c_void_p(a), buf, n, byref(got))
        return buf.raw[:got.value] if got.value == n else None

    def num(a, n):
        b = rd(a, n)
        return int.from_bytes(b, 'little') if b else None

    while True:
        print('--- %s ---' % time.strftime('%H:%M:%S'))
        for addr, size, label in GLOBALS:
            v = num(addr, size)
            print('  0x%08X  %-38s = %s' % (addr, label,
                  ('%d (0x%X)' % (v, v)) if v is not None else 'unreadable'))
        tbl = num(0x7B33C4, 4)
        cnt = num(0x917E64, 4)
        if tbl and cnt and cnt < 4096:
            live = []
            for i in range(cnt):
                o = tbl + i * 0x27
                b = rd(o, 0x27)
                if not b:
                    continue
                alive = int.from_bytes(b[2:4], 'little')
                if not alive:
                    continue
                ty = int.from_bytes(b[0:2], 'little')
                px = int.from_bytes(b[7:11], 'little', signed=True)
                py = int.from_bytes(b[11:15], 'little', signed=True)
                pz = int.from_bytes(b[15:19], 'little', signed=True)
                live.append((i, ty, b[4], px, py, pz))
            print('  live objects: %d' % len(live))
            for e in live[:12]:
                print('     [%4d] type=%-4d cat=%-3d pos=(%d,%d,%d)' % e)
            if len(live) > 12:
                print('     ... and %d more' % (len(live) - 12))
        if secs <= 0:
            break
        time.sleep(secs)
    return 0

if __name__ == '__main__':
    sys.exit(main())
