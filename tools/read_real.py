import ctypes, sys
from ctypes import byref, c_char, c_size_t, c_void_p
k = ctypes.windll.kernel32
sys.path.insert(0, 'tools')
from poll_real import find_pid
pid = find_pid()
if not pid:
    print('xwingalliance.exe not running'); sys.exit()
h = k.OpenProcess(0x410, False, pid)
def rd(a, n):
    b = (c_char * n)(); g = c_size_t(0); k.ReadProcessMemory(h, c_void_p(a), b, n, byref(g)); return b.raw[:g.value]
def u32(a): return int.from_bytes(rd(a, 4), 'little')
def u16(a): return int.from_bytes(rd(a, 2), 'little')
print(f'pid={pid}')
print('=== FULL session string @0x783ED8 (200 bytes raw) ===')
raw = rd(0x783ED8, 200)
print(repr(raw))
print('=== AE2A8A + descriptor array AE2A8E[0..8] ===')
print('AE2A8A =', u32(0xAE2A8A))
print('  ' + ' '.join(f'[{i}]=0x{u16(0xAE2A8E + i*4):04X}' for i in range(9)))
print('=== world-build path fields 0x7732F0..773308 (ptr -> str) ===')
for off in range(0x7732F0, 0x77330C, 4):
    p = u32(off); st = rd(p, 48).split(b'\x00')[0] if 0x10000 < p < 0x10000000 else b''
    print(f'  0x{off:X} -> 0x{p:X}  {st!r}')
print('=== object count / arrays ===')
for a in (0x7B4C00, 0x80DC80, 0x9AFEE4, 0x9AFEE0):
    print(f'  0x{a:X} = {u32(a)} (0x{u32(a):X})')
print('=== mode/session globals ===')
for a, nm in [(0xABD7B4,'ABD7B4'),(0xAE2A86,'AE2A86'),(0xA21481,'A21481'),(0xA21449,'A21449'),(0x9F4B98,'9F4B98'),(0x9F5EC0,'9F5EC0'),(0x782878,'782878'),(0x91AD34,'91AD34_res')]:
    print(f'  {nm}=0x{u32(a):X} ({u32(a)})')
