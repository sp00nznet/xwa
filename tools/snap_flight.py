"""
Snapshot the REAL running XWA's flight state, so the recomp can be made to match
instead of guessed at. Read-only (PROCESS_VM_READ, no debugger -> no SteamStub
anti-debug trip). Guest VAs == recomp VAs because g_mem_base=0.

Usage:
    1. Launch XWA (Steam or the decrypted exe), fly into a mission -- be IN space,
       cockpit up, ships visible.
    2. py -3.11 tools/snap_flight.py [outfile]      (default: snap_flight.txt)

Dumps the exact fields the recomp's flight path gets wrong: the FG table, the
player craft record, the render object (ro = FG+0x23) and its scene pointer
(ro+0xDD), the camera matrix, and the HUD mask buffers.
"""
import ctypes, sys, time
from ctypes import wintypes, byref, c_char, c_size_t, c_void_p

k = ctypes.windll.kernel32
sys.path.insert(0, 'tools')
from poll_real import find_pid

CANDIDATES = [b'xwa_recomp.exe', b'xwingalliance.exe', b'xwa_real.exe', b'xwa_decrypted.exe', b'XWingAlliance.exe']


def open_game():
    for nm in CANDIDATES:
        pid = find_pid(nm)
        if pid:
            h = k.OpenProcess(0x10 | 0x400, False, pid)   # VM_READ | QUERY_INFORMATION
            if h:
                return nm.decode(), pid, h
    return None, None, None


class Mem:
    def __init__(self, h):
        self.h = h

    def rd(self, a, n):
        buf = (c_char * n)(); got = c_size_t(0)
        k.ReadProcessMemory(self.h, c_void_p(a), buf, n, byref(got))
        return buf.raw[:got.value]

    def u8(self, a):
        b = self.rd(a, 1); return b[0] if b else None

    def u16(self, a):
        b = self.rd(a, 2); return int.from_bytes(b, 'little') if len(b) == 2 else None

    def u32(self, a):
        b = self.rd(a, 4); return int.from_bytes(b, 'little') if len(b) == 4 else None

    def i32(self, a):
        v = self.u32(a); return v - (1 << 32) if v is not None and v >= (1 << 31) else v


def hexdump(data, base, out, width=16):
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = ' '.join(f'{c:02X}' for c in chunk)
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        out(f'    {base + off:08X}  {hexs:<{width * 3}} {txt}')


# (label, address) globals worth capturing verbatim
GLOBALS = [
    ('A1C089  screen depth',      0xA1C089), ('ABD7B4  game mode',        0xABD7B4),
    ('77330C  session flag',      0x77330C), ('773310',                   0x773310),
    ('A21449  DP object',         0xA21449), ('9AFEE4  DP saved obj',     0x9AFEE4),
    ('7B33C4  FG table',          0x7B33C4), ('63185C  FG count (u16)',   0x63185C),
    ('8C1CC8  player slot',       0x8C1CC8), ('7CA3B8  craft loop end',   0x7CA3B8),
    ('8BF378  craft loop start',  0x8BF378), ('7B4C00  obj count (u16)',  0x7B4C00),
    ('8052A0  obj pool',          0x8052A0), ('8C1CE4  view count',       0x8C1CE4),
    ('80B610  obj stride div',    0x80B610), ('8B94C8  obj count2',       0x8B94C8),
    ('7D5240  FG total',          0x7D5240), ('7828D0  ALERTBOXBUFFER ptr',    0x7828D0),
    ('9109C0  render fn ptr',     0x9109C0), ('7B1CE0  scene ptr',        0x7B1CE0),
    ('7B1CE8  render ctx',        0x7B1CE8), ('7B1CD4  render flags',     0x7B1CD4),
    ('68C898  HUD mask A',        0x68C898), ('68C89C  HUD mask B',       0x68C89C),
    ('693594  rasterizer mode',   0x693594), ('7CA3A8  screen h',         0x7CA3A8),
    ('7D4B6C  screen w',          0x7D4B6C), ('8D6BB0  render gate',      0x8D6BB0),
    ('8BA034  camera ref craft',  0x8BA034), ('8BA028  camera X',         0x8BA028),
    ('8BA02C  camera Y',          0x8BA02C), ('8BA030  camera Z',         0x8BA030),
    ('80DC80  species tbl',       0x80DC80), ('80DCBC  species entry',    0x80DCBC),
    ('9F4B98  skirmish buf',      0x9F4B98), ('9EB8E0  craft tbl',        0x9EB8E0),
    ('AE2A8A  mission index',     0xAE2A8A), ('7B1D04  block list cnt',   0x7B1D04),
    # --- the render-gate chain traced in xwa-flight-entry #201..#209 -------------
    ('7733CC  Begin/End nesting', 0x7733CC), ('5FFD9C  render mode',      0x5FFD9C),
    ('7CA1EC  viewport buf ptr',  0x7CA1EC), ('63CF40  vp buf handle',     0x63CF40),
    ('63CF50  vp buf handle2',    0x63CF50), ('5FFDAC  input poll mode',   0x5FFDAC),
    ('910780  render alloc',      0x910780), ('7828D4  alertbox size',     0x7828D4),
]

FG_STRIDE = 0x27
OBJ_STRIDE = 0xBCF


def main():
    outpath = sys.argv[1] if len(sys.argv) > 1 else 'snap_flight.txt'
    name, pid, h = open_game()
    if not h:
        print('No running XWA found. Tried: ' + ', '.join(c.decode() for c in CANDIDATES))
        print('Launch the game and fly into a mission, then re-run.')
        return 1
    m = Mem(h)
    lines = []
    def out(s=''):
        lines.append(s); print(s)

    out(f'=== XWA live flight snapshot: {name} pid={pid} ===')

    depth = m.u32(0xA1C089) or 0
    cb = m.u32(0xA1C8D5 + 0x850 * (depth & 0xFF))
    named = {0x0049E600: '*** 3D FLIGHT FRAME ***', 0x005710F0: 'FLIGHT INIT',
             0x005316B0: 'LOADING', 0x005397D0: 'concourse', 0x0053B500: 'combat sim',
             0x005438B0: 'skirmish setup'}.get(cb, '')
    out(f'active screen cb = 0x{cb:08X} (depth={depth}) {named}')
    if cb not in (0x005710F0, 0x0049E600):
        out('!! NOT on a flight screen -- fly into a mission first; the numbers below')
        out('   will be from whatever screen is up, which is not what we need.')
    out()

    out('=== globals ===')
    for label, addr in GLOBALS:
        v = m.u32(addr)
        out(f'  {label:<26} @0x{addr:06X} = ' + ('<unreadable>' if v is None else f'0x{v:08X} ({v})'))
    out()

    out('=== camera view matrix 0x8D93C0..0x8D9400 ===')
    hexdump(m.rd(0x8D93C0, 0x40), 0x8D93C0, out)
    out('=== camera matrix SOURCE 0x693774..0x6937B0 ===')
    hexdump(m.rd(0x693774, 0x3C), 0x693774, out)
    out()

    fgt = m.u32(0x7B33C4) or 0
    fgn = m.u16(0x63185C) or 0
    out(f'=== flight groups: table=0x{fgt:08X} count={fgn} (stride 0x{FG_STRIDE:X}) ===')
    for i in range(min(fgn, 24)):
        base = fgt + i * FG_STRIDE
        raw = m.rd(base, FG_STRIDE)
        if len(raw) != FG_STRIDE:
            out(f'  FG[{i}] @0x{base:08X} <unreadable>'); continue
        typ = int.from_bytes(raw[2:4], 'little')
        slot = raw[5]
        px, py, pz = (int.from_bytes(raw[o:o + 4], 'little', signed=True) for o in (7, 0xB, 0xF))
        ro = int.from_bytes(raw[0x23:0x27], 'little')
        out(f'  FG[{i:2}] @0x{base:08X} type={typ:<5} slot={slot:<3} pos=({px},{py},{pz}) ro=0x{ro:08X}')
        hexdump(raw, base, out)
    out()

    pslot = m.u32(0x8C1CC8)
    out(f'=== player craft: slot 0x8C1CC8 = {pslot} ===')
    if pslot is not None and pslot < 0x400:
        rec = 0x8B94E0 + pslot * OBJ_STRIDE
        fgidx = m.u32(rec)
        out(f'  record @0x{rec:08X}  FGidx(+0)=0x{fgidx:X}')
        for off, nm2 in ((0x4, 'f4'), (0x10, 'craftType'), (0x11, 'tag'), (0x15, 'built'),
                         (0xEE, 'craftID'), (0xF0, 'type'), (0xF1, 'active'), (0xF5, 'f5')):
            out(f'    +0x{off:03X} {nm2:<10} = 0x{m.u8(rec + off):02X}')
        out('  first 0x100 bytes of the player object record:')
        hexdump(m.rd(rec, 0x100), rec, out)

        if fgidx is not None and fgidx != 0xFFFF and fgt:
            fgb = fgt + fgidx * FG_STRIDE
            ro = m.u32(fgb + 0x23)
            out(f'  player FG[{fgidx}] @0x{fgb:08X}  ro(+0x23)=0x{ro:08X}')
            if ro:
                out('  === RENDER OBJECT (ro) first 0x120 bytes ===')
                hexdump(m.rd(ro, 0x120), ro, out)
                scene = m.u32(ro + 0xDD)
                out(f'  ro+0xDD (scene/craft ptr) = 0x{scene:08X}   ro+0xD9 = 0x{m.u32(ro + 0xD9):08X}'
                    f'   ro+0x8D = 0x{m.u32(ro + 0x8D):08X}   ro+0 (model) = 0x{m.u32(ro):08X}')
                if scene:
                    out('  === ro+0xDD target (the thing GetCraftPointer returns) first 0x100 ===')
                    hexdump(m.rd(scene, 0x100), scene, out)
    out()

    # The player record path above bails when 8B94E0[+0]==0xFFFF, which is what the REAL
    # game shows in flight -- so dump the FG render objects directly, unconditionally.
    out('=== render objects (ro = FG+0x23), first 4 FGs, 0xE5 bytes each ===')
    for i in range(min(fgn, 4)):
        ro = m.u32(fgt + i * FG_STRIDE + 0x23)
        if not ro:
            out(f'  FG[{i}] ro = 0'); continue
        out(f'  --- FG[{i}] ro = 0x{ro:08X} ---')
        hexdump(m.rd(ro, 0xE5), ro, out)
        for off in (0x00, 0x04, 0x08, 0x0C, 0x8D, 0xD9, 0xDD, 0xE1):
            out(f'      ro+0x{off:02X} = 0x{m.u32(ro + off):08X}')
        scene = m.u32(ro + 0xDD)
        if scene and 0x10000 < scene < 0x7FFFFFFF:
            out(f'      === ro+0xDD target 0x{scene:08X} first 0x80 ===')
            hexdump(m.rd(scene, 0x80), scene, out)
    out()

    out('=== object pool head 0x8052A0 -> first 0x100 ===')
    pool = m.u32(0x8052A0)
    if pool:
        hexdump(m.rd(pool, 0x100), pool, out)
    out()

    out('=== object slots 0..39 (0x8B94E0, stride 0xBCF) ===')
    for s in range(40):
        rec = 0x8B94E0 + s * OBJ_STRIDE
        fgidx = m.u32(rec)
        if fgidx is None or fgidx == 0xFFFF:
            continue
        out(f'  slot[{s:2}] FGidx=0x{fgidx:X} type(+0x10)=0x{m.u8(rec+0x10):02X} '
            f'tag(+0x11)=0x{m.u8(rec+0x11):02X} active(+0xF1)=0x{m.u8(rec+0xF1):02X}')

    with open(outpath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'\nwrote {outpath} ({len(lines)} lines)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
