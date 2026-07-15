import sys, struct
sys.path.insert(0, 'D:/recomp/pc/xwa/recomp')
import pefile

pe = pefile.PE("D:/recomp/pc/xwa/Star Wars X-Wing Alliance/xwingalliance.exe")
image_base = pe.OPTIONAL_HEADER.ImageBase

def read_bytes(va, size):
    rva = va - image_base
    return pe.get_data(rva, size)

# === Jump table for sub_004CD6C0 ===
# RECOMP_ITAIL(MEM32(edx * 4 + 0x4CDDF0))
# First, find the index lookup table at 0x4CDE20
# SET_LO8(edx, MEM8(eax + 0x4CDE20)) -> edx is a byte index
# Then jump table at 0x4CDDF0

print("=== sub_004CD6C0 jump table ===")
print("Index table at 0x4CDE20:")
idx_table = read_bytes(0x4CDE20, 64)
print(f"  First 64 bytes: {idx_table.hex()}")
# Find max index value
max_idx = max(idx_table)
print(f"  Max index value: {max_idx}")

print("\nJump table at 0x4CDDF0:")
# Read enough entries
jmp_table = read_bytes(0x4CDDF0, (max_idx + 1) * 4)
for i in range(max_idx + 1):
    val = struct.unpack_from('<I', jmp_table, i * 4)[0]
    print(f"  [{i}] = 0x{val:08X}")

# Also figure out what range eax can be (compare before the index lookup)
# Look at the code: what's the bounds check?
print("\n\n=== sub_0058A7C0 jump table ===")
# RECOMP_ITAIL(MEM32(eax * 4 + 0x58AAB3))
# Bounds check: cmp dword ptr [ebp - 0x40], 8; ja 0x58AA98
# So eax is 0-8 (9 entries)
print("Jump table at 0x58AAB3:")
jmp_table2 = read_bytes(0x58AAB3, 9 * 4)
for i in range(9):
    val = struct.unpack_from('<I', jmp_table2, i * 4)[0]
    print(f"  [{i}] = 0x{val:08X}")

# These are addresses WITHIN sub_0058A7C0
# Let's map them to the labels we see in the generated code
print("\nExpected case targets in sub_0058A7C0:")
case_targets = {
    0x0058A84D: "case 0: L_0058A84D",
    0x0058A8AC: "case 1: L_0058A8AC",
    0x0058A8F3: "case 2: L_0058A8F3",
    0x0058A930: "case 3: L_0058A930",
    0x0058A96D: "case 4: L_0058A96D",
    0x0058A9AA: "case 5: L_0058A9AA",
    0x0058A9E7: "case 6: L_0058A9E7",
    0x0058AA24: "case 7: L_0058AA24",
    0x0058AA5E: "case 8: L_0058AA5E",
}
for addr, desc in sorted(case_targets.items()):
    print(f"  0x{addr:08X} -> {desc}")

print("\n\n=== Also check 0x4CE0B4 and 0x4CE4B8 jump tables ===")

# RECOMP_ITAIL(MEM32(edx * 4 + 0x4CE0B4))
# Index table at 0x4CE0DC
print("Index table at 0x4CE0DC:")
idx_table2 = read_bytes(0x4CE0DC, 32)
print(f"  First 32 bytes: {idx_table2.hex()}")
max_idx2 = max(idx_table2[:16])
print(f"  Max index value (first 16): {max_idx2}")

print("\nJump table at 0x4CE0B4:")
jmp_table3 = read_bytes(0x4CE0B4, (max_idx2 + 1) * 4)
for i in range(max_idx2 + 1):
    val = struct.unpack_from('<I', jmp_table3, i * 4)[0]
    print(f"  [{i}] = 0x{val:08X}")

# RECOMP_ITAIL(MEM32(ebp * 4 + 0x4CE4B8))
# Bounds check: cmp ebp, 0xC; ja 0x4CE49A -> 0-12 (13 entries)
print("\nJump table at 0x4CE4B8:")
jmp_table4 = read_bytes(0x4CE4B8, 13 * 4)
for i in range(13):
    val = struct.unpack_from('<I', jmp_table4, i * 4)[0]
    print(f"  [{i}] = 0x{val:08X}")
