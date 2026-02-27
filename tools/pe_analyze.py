"""
PE Binary Analyzer for X-Wing Alliance static recompilation.
Parses PE headers, sections, imports, exports, and extracts metadata
needed by the disassembler and lifter.
"""

import sys
import json
import struct
import pefile
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & 0x20000020)  # IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE

    @property
    def is_data(self) -> bool:
        return bool(self.characteristics & 0x00000040)  # IMAGE_SCN_CNT_INITIALIZED_DATA

    @property
    def va_end(self) -> int:
        return self.virtual_address + self.virtual_size


@dataclass
class ImportEntry:
    dll: str
    name: Optional[str]
    ordinal: Optional[int]
    iat_rva: int  # IAT slot address (RVA)


@dataclass
class PEInfo:
    filename: str
    image_base: int
    entry_point_rva: int
    timestamp: int
    linker_version: str
    sections: list
    imports: list
    code_start: int  # VA of first code byte
    code_end: int    # VA past last code byte
    data_start: int  # VA of first data byte
    data_end: int    # VA past last data byte


def analyze_pe(filepath: str) -> PEInfo:
    """Analyze a PE file and return structured metadata."""
    pe = pefile.PE(filepath)
    path = Path(filepath)

    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        sections.append(Section(
            name=name,
            virtual_address=s.VirtualAddress,
            virtual_size=s.Misc_VirtualSize,
            raw_offset=s.PointerToRawData,
            raw_size=s.SizeOfRawData,
            characteristics=s.Characteristics,
        ))

    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = dll_entry.dll.decode('ascii', errors='replace')
            for imp in dll_entry.imports:
                imports.append(ImportEntry(
                    dll=dll_name,
                    name=imp.name.decode('ascii', errors='replace') if imp.name else None,
                    ordinal=imp.ordinal if not imp.name else None,
                    iat_rva=imp.address - pe.OPTIONAL_HEADER.ImageBase,
                ))

    # Find code and data boundaries
    code_sections = [s for s in sections if s.is_code and s.name != '.bind']
    data_sections = [s for s in sections if s.is_data and s.name not in ('.rsrc', '.bind', '.reloc')]

    code_start = min(s.virtual_address for s in code_sections) if code_sections else 0
    code_end = max(s.va_end for s in code_sections) if code_sections else 0
    data_start = min(s.virtual_address for s in data_sections) if data_sections else 0
    data_end = max(s.va_end for s in data_sections) if data_sections else 0

    image_base = pe.OPTIONAL_HEADER.ImageBase

    info = PEInfo(
        filename=path.name,
        image_base=image_base,
        entry_point_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        timestamp=pe.FILE_HEADER.TimeDateStamp,
        linker_version=f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion:02d}",
        sections=sections,
        imports=imports,
        code_start=image_base + code_start,
        code_end=image_base + code_end,
        data_start=image_base + data_start,
        data_end=image_base + data_end,
    )

    pe.close()
    return info


def va_to_file_offset(sections: list, va: int, image_base: int) -> Optional[int]:
    """Convert a virtual address to a file offset."""
    rva = va - image_base
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + s.raw_size:
            return s.raw_offset + (rva - s.virtual_address)
    return None


def read_bytes_at_va(filepath: str, sections: list, image_base: int, va: int, size: int) -> Optional[bytes]:
    """Read bytes from the PE file at a given virtual address."""
    offset = va_to_file_offset(sections, va, image_base)
    if offset is None:
        return None
    with open(filepath, 'rb') as f:
        f.seek(offset)
        return f.read(size)


def build_iat_map(info: PEInfo) -> dict:
    """Build a map from IAT VA -> (dll, function_name) for resolving import calls."""
    iat = {}
    for imp in info.imports:
        va = info.image_base + imp.iat_rva
        name = imp.name if imp.name else f"ordinal_{imp.ordinal}"
        iat[va] = (imp.dll, name)
    return iat


def print_summary(info: PEInfo):
    """Print a human-readable summary of the PE analysis."""
    print(f"=== {info.filename} ===")
    print(f"  Image Base:    0x{info.image_base:08X}")
    print(f"  Entry Point:   0x{info.image_base + info.entry_point_rva:08X} (RVA 0x{info.entry_point_rva:08X})")
    print(f"  Linker:        {info.linker_version}")
    print(f"  Code Range:    0x{info.code_start:08X} - 0x{info.code_end:08X} ({info.code_end - info.code_start:,} bytes)")
    print(f"  Data Range:    0x{info.data_start:08X} - 0x{info.data_end:08X} ({info.data_end - info.data_start:,} bytes)")
    print()
    print("  Sections:")
    for s in info.sections:
        flags = []
        if s.is_code: flags.append("CODE")
        if s.is_data: flags.append("DATA")
        if s.characteristics & 0x80000000: flags.append("WRITE")
        print(f"    {s.name:8s}  VA 0x{s.virtual_address:08X}  Size 0x{s.virtual_size:08X}  Raw 0x{s.raw_offset:08X}  [{', '.join(flags)}]")
    print()
    print(f"  Imports: {len(info.imports)} functions from {len(set(i.dll for i in info.imports))} DLLs")
    by_dll = {}
    for imp in info.imports:
        by_dll.setdefault(imp.dll, []).append(imp)
    for dll, imps in sorted(by_dll.items()):
        print(f"    {dll}: {len(imps)} imports")
        for imp in imps[:5]:
            name = imp.name if imp.name else f"ordinal {imp.ordinal}"
            print(f"      0x{info.image_base + imp.iat_rva:08X}  {name}")
        if len(imps) > 5:
            print(f"      ... and {len(imps) - 5} more")


def export_json(info: PEInfo, output_path: str):
    """Export analysis to JSON for consumption by other tools."""
    data = {
        'filename': info.filename,
        'image_base': info.image_base,
        'entry_point': info.image_base + info.entry_point_rva,
        'code_start': info.code_start,
        'code_end': info.code_end,
        'data_start': info.data_start,
        'data_end': info.data_end,
        'sections': [asdict(s) for s in info.sections],
        'imports': [asdict(i) for i in info.imports],
        'iat_map': {
            f"0x{info.image_base + imp.iat_rva:08X}": {
                'dll': imp.dll,
                'name': imp.name if imp.name else f"ordinal_{imp.ordinal}"
            }
            for imp in info.imports
        }
    }
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Exported to {output_path}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pe_file> [--json output.json]")
        sys.exit(1)

    filepath = sys.argv[1]
    info = analyze_pe(filepath)
    print_summary(info)

    if '--json' in sys.argv:
        idx = sys.argv.index('--json')
        if idx + 1 < len(sys.argv):
            export_json(info, sys.argv[idx + 1])
