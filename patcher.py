#!/usr/bin/env python3
"""
Requires:  pip install pefile capstone   (capstone only to measure the old function; skip with --func-size)
Usage:     python patcher.py g15.dll --dump        # hexdump the function
           python patcher.py g15.dll --dry-run     # show what each signature matched
           python patcher.py g15.dll --fix-pe      # fix the PE import for CommandLine for some versions of Source
           python patcher.py g15.dll               # write g15_patched.dll
"""
import argparse
import re
import struct
import sys
from pathlib import Path

import pefile

DEFAULT_DLL = "bin\\lgLcdApi_x86.dll"

# first bytes of the new stub: push ebx / call $+5 / pop ebx
STUB_SIGNATURE = bytes([0x53, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B])

IMPORT_OLD = "CommandLine_Tier0"
IMPORT_NEW = "CommandLine"

SIGNATURES = {
    "func_start": [
        "55 8B EC 83 EC ?? 53 8D 45",
    ],

    "cleanup_func": [
        "A1 ?? ?? ?? ?? 85 C0 74 ?? 50 FF 15",
    ],

    "var_hlibmodule": [
        "A1 @@ 85 C0 74 ?? 50 FF 15",
    ],

    # mov GetInterface, eax ; jz ; push 2
    "var_getinterface": [
        "A3 @@ 74 ?? 6A",
    ],

    # mov g_..., eax ; test ebx, ebx
    "var_interface": [
        "A3 @@ 85 DB",
    ],
}

IAT_NAMES = {"iat_loadlibrarya": "LoadLibraryA", "iat_getprocaddress": "GetProcAddress"}

def die(msg):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)

def u32(x):
    return x & 0xFFFFFFFF

def compile_aob(text):
    """-> (compiled regex, capture kind: None | 'abs' | 'rel')"""
    parts, kind = [], None
    for tok in text.split():
        if tok in ("??", "?"):
            parts.append(b".")
        elif tok in ("@@", "@rel"):
            if kind is not None:
                raise ValueError(f"more than one capture in signature: {text!r}")
            kind = "abs" if tok == "@@" else "rel"
            parts.append(b"(.{4})")
        elif tok.startswith("*") and tok[1:].isdigit():
            parts.append(b".{0,%d}?" % int(tok[1:]))
        else:
            try:
                parts.append(re.escape(bytes([int(tok, 16)])))
            except ValueError:
                raise ValueError(f"bad token {tok!r} in signature {text!r}")
    return re.compile(b"".join(parts), re.DOTALL), kind

def scan(buf, aob):
    """Yield (offset_in_buf, captured_value_or_None) for every (overlapping) match.
    The captured value is a raw absolute VA for '@@' or a *relative* displacement
    plus the capture position for '@rel' (resolved by the caller)."""
    rx, kind = compile_aob(aob)
    pos = 0
    while True:
        m = rx.search(buf, pos)
        if not m:
            return
        if kind is None:
            yield m.start(), None, kind, None
        else:
            val = struct.unpack("<I", m.group(1))[0]
            yield m.start(), val, kind, m.start(1)
        pos = m.start() + 1

def resolve(name, patterns, pe, data, image_lo, image_hi):
    """Search all executable sections. Returns the single address the signature
    resolves to, or dies if it is missing / ambiguous."""
    for aob in patterns:
        hits = {}                                   # target VA -> [match VAs]
        for sec, raw, sbuf in exec_sections(pe, data):
            sec_va = image_lo + sec.VirtualAddress
            for off, val, kind, cap_off in scan(sbuf, aob):
                if kind == "abs":
                    target = val
                elif kind == "rel":
                    target = u32(sec_va + cap_off + 4 + struct.unpack("<i", struct.pack("<I", val))[0])
                else:
                    target = sec_va + off
                if kind is not None and not (image_lo <= target < image_hi):
                    continue                        # captured garbage, not an address in this image
                hits.setdefault(target, []).append(sec_va + off)
        n = sum(len(v) for v in hits.values())
        print(f"    {name:<18} {n} match(es)  {aob}")
        if not hits:
            continue
        if len(hits) > 1:
            lst = ", ".join(f"{t:#x} (@ {m[0]:#x})" for t, m in sorted(hits.items()))
            die(f"signature '{name}' is ambiguous - resolves to: {lst}")
        (target, matches), = hits.items()
        print(f"    {'':<18} -> {target:#x}   (match at {matches[0]:#x})")
        return target
    die(f"signature '{name}' matched nothing")

def find_iat_slot(pe, func_name):
    """VA of the IAT entry for an imported function, from the PE import table."""
    want = func_name.encode()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name == want:
                return imp.address
    return None

def exec_sections(pe, data):
    for s in pe.sections:
        if s.Characteristics & 0x20000000 or s.Characteristics & 0x20:
            size = min(s.SizeOfRawData, s.Misc_VirtualSize) if s.Misc_VirtualSize else s.SizeOfRawData
            yield s, s.PointerToRawData, bytes(data[s.PointerToRawData:s.PointerToRawData + size])

def clear_relocs(pe, data, lo_rva, hi_rva):
    """Turn every base-reloc entry whose target lies in [lo,hi) into a
    type-0 (IMAGE_REL_BASED_ABSOLUTE = padding) entry."""
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    if not d.VirtualAddress or not d.Size:
        return 0
    off = pe.get_offset_from_rva(d.VirtualAddress)
    end = off + d.Size
    cleared = 0
    while off + 8 <= end:
        page, size = struct.unpack_from("<II", data, off)
        if size < 8:
            break
        for p in range(off + 8, off + size, 2):
            (entry,) = struct.unpack_from("<H", data, p)
            typ, o = entry >> 12, entry & 0xFFF
            if typ != 0 and lo_rva <= page + o < hi_rva:
                struct.pack_into("<H", data, p, 0)
                cleared += 1
        off += size
    return cleared

def function_length(buf, va):
    """Only used to learn how big the old function is (skip with --func-size)."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        from capstone.x86 import X86_OP_IMM
    except ImportError:
        die("capstone is needed to measure the function; `pip install capstone` or pass --func-size")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    max_target = va
    for ins in md.disasm(buf, va):
        if ins.mnemonic.startswith("j") and ins.operands and ins.operands[0].type == X86_OP_IMM:
            max_target = max(max_target, ins.operands[0].imm)
        if ins.mnemonic in ("ret", "retn") and ins.address >= max_target:
            return ins.address + ins.size - va
    die("couldn't find the end of the function; pass --func-size")

def hexdump(buf, va):
    for i in range(0, len(buf), 16):
        chunk = buf[i:i + 16]
        print(f"{va + i:08x}  {' '.join(f'{b:02X}' for b in chunk)}")

def build_stub(start_va, iat_ll, iat_gpa, v_hlib, v_gi, v_iface, cleanup_va, dll_name):
    base_va = start_va + 6  # value of ebx after `call $+5 / pop ebx`
    dll = dll_name.encode("ascii") + b"\0"
    gi_str = b"GetInterface\0"

    def gen(dll_va, gi_va):
        code, labels, fixups = bytearray(), {}, []

        def emit(*b):
            code.extend(b)

        def d32(target):
            return struct.pack("<i", target - base_va)

        def jump(opcode, label):
            emit(opcode, 0)
            fixups.append((len(code) - 1, label))

        def label(name):
            labels[name] = len(code)

        emit(0x53)                                   # push ebx
        emit(0xE8, 0, 0, 0, 0)                       # call $+5
        emit(0x5B)                                   # pop  ebx

        emit(0x8D, 0x83); emit(*d32(dll_va))         # lea  eax,[ebx+dll]
        emit(0x50)                                   # push eax
        emit(0xFF, 0x93); emit(*d32(iat_ll))         # call [LoadLibraryA]
        emit(0x89, 0x83); emit(*d32(v_hlib))         # mov  [hLibModule],eax
        emit(0x85, 0xC0)                             # test eax,eax
        jump(0x74, "fail")                           # jz   fail

        emit(0x8D, 0x8B); emit(*d32(gi_va))          # lea  ecx,[ebx+"GetInterface"]
        emit(0x51)                                   # push ecx
        emit(0x50)                                   # push eax (hModule)
        emit(0xFF, 0x93); emit(*d32(iat_gpa))        # call [GetProcAddress]
        emit(0x89, 0x83); emit(*d32(v_gi))           # mov  [GetInterface],eax
        emit(0x85, 0xC0)                             # test eax,eax
        jump(0x74, "cleanup")                        # jz   cleanup

        emit(0x6A, 0x02)                             # push 2
        emit(0xFF, 0xD0)                             # call eax   (stdcall, pops arg)
        emit(0x89, 0x83); emit(*d32(v_iface))        # mov  [g_lgLcdLibLinkedRemoteInterface],eax
        emit(0x85, 0xC0)                             # test eax,eax
        jump(0x74, "cleanup")                        # jz   cleanup

        emit(0xB8, 1, 0, 0, 0)                       # mov  eax,1
        jump(0xEB, "exit")                           # jmp  exit

        label("cleanup")
        rel = cleanup_va - (start_va + len(code) + 5)
        emit(0xE8); emit(*struct.pack("<i", rel))    # call sub_10006704
        label("fail")
        emit(0x31, 0xC0)                             # xor  eax,eax
        label("exit")
        emit(0x5B)                                   # pop  ebx
        emit(0xC3)                                   # ret

        for pos, name in fixups:
            rel8 = labels[name] - (pos + 1)
            assert -128 <= rel8 <= 127, "short jump out of range"
            code[pos] = rel8 & 0xFF
        return bytes(code)

    code_len = len(gen(0, 0))
    dll_va = start_va + code_len
    gi_va = dll_va + len(dll)
    code = gen(dll_va, gi_va)
    assert len(code) == code_len
    return code + dll + gi_str, code_len

def read_cstr(data, off):
    return bytes(data[off:data.index(b"\0", off)])

def rename_import(pe, data, old, new):
    old_b, new_b = old.encode("ascii"), new.encode("ascii")
    if len(new_b) > len(old_b):
        die("new import name is longer than the old one; can't rename in place")

    renamed, already, seen = 0, 0, set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("latin1")
        for imp in entry.imports:
            if imp.name == new_b:
                already += 1
            if imp.name != old_b:
                continue
            soff = pe.get_offset_from_rva(imp.hint_name_table_rva + 2)   # skip the 2-byte hint
            if soff in seen:                        # descriptor sharing the same name entry
                continue
            if bytes(data[soff:soff + len(old_b) + 1]) != old_b + b"\0":
                die(f"unexpected bytes at {soff:#x}; import name entry doesn't look right")
            seen.add(soff)
            span = len(old_b) + 1
            data[soff:soff + span] = new_b + b"\0" * (span - len(new_b))
            print(f"    {dll}: '{old}' -> '{new}'  (name entry at file offset {soff:#x})")
            renamed += 1

    if not renamed and not already:
        similar = sorted({imp.name.decode("latin1")
                          for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
                          for imp in entry.imports
                          if imp.name and b"CommandLine" in imp.name})
        die(f"import '{old}' not found in the import table"
            + (f" (similar: {', '.join(similar)})" if similar else ""))
    return renamed  

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("-o", "--output", help="default: <name>_patched<ext>")
    ap.add_argument("--dll", default=DEFAULT_DLL, help=f"DLL to load (default {DEFAULT_DLL})")
    ap.add_argument("--func-size", type=lambda x: int(x, 0), help="size of the original function in bytes (skips the capstone measurement)")
    ap.add_argument("--fix-pe", action="store_true", help=f"tier0.dll: rename export {IMPORT_OLD} -> {IMPORT_NEW} and exit")
    ap.add_argument("--dump", action="store_true", help="hexdump the located function and exit")
    args = ap.parse_args()

    src = Path(args.input)
    data = bytearray(src.read_bytes())
    pe = pefile.PE(data=bytes(data))
    if pe.FILE_HEADER.Machine != 0x14C:
        die("this is not a 32-bit x86 PE")
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image_lo, image_hi = image_base, image_base + pe.OPTIONAL_HEADER.SizeOfImage
    print(f"[*] ImageBase {image_base:#x}")

    out = Path(args.output) if args.output else src.with_name(src.stem + "_patched" + src.suffix)

    if args.fix_pe:
        print(f"[*] renaming tier0 export {IMPORT_OLD} -> {IMPORT_NEW}")
        if rename_import(pe, data, IMPORT_OLD, IMPORT_NEW):
            out.write_bytes(bytes(data))
            print(f"[+] wrote {out}")

            # re-read the file we just wrote so everything below works on it
            data = bytearray(out.read_bytes())
            pe.close()
            pe = pefile.PE(data=bytes(data))
        else:
            print(f"    no '{IMPORT_OLD}' import left, skipping")

    def get(name):
        if name in IAT_NAMES:
            slot = find_iat_slot(pe, IAT_NAMES[name])
            if slot is None:
                die(f"{IAT_NAMES[name]} is not in this DLL's import table")
            print(f"    {name:<18} import table -> {slot:#x}")
            return slot
        return resolve(name, SIGNATURES[name], pe, data, image_lo, image_hi)

    print("[*] locating function start")
    try:
        func_va = get("func_start")
    except SystemExit:
        if any(STUB_SIGNATURE in sbuf for _, _, sbuf in exec_sections(pe, data)):
            print("    (the stub signature is present - this file looks already patched)", file=sys.stderr)
        raise
    func_off = pe.get_offset_from_rva(func_va - image_base)
    print(f"    function VA {func_va:#x}  (RVA {func_va - image_base:#x}, file offset {func_off:#x})")

    if data[func_off:func_off + len(STUB_SIGNATURE)] == STUB_SIGNATURE:
        die("this file already appears to be patched")

    func_len = args.func_size or function_length(bytes(data[func_off:func_off + 0x800]), func_va)
    fbuf = bytes(data[func_off:func_off + func_len])
    print(f"[*] function size {func_len:#x} bytes")

    if args.dump:
        hexdump(fbuf, func_va)
        return

    print("[*] resolving addresses")
    addr = {name: get(name) for name in
            ("cleanup_func", "var_hlibmodule", "var_getinterface", "var_interface",
             "iat_loadlibrarya", "iat_getprocaddress")}

    print("[*] final addresses")
    for name, v in addr.items():
        print(f"    {name:<18} {v:#x}")

    blob, code_len = build_stub(func_va, addr["iat_loadlibrarya"], addr["iat_getprocaddress"],
                                addr["var_hlibmodule"], addr["var_getinterface"],
                                addr["var_interface"], addr["cleanup_func"], args.dll)
    print(f"[*] new stub: {code_len} code bytes + {len(blob) - code_len} bytes of strings "
          f"= {len(blob)} / {func_len} available")
    if len(blob) > func_len:
        die("new code doesn't fit inside the original function")

    data[func_off:func_off + func_len] = blob + b"\xCC" * (func_len - len(blob))
    n = clear_relocs(pe, data, func_va - image_base, func_va - image_base + func_len)
    print(f"[*] neutralised {n} base-relocation entries inside the old function")

    out = Path(args.output) if args.output else src.with_name(src.stem + "_patched" + src.suffix)
    out.write_bytes(bytes(data))
    print(f"[+] wrote {out}")
    print(f"    Make sure {args.dll} sits next to the application (or is otherwise on the DLL search path).")


if __name__ == "__main__":
    main()