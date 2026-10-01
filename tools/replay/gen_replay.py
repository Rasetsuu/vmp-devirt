#!/usr/bin/env python3
"""Generate replay driver sources: section map + dispatch table.
Usage: gen_replay.py <binary> <recomp-dir>   (recomp-dir holds b_*.ll)
Writes tables.h + dispatch.h into <recomp-dir>/drv/ (create it).
Artifacts (*.o, sections.bin, replay binary, traces) stay out of git.
"""
import glob
import os
import re
import sys

BIN = sys.argv[1] if len(sys.argv) > 1 else None
RECOMP = sys.argv[2] if len(sys.argv) > 2 else None
if not BIN or not RECOMP:
    sys.exit("usage: gen_replay.py <binary> <recomp-dir>")
OUT = RECOMP + "/drv"
os.makedirs(OUT, exist_ok=True)

import pefile

def load_pe(path):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = open(path, "rb").read()
    secs = []
    for s in pe.sections:
        name = bytes(s.Name).decode().rstrip(chr(0))
        va = base + s.VirtualAddress
        span = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if span == 0:
            continue
        secs.append((name, va, span, s.PointerToRawData, s.SizeOfRawData))
    entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    return secs, entry, data, pe


def load_elf(path):
    """ELF64 section map without new deps (manual shdr parse).
    NOBITS (.bss) maps zero-filled (raw 0)."""
    import struct
    data = open(path, "rb").read()
    assert data[:4] == b"\x7fELF" and data[4] == 2, "not ELF64"
    e_entry = struct.unpack("<Q", data[24:32])[0]
    e_shoff, = struct.unpack("<Q", data[40:48])
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[58:64])
    raws = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, stype, flags, addr, off, size = struct.unpack("<IIQQQQ", data[o:o + 40])
        raws.append((name, stype, flags, addr, off, size))
    SHT_NOBITS, SHT_NULL = 8, 0
    strtab = raws[e_shstrndx]
    s_off, s_size = strtab[4], strtab[5]
    strs = data[s_off:s_off + s_size]
    def nm(i):
        j = strs.find(b"\x00", i)
        return strs[i:j].decode()
    secs = []
    for name_i, stype, flags, addr, off, size in raws:
        n = nm(name_i)
        if stype in (SHT_NULL,) or addr == 0 or size == 0 or not n:
            continue
        nobits = (stype == SHT_NOBITS)
        secs.append((n, addr, size, off if not nobits else 0, 0 if nobits else size))
    return secs, e_entry, data, None


if open(BIN, "rb").read(4) == b"\x7fELF":
    secs, entry, data, pe = load_elf(BIN)
else:
    secs, entry, data, pe = load_pe(BIN)

# raw section-image blob + table (driver mmaps + copies)
blob = b""
entries = []
for name, va, span, off, raw in secs:
    # exact span; the driver page-aligns once (pre-rounding here caused
    # double-round overlap on unaligned ELF sections).
    entries.append((va, span, len(blob), raw, off))
    blob += data[off:off + raw] if raw > 0 else b""
open(OUT + "/sections.bin", "wb").write(blob)

vas = []
for ll in glob.glob(RECOMP + "/b_*.ll") + glob.glob(RECOMP + "/../bb_obj2/b_*.ll"):
    m = re.search(r"b_([0-9a-f]+)\.ll$", ll)
    if m:
        vas.append(int(m.group(1), 16))
vas.sort()
print("lifted blocks:", len(vas))

with open(OUT + "/tables.h", "w") as f:
    f.write("// generated: section map + entry + pool\n")
    f.write("struct Sec { uint64_t va, size, blob_off, raw_len, file_off; };\n")
    f.write("static const Sec kSecs[] = {\n")
    for va, mapped, boff, raw, foff in entries:
        f.write("  {0x%x, 0x%x, %d, 0x%x, 0x%x},\n" % (va, mapped, boff, raw, foff))
    f.write("};\n")
    entry = entry  # load_pe/load_elf both return absolute entry
    f.write("static const uint64_t kEntry = 0x%x;\n" % entry)
    f.write("static const uint64_t kPool = 0x%x;\n" % (entries[0][0] + 0x1000))

# Import slot table for stub poking (driver mirrors tracer rules).
# kind: 0 = zero-ret, 1 = heap-ret, 2 = time-stub.
# ELF: no IAT; GOT slots for libc calls get real addresses via dlsym
# in the driver (kind 3 = dlsym-resolve). PE: classic IAT kinds.
HEAPISH = ("Alloc", "Heap", "Virtual", "malloc", "Global", "Local", "MapView")
with open(OUT + "/iat.h", "w") as f:
    f.write("// generated: import slot -> stub kind (0 zero, 1 heap, 2 time, 3 dlsym)\n")
    f.write("static const struct { uint64_t slot; unsigned kind; } kIAT[] = {\n")
    n = 0
    if pe is None:
        # ELF: GOT slots from .rela.plt -> dynsym names (manual parse,
        # same layout as the tracer's PLT_STUBS). Driver dlsym-resolves.
        import struct
        try:
            e_shoff, = struct.unpack("<Q", data[40:48])
            e_shentsz, e_shnum, e_shstrx = struct.unpack("<HHH", data[58:64])
            raws = []
            for i in range(e_shnum):
                o = e_shoff + i * e_shentsz
                raws.append(struct.unpack("<IIQQQQIIQQ", data[o:o + 64]))
            stb = raws[e_shstrx]
            strs = data[stb[4]:stb[4] + stb[5]]
            sec_by_name = {}
            for r in raws:
                j = strs.find(b"\x00", r[0])
                sec_by_name[strs[r[0]:j].decode()] = r
            dynsym = None
            for r in raws:
                j = strs.find(b"\x00", r[0])
                if strs[r[0]:j] == b".dynsym":
                    dynsym = r
            dsyms = []
            if dynsym:
                d = data[dynsym[4]:dynsym[4] + dynsym[5]]
                for c in [d[i:i + 24] for i in range(0, len(d), 24)]:
                    dsyms.append(struct.unpack("<IBBHQQ", c)[0])
            dstr = None
            for r in raws:
                j = strs.find(b"\x00", r[0])
                if strs[r[0]:j] == b".dynstr":
                    dstr = data[r[4]:r[4] + r[5]]
            rp = sec_by_name.get(".rela.plt")
            if rp and dstr is not None:
                rel = data[rp[4]:rp[4] + rp[5]]
                for c in [rel[i:i + 24] for i in range(0, len(rel), 24)]:
                    off, info, _ = struct.unpack("<QQq", c)
                    si = info >> 32
                    nm = ""
                    if si < len(dsyms):
                        k = dsyms[si]
                        j = dstr.find(b"\x00", k)
                        nm = dstr[k:j].decode()
                    f.write("  {0x%x, %d},  //plt %s\n" % (off, 3, nm))
                    n += 1
        except Exception as ex:
            f.write("  // no rela.plt: %s\n" % ex)
    else:
        try:
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                for fn in e.imports:
                    if not fn.name:
                        continue
                    name = fn.name.decode()
                    va = fn.address  # pefile gives the slot VA directly
                    if name in ("GetSystemTimeAsFileTime",):
                        kind = 2
                    elif name in ("LocalAlloc", "VirtualAlloc"):
                        kind = 1
                    elif name == "GetProcAddress":
                        kind = 0  # tracer logs+traps; replay returns 0 (same rax)
                    elif any(k in name for k in HEAPISH):
                        kind = 1
                    else:
                        kind = 0
                    f.write("  {0x%x, %d},  // %s\n" % (va, kind, name))
                    n += 1
        except Exception as ex:
            f.write("  // no import dir: %s\n" % ex)
    f.write("};\n")
    print("iat slots:", n)
# ELF GOT names for driver dlsym (kind 3). PE path: empty.
with open(OUT + "/iat.h", "a") as f:
    f.write("static const struct { uint64_t slot; const char *name; } kGOT[] = {\n")
    if pe is None:
        import re as _re
        txt = open(OUT + "/iat.h").read()
        for m in _re.finditer(r"\{0x([0-9a-f]+), 3\},  //plt (\S+)", txt):
            f.write('  {0x%s, "%s"},\n' % (m.group(1), m.group(2)))
    f.write("};\n")
print("wrote tables.h dispatch.h iat.h sections.bin", len(blob), "bytes")

with open(OUT + "/dispatch.h", "w") as f:
    f.write("// generated: VA -> lifted fn decls\n")
    for va in vas:
        f.write('extern "C" void *sub_%x(void *, uint64_t, void *);\n' % va)
    f.write("static const struct { uint64_t va; Fn fn; } kFns[] = {\n")
    for va in vas:
        f.write("  {0x%x, sub_%x},\n" % (va, va))
    f.write("};\n")
print("wrote tables.h dispatch.h sections.bin", len(blob), "bytes")
