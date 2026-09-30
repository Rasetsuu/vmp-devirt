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
pe = pefile.PE(BIN)
base = pe.OPTIONAL_HEADER.ImageBase
data = open(BIN, "rb").read()

secs = []
for s in pe.sections:
    name = bytes(s.Name).decode().rstrip(chr(0))
    va = base + s.VirtualAddress
    span = max(s.Misc_VirtualSize, s.SizeOfRawData)
    if span == 0:
        continue
    secs.append((name, va, span, s.PointerToRawData, s.SizeOfRawData))

# raw section-image blob + table (driver mmaps + copies)
blob = b""
entries = []
for name, va, span, off, raw in secs:
    mapped = (span + 0xFFF) & ~0xFFF
    entries.append((va, mapped, len(blob), raw, off))
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
    entry = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    f.write("static const uint64_t kEntry = 0x%x;\n" % entry)
    f.write("static const uint64_t kPool = 0x%x;\n" % (entries[0][0] + 0x1000))

with open(OUT + "/dispatch.h", "w") as f:
    f.write("// generated: VA -> lifted fn decls\n")
    for va in vas:
        f.write('extern "C" void *sub_%x(void *, uint64_t, void *);\n' % va)
    f.write("static const struct { uint64_t va; Fn fn; } kFns[] = {\n")
    for va in vas:
        f.write("  {0x%x, sub_%x},\n" % (va, va))
    f.write("};\n")
print("wrote tables.h dispatch.h sections.bin", len(blob), "bytes")
