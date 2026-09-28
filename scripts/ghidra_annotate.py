# Annotate VM fetch sites + handler semantics onto functions.
# Usage (headless): analyzeHeadless <proj> <name> -import <bin>
#   -postScript ghidra_annotate.py -scriptPath <this dir>
# Annotation bundle: JSON {"fetch_sites": ["0x..."], "handlers": {"0x...":
#   {"alu": [...], "regs": [...], "consts": [...], "seq": [...]}}}
# Env ANNOT_JSON overrides the bundle path (default: ./data/annot.json).
import json
import os

BUNDLE = os.environ.get(
    "ANNOT_JSON",
    os.path.join(os.getcwd(), "data", "annot.json"),
)


def func_entry(addr):
    """Containing function entry, or the address itself."""
    try:
        f = getFunctionContaining(addr)
        if f is not None:
            return f.getEntryPoint()
    except Exception:
        pass
    return addr


def main():
    try:
        data = json.load(open(BUNDLE))
    except Exception as e:
        print("annot bundle missing: %s (%s)" % (BUNDLE, e))
        return
    bm = currentProgram.getBookmarkManager()
    listing = currentProgram.getListing()
    n_f = 0
    for s in data.get("fetch_sites", []):
        try:
            addr = toAddr(int(s, 16))
        except Exception:
            continue
        try:
            bm.setBookmark(
                addr, "Note", "VMFETCH",
                "VM fetch site (dynamic execution; see project notes)",
            )
            n_f += 1
        except Exception:
            pass
    n_h = 0
    seen_funcs = set()
    for va, c in data.get("handlers", {}).items():
        try:
            addr = toAddr(int(va, 16))
        except Exception:
            continue
        try:
            entry = func_entry(addr)
            key = str(entry)
            if key in seen_funcs:
                continue
            seen_funcs.add(key)
            cu = listing.getCodeUnitAt(entry)
            if cu is None:
                continue
            txt = "VMHANDLER @%s alu=%s regs=%s consts=%s" % (
                va,
                ",".join(c.get("alu", [])),
                ",".join(c.get("regs", [])),
                ",".join(c.get("consts", [])),
            )
            cu.setComment(cu.PLATE_COMMENT, txt)
            n_h += 1
        except Exception:
            pass
    print("annotated fetch=%d handler_funcs=%d" % (n_f, n_h))


main()
