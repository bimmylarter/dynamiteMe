"""Verify mapped pairs via RIP-relative data references.

For each (old function, new function) pair, disassemble both, align instruction streams on
normalized text, and collect RIP-relative memory targets at aligned positions. Static data did not
move much between builds, so (new_ref - old_ref) should be small and consistent with the data delta
seen in other confirmed functions. A pair whose data refs disagree is suspect.
"""
import json
import os
import sys
from difflib import SequenceMatcher

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from match import md, X  # noqa: E402
from match2 import norm  # noqa: E402

S = os.path.dirname(__file__)


def follow(p, va):
    off = p.va2off(va)
    if p.data[off] == 0xE9:
        return va + 5 + int.from_bytes(p.data[off + 1:off + 5], "little", signed=True)
    return va


def stream(p, va, n=80):
    off = p.va2off(va)
    out = []
    for ins in md.disasm(bytes(p.data[off:off + n * 15]), va):
        ref = None
        for op in ins.operands:
            if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
                ref = ins.address + ins.size + op.mem.disp
        out.append((norm(ins), ref))
        if len(out) >= n or ins.mnemonic in ("ret", "int3"):
            break
    return out


def data_deltas(old, new, ova, nva):
    a = stream(old, follow(old, ova))
    b = stream(new, follow(new, nva))
    sm = SequenceMatcher(None, [x[0] for x in a], [x[0] for x in b], autojunk=False)
    deltas = []
    for blk in sm.get_matching_blocks():
        for k in range(blk.size):
            ra, rb = a[blk.a + k][1], b[blk.b + k][1]
            if ra is not None and rb is not None:
                deltas.append(rb - ra)
    return deltas, round(sm.ratio(), 2)


def main(final_path):
    old = PE(os.path.join(S, "exe/old_mgsvtpp.exe"))
    new = PE(os.path.join(S, "exe/new_mgsvtpp.exe"))
    m = json.load(open(final_path))
    for k, v in m.items():
        if not v.get("new"):
            print(f"{k:60} unmapped")
            continue
        d, r = data_deltas(old, new, int(v["old"], 16), int(v["new"], 16))
        ds = sorted(set(d))
        summary = ", ".join(f"{x:+#x}" for x in ds[:6]) if ds else "-"
        print(f"{k:60} ratio={r:<5} data_deltas=[{summary}]")


if __name__ == "__main__":
    main(sys.argv[1])
