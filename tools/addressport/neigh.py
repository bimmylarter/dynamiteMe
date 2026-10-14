"""Show function sequence around an old low address and around a new address, side by side.

Each function is summarized as: address, size to next start, stub target (if jmp stub), first 3
normalized instructions (following stubs). Usage: neigh.py OLD_LOW NEW_CENTER [count]
"""
import bisect
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from match2 import tokens, pdata_starts  # noqa: E402
from resolve2 import leaf_candidates  # noqa: E402

S = os.path.dirname(__file__)


def starts_near(p, ps, center, count):
    lo = center - 0x80 * count
    hi = center + 0x80 * count
    s = set(x for x in ps if lo <= x <= hi) | set(leaf_candidates(p, lo, hi))
    s = sorted(s)
    i = bisect.bisect_left(s, center)
    return s[max(0, i - count):i + count + 1]


def summarize(p, a):
    off = p.va2off(a)
    stub = None
    tgt = a
    if p.data[off] == 0xE9:
        rel = int.from_bytes(p.data[off + 1:off + 5], "little", signed=True)
        tgt = a + 5 + rel
        stub = tgt
    t = tokens(p, tgt, max_ins=4)
    return stub, t


def main():
    old = PE(os.path.join(S, "exe/old_mgsvtpp.exe"))
    new = PE(os.path.join(S, "exe/new_mgsvtpp.exe"))
    ol, nc = int(sys.argv[1], 16), int(sys.argv[2], 16)
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    hl = [int(x, 16) for x in sys.argv[4:]]
    for label, p, c in (("OLD", old, ol), ("NEW", new, nc)):
        ps = pdata_starts(p)
        print(f"--- {label} around {c:#x}")
        lst = starts_near(p, ps, c, count)
        for i, a in enumerate(lst):
            nxt = lst[i + 1] - a if i + 1 < len(lst) else 0
            stub, t = summarize(p, a)
            mark = "<==" if a == c or a in hl else ""
            print(f"  {a:#x} size={nxt:#6x} {'stub->' + hex(stub) if stub else '':24} {' | '.join(t)[:110]} {mark}")


if __name__ == "__main__":
    main()
