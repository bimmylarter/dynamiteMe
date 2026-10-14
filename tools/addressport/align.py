"""Neighbourhood sequence alignment: independent check of each mapping.

Around old_low (old layout) and around the predicted new address, list function starts in order and
describe each by (first 4 normalized instructions after following a jmp stub, size bucket).
Align the two sequences with difflib; the new function aligned with old_low is the answer.
"""
import bisect
import json
import os
import sys
from difflib import SequenceMatcher

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from match2 import tokens, pdata_starts  # noqa: E402
from resolve2 import leaf_candidates  # noqa: E402

S = os.path.dirname(__file__)
SPAN = 0xC00


def seq(p, ps, center):
    lo, hi = center - SPAN, center + SPAN
    i0, i1 = bisect.bisect_left(ps, lo), bisect.bisect_right(ps, hi)
    st = sorted(set(ps[i0:i1]) | set(leaf_candidates(p, lo, hi)))
    out = []
    for i, a in enumerate(st):
        off = p.va2off(a)
        tgt = a
        if p.data[off] == 0xE9:
            tgt = a + 5 + int.from_bytes(p.data[off + 1:off + 5], "little", signed=True)
        t = tuple(tokens(p, tgt, max_ins=4))
        size = (st[i + 1] - a) if i + 1 < len(st) else -1
        out.append((a, tgt, t, size))
    return out


def align(old, new, ops, nps, old_low, new_pred):
    so = seq(old, ops, old_low)
    sn = seq(new, nps, new_pred)
    ko = [(t, s) for _, _, t, s in so]
    kn = [(t, s) for _, _, t, s in sn]
    try:
        i = [a for a, *_ in so].index(old_low)
    except ValueError:
        return None, "old_low not a function start"
    sm = SequenceMatcher(None, ko, kn, autojunk=False)
    for blk in sm.get_matching_blocks():
        if blk.a <= i < blk.a + blk.size:
            j = blk.b + (i - blk.a)
            # require context: block of >= 3 (or neighbours matched on both sides)
            return sn[j][1], f"block size {blk.size}, ratio {sm.ratio():.2f}"
    # not in an equal block: try matching by position between neighbouring blocks (size-only)
    blocks = sm.get_matching_blocks()
    prev = max((b for b in blocks if b.a + b.size <= i and b.size), key=lambda b: b.a, default=None)
    nxt = min((b for b in blocks if b.a > i and b.size), key=lambda b: b.a, default=None)
    if prev and nxt:
        gap_o = nxt.a - (prev.a + prev.size)
        gap_n = nxt.b - (prev.b + prev.size)
        if gap_o == gap_n:
            j = prev.b + prev.size + (i - (prev.a + prev.size))
            return sn[j][1], f"positional between blocks (gap {gap_o}), ratio {sm.ratio():.2f}"
        return None, f"gap mismatch old {gap_o} new {gap_n}"
    return None, "no surrounding blocks"


def main(map_path, out_path):
    old = PE(os.path.join(S, "exe/old_mgsvtpp.exe"))
    new = PE(os.path.join(S, "exe/new_mgsvtpp.exe"))
    ops, nps = pdata_starts(old), pdata_starts(new)
    m = json.load(open(map_path))
    out = {}
    agree = disagree = unk = 0
    for k, v in m.items():
        if not v.get("old_low") or not v.get("predicted"):
            out[k] = {"align": None, "why": "no layout info"}
            unk += 1
            continue
        res, why = align(old, new, ops, nps, int(v["old_low"], 16), int(v["predicted"], 16))
        out[k] = {"align": hex(res) if res else None, "why": why, "resolver": v["new"], "conf": v["confidence"]}
        if res is None:
            unk += 1
            tag = "?"
        elif hex(res) == v["new"]:
            agree += 1
            tag = "="
        else:
            disagree += 1
            tag = "X"
        if tag != "=" or v["confidence"] != "high":
            print(f"{tag} {v['confidence']:6} {k:58} resolver={v['new']} align={out[k]['align']} ({why})")
    print(f"agree {agree}, disagree {disagree}, unknown {unk}")
    json.dump(out, open(out_path, "w"), indent=1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
