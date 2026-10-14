"""Resolver v2: dense local anchors + leaf-function candidates.

1. old_low = address itself (low code region) or the low-region jmp stub pointing to it.
2. Sparse delta from resolve.py anchors gives a rough prediction.
3. Dense anchors: unprotected old functions near old_low (old .pdata starts in low region, not stubs)
   are matched to new by near-exact instruction equality around the rough prediction.
   The closest dense anchor before old_low gives an exact local delta.
4. Candidates near the precise prediction: new .pdata starts plus 16-aligned addresses after padding.
   Scored by instruction similarity with a strong distance penalty.
"""
import bisect
import json
import os
import sys
from difflib import SequenceMatcher

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from match import parse_addresses  # noqa: E402
from match2 import tokens, pdata_starts, common_prefix  # noqa: E402
from xref import rel32_xrefs  # noqa: E402

LOW_END = 0x14208D000
ROUGH_WIN = 0x2000
LOCAL_RANGE = 0x3000
FINE_WIN = 0x400


def sim(a, b):
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b, autojunk=False).ratio()


class Tok:
    def __init__(self, pe):
        self.pe = pe
        self.c = {}

    def __call__(self, va, n=48):
        k = (va, n)
        if k not in self.c:
            self.c[k] = tokens(self.pe, va, max_ins=n)
        return self.c[k]


def is_stub(pe, va):
    off = pe.va2off(va)
    return off is not None and pe.data[off] == 0xE9


def leaf_candidates(pe, lo, hi):
    out = []
    a = (lo + 15) & ~15
    while a < hi:
        off = pe.va2off(a)
        if off is not None and pe.data[off - 1] in (0xCC, 0xC3, 0x90) and pe.data[off] not in (0xCC, 0x00):
            out.append(a)
        a += 16
    return out


def main(old_path, new_path, hdr, sparse_path, out_path):
    old, new = PE(old_path), PE(new_path)
    ot, nt = Tok(old), Tok(new)
    entries = parse_addresses(hdr)
    sparse = json.load(open(sparse_path))["results"]
    old_starts = pdata_starts(old)
    new_starts = pdata_starts(new)

    targets = sorted({va for _, va in entries})
    stubs = rel32_xrefs(old, targets, opcodes=(0xE9,))

    # sparse anchors (high confidence, consistent) from resolve.py
    sp = sorted((int(r["old_low"], 16), int(r["new"], 16) - int(r["old_low"], 16))
                for r in sparse.values() if r.get("confidence") == "high")
    sp_keys = [k for k, _ in sp]

    def rough(low):
        i = bisect.bisect_left(sp_keys, low)
        cand = []
        if i > 0:
            cand.append(sp[i - 1])
        if i < len(sp):
            cand.append(sp[i])
        k, d = min(cand, key=lambda x: abs(x[0] - low))
        return low + d

    dense_cache = {}

    def dense_anchor(low):
        """Find nearest unprotected old function before (and after) low that matches exactly in new."""
        r = rough(low)
        i = bisect.bisect_left(old_starts, low)
        found = []
        # walk backwards then forwards, nearest first
        order = []
        for j in range(i - 1, max(-1, i - 40), -1):
            if low - old_starts[j] > LOCAL_RANGE:
                break
            order.append(old_starts[j])
        for j in range(i, min(len(old_starts), i + 40)):
            if old_starts[j] - low > LOCAL_RANGE or old_starts[j] >= LOW_END:
                break
            if old_starts[j] != low:
                order.append(old_starts[j])
        for o in order:
            if o in dense_cache:
                if dense_cache[o] is not None:
                    found.append((o, dense_cache[o]))
                continue
            dense_cache[o] = None
            if o >= LOW_END or is_stub(old, o):
                continue
            otk = ot(o)
            if len(otk) < 8:
                continue
            pred = o + (r - low)
            lo = bisect.bisect_left(new_starts, pred - ROUGH_WIN)
            hi = bisect.bisect_right(new_starts, pred + ROUGH_WIN)
            hits = [c for c in new_starts[lo:hi] if nt(c) == otk]
            if len(hits) == 1:
                dense_cache[o] = hits[0] - o
                found.append((o, hits[0] - o))
            if len(found) >= 4:
                break
        return found

    results = {}
    for name, va in entries:
        lows = [va] if va < LOW_END else sorted({s for s, _ in stubs[va] if s < LOW_END})
        otk = ot(va)
        best = None
        second = None
        detail = []
        for low in lows:
            anchors = dense_anchor(low)
            if anchors:
                # prefer the nearest anchor before low
                before = [a for a in anchors if a[0] < low]
                a = max(before) if before else min(anchors, key=lambda x: abs(x[0] - low))
                pred = low + a[1]
                agree = len({d for _, d in anchors})
                detail.append(f"low={low:#x} dense={len(anchors)} deltas={sorted({d for _, d in anchors})}")
            else:
                pred = rough(low)
                detail.append(f"low={low:#x} rough only")
            lo = bisect.bisect_left(new_starts, pred - FINE_WIN)
            hi = bisect.bisect_right(new_starts, pred + FINE_WIN)
            cands = set(new_starts[lo:hi]) | set(leaf_candidates(new, pred - FINE_WIN, pred + FINE_WIN))
            for c0 in cands:
                c = c0
                coff = new.va2off(c0)
                if coff is not None and new.data[coff] == 0xE9:
                    rel = int.from_bytes(new.data[coff + 1:coff + 5], "little", signed=True)
                    tgt = c0 + 5 + rel
                    if new.va2off(tgt) is not None:
                        c = tgt  # follow protection stub to real function
                ctk = nt(c)
                s = sim(otk, ctk)
                p = common_prefix(otk, ctk)
                score = s + 0.01 * min(p, 10) - abs(c0 - pred) / FINE_WIN * 0.15
                cand = (round(score, 4), s, p, c, pred, low, c0)
                if best is None or cand > best:
                    second, best = best, cand
                elif second is None or cand > second:
                    second = cand
        if best is None:
            results[name] = {"old": hex(va), "new": None, "confidence": "none", "detail": detail}
            continue
        score, s, p, c, pred, low, slot = best
        margin = score - second[0] if second else 1.0
        exact_pos = slot == pred
        if s >= 0.85 and (margin > 0.05 or exact_pos):
            conf = "high"
        elif s >= 0.6 and (margin > 0.03 or exact_pos):
            conf = "medium"
        else:
            conf = "low"
        results[name] = {"old": hex(va), "old_low": hex(low), "new": hex(c), "predicted": hex(pred),
                         "exact_pos": exact_pos, "new_stub": hex(slot) if slot != c else None, "similarity": round(s, 3), "prefix": p, "n_ins": len(otk),
                         "margin": round(margin, 3), "confidence": conf, "detail": detail,
                         "second": hex(second[3]) if second else None}
    json.dump(results, open(out_path, "w"), indent=1)
    from collections import Counter
    print(Counter(r["confidence"] for r in results.values()))
    for k, r in results.items():
        if r["confidence"] != "high":
            print(f"{r['confidence']:6} {k:58} {r['old']} -> {r.get('new')} pred={r.get('predicted')} sim={r.get('similarity')} "
                  f"pre={r.get('prefix')}/{r.get('n_ins')} margin={r.get('margin')} 2nd={r.get('second')} {r.get('detail')}")


if __name__ == "__main__":
    main(*sys.argv[1:6])
