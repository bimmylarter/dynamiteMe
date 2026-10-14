"""Final resolver: combine instruction matching with layout prediction.

old_low = original (pre-protection) address: the address itself if in the low code region,
otherwise the low-region jmp stub that points to it. New code keeps the original layout with a
slowly drifting offset, so new ~= old_low + delta(old_low), with delta interpolated from
confident anchors. Near the prediction, candidates from new .pdata are scored by normalized
instruction similarity.
"""
import bisect
import json
import os
import statistics
import sys
from difflib import SequenceMatcher

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from match import parse_addresses  # noqa: E402
from match2 import NewIndex, tokens, pdata_starts, common_prefix  # noqa: E402
from xref import rel32_xrefs  # noqa: E402

LOW_END = 0x14208D000
WINDOW = 0x1800


def similarity(a, b):
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b, autojunk=False).ratio()


def main(old_path, new_path, hdr, out_path):
    old, new = PE(old_path), PE(new_path)
    entries = parse_addresses(hdr)
    idx = NewIndex(new)
    new_starts = idx.starts
    old_starts = set(pdata_starts(old))

    targets = sorted({va for _, va in entries})
    stubs = rel32_xrefs(old, targets, opcodes=(0xE9,))

    info = {}
    for name, va in entries:
        if va < LOW_END:
            lows = [va]
        else:
            lows = sorted({s for s, _ in stubs[va] if s < LOW_END})
        ot = tokens(old, va)
        info[name] = {"old": va, "lows": lows, "toks": ot}

    # pass 1: global instruction match, keep as anchor candidates
    anchors = []
    for name, d in info.items():
        if len(d["lows"]) != 1 or len(d["toks"]) < 6:
            continue
        scored = idx.query(d["toks"])
        if not scored:
            continue
        best = scored[0][0]
        top = [s for s in scored if s[0] == best]
        if len(top) == 1 and best >= min(len(d["toks"]), 10):
            anchors.append((d["lows"][0], top[0][2] - d["lows"][0], name))
    anchors.sort()

    # drop anchors whose delta disagrees with neighbours
    def consistent(i):
        lo, hi = max(0, i - 4), min(len(anchors), i + 5)
        neigh = [anchors[j][1] for j in range(lo, hi) if j != i]
        if len(neigh) < 2:
            return True
        return abs(anchors[i][1] - statistics.median(neigh)) < 0x4000

    good = [a for i, a in enumerate(anchors) if consistent(i)]
    dropped = [a[2] for a in anchors if a not in good]
    keys = [a[0] for a in good]

    def predict(low):
        i = bisect.bisect_left(keys, low)
        if i == 0:
            return low + good[0][1], 0
        if i >= len(good):
            return low + good[-1][1], 0
        (k0, d0, _), (k1, d1, _) = good[i - 1], good[i]
        t = (low - k0) / (k1 - k0) if k1 != k0 else 0
        dist = min(low - k0, k1 - low)
        return int(low + d0 + (d1 - d0) * t), dist

    results = {}
    for name, d in info.items():
        best = None
        second = None
        notes = []
        for low in d["lows"] or []:
            pred, dist = predict(low)
            lo = bisect.bisect_left(new_starts, pred - WINDOW)
            hi = bisect.bisect_right(new_starts, pred + WINDOW)
            for c in new_starts[lo:hi]:
                ct = idx.toks(c)
                sim = similarity(d["toks"], ct)
                pre = common_prefix(d["toks"], ct)
                score = sim + 0.02 * min(pre, 10) - abs(c - pred) / (WINDOW * 20)
                cand = (score, sim, pre, c, pred, low)
                if best is None or cand > best:
                    second = best
                    best = cand
                elif second is None or cand > second:
                    second = cand
            notes.append(f"low={low:#x} pred={pred:#x} anchor_dist={dist:#x}")
        if best is None:
            results[name] = {"old": hex(d["old"]), "new": None, "confidence": "none", "why": "no low-region stub" if not d["lows"] else "no candidates", "notes": notes}
            continue
        score, sim, pre, c, pred, low = best
        margin = score - second[0] if second else 1.0
        if sim >= 0.8 and margin > 0.05:
            conf = "high"
        elif sim >= 0.5 and margin > 0.03:
            conf = "medium"
        else:
            conf = "low"
        results[name] = {
            "old": hex(d["old"]), "old_low": hex(low), "new": hex(c), "predicted": hex(pred),
            "similarity": round(sim, 3), "prefix": pre, "n_ins": len(d["toks"]),
            "margin": round(margin, 3), "confidence": conf, "notes": notes,
        }

    json.dump({"results": results, "anchors": len(good), "dropped_anchors": dropped}, open(out_path, "w"), indent=1)
    from collections import Counter
    print("anchors", len(good), "dropped", dropped)
    print(Counter(r["confidence"] for r in results.values()))
    for k, r in results.items():
        if r["confidence"] != "high":
            print(f"{r['confidence']:6} {k:60} {r['old']} -> {r.get('new')} sim={r.get('similarity')} pre={r.get('prefix')}/{r.get('n_ins')} margin={r.get('margin')} {r.get('why','')}")


if __name__ == "__main__":
    main(*sys.argv[1:5])
