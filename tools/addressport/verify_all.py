"""Independent verification of every mapping in final.json.

Checks per entry:
  body    - SequenceMatcher ratio of normalized instruction streams (old real fn vs new real fn,
            following protection stubs on both sides)
  callers - number of direct `call rel32` sites reaching the function (directly or through a jmp stub)
            in old vs new
  align   - neighbourhood alignment result (align.py) for resolver entries
"""
import json
import os
import sys
from difflib import SequenceMatcher

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from verify import stream, follow  # noqa: E402
from xref import rel32_xrefs  # noqa: E402

S = os.path.dirname(__file__)


def caller_counts(p, fns):
    """fns: list of real function VAs. returns {fn: n_calls} counting calls to fn and to any jmp stub -> fn."""
    jm = rel32_xrefs(p, fns, opcodes=(0xE9,))
    stubs = {f: [s for s, _ in jm[f]] for f in fns}
    all_t = sorted(set(fns) | {s for v in stubs.values() for s in v})
    calls = rel32_xrefs(p, all_t, opcodes=(0xE8,))
    return {f: len(calls[f]) + sum(len(calls[s]) for s in stubs[f]) for f in fns}


def main(final_path, align_path, out_path):
    old = PE(os.path.join(S, "exe/old_mgsvtpp.exe"))
    new = PE(os.path.join(S, "exe/new_mgsvtpp.exe"))
    fin = json.load(open(final_path))
    al = json.load(open(align_path))
    items = [(k, v) for k, v in fin.items() if v["new"]]
    oreal = {k: follow(old, int(v["old"], 16)) for k, v in items}
    nreal = {k: follow(new, int(v["new"], 16)) for k, v in items}
    oc = caller_counts(old, sorted(set(oreal.values())))
    nc = caller_counts(new, sorted(set(nreal.values())))
    report = {}
    for k, v in items:
        a = stream(old, oreal[k], 100)
        b = stream(new, nreal[k], 100)
        ratio = SequenceMatcher(None, [x[0] for x in a], [x[0] for x in b], autojunk=False).ratio()
        co, cn = oc[oreal[k]], nc[nreal[k]]
        alv = al.get(k, {})
        align_ok = alv.get("align") == v["new"] if alv.get("align") else None
        checks = [ratio >= 0.9, co == cn, align_ok is True]
        report[k] = {"old": v["old"], "new": v["new"], "how": v["how"], "body": round(ratio, 2),
                     "callers_old": co, "callers_new": cn, "align": align_ok, "passed": sum(checks)}
    json.dump(report, open(out_path, "w"), indent=1)
    weak = sorted(report.items(), key=lambda kv: kv[1]["passed"])
    from collections import Counter
    print("checks passed:", Counter(r["passed"] for r in report.values()))
    for k, r in weak:
        if r["passed"] <= 1:
            print(f"{r['passed']} {k:58} {r['old']}->{r['new']} body={r['body']} callers {r['callers_old']}/{r['callers_new']} align={r['align']} [{r['how']}]")


if __name__ == "__main__":
    main(*sys.argv[1:4])
