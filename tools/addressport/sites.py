"""Locate each in-memory patch site in the new exe by instruction context.

For each site: old function (protected copy or low code) and its new counterpart are known. The old
instruction stream around the site (6 before, 6 after) is matched against linear disassembly of all
new code chunks near the new function. The best window whose centre instruction has the same
normalized text as the old site instruction wins.
"""
import bisect
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from ptab import pdata_raw  # noqa: E402
from match import md  # noqa: E402
from match2 import norm  # noqa: E402
from verify import follow  # noqa: E402

S = os.path.dirname(__file__)
CTX = 6


def linear(p, start, end):
    off = p.va2off(start)
    out = []
    for ins in md.disasm(bytes(p.data[off:off + (end - start)]), start):
        out.append(ins)
    return out


def old_context(old, chunk, site):
    ins = linear(old, chunk, site + 0x60)
    addrs = [i.address for i in ins]
    if site not in addrs:
        return None, None
    k = addrs.index(site)
    before = [norm(i) for i in ins[max(0, k - CTX):k]]
    after = [norm(i) for i in ins[k:k + CTX + 1]]
    return before, after, ins[k:k + 4]


def score(before, after, nb, na):
    s = 0
    for x, y in zip(reversed(before), reversed(nb)):
        s += x == y
    for x, y in zip(after, na):
        s += x == y
    return s


def main(sites_path, fnmap_path, out_path):
    old = PE(os.path.join(S, "exe/old_mgsvtpp.exe"))
    new = PE(os.path.join(S, "exe/new_mgsvtpp.exe"))
    npr = sorted(pdata_raw(new))
    nbeg = [b for b, e, u in npr]
    sites = json.load(open(sites_path))
    fnmap = json.load(open(fnmap_path))
    results = []
    for i, s in enumerate(sites):
        site = int(s["site"], 16)
        if not s.get("chunk"):
            results.append({**s, "new_site": None, "why": "no chunk"})
            continue
        chunk = int(s["chunk"], 16)
        r = old_context(old, chunk, site)
        if r[0] is None:
            results.append({**s, "new_site": None, "why": "site not on instruction boundary from chunk"})
            continue
        before, after, old_ins = r
        nfn = follow(new, int(fnmap[s["name"]], 16))
        # gather chunks of new code near nfn
        lo = bisect.bisect_left(nbeg, nfn - 0x100)
        hi = bisect.bisect_right(nbeg, nfn + 0x4000)
        starts = sorted(set([nfn] + nbeg[lo:hi]))
        best = []
        seen = set()
        for st in starts:
            end = min(st + 0x2000, new.off2va(new.va2off(st)) + 0x2000)
            ins = linear(new, st, end)
            toks = [norm(x) for x in ins]
            for k, x in enumerate(ins):
                if x.address in seen:
                    continue
                if toks[k] != after[0]:
                    continue
                seen.add(x.address)
                sc = score(before, after, toks[max(0, k - CTX):k], toks[k:k + CTX + 1])
                best.append((sc, x.address, ins[k:k + 4]))
        best.sort(key=lambda t: (-t[0], abs(t[1] - nfn)))
        if not best:
            results.append({**s, "new_site": None, "why": "site instruction not found near new fn"})
            continue
        top = best[0]
        second = best[1][0] if len(best) > 1 else None
        results.append({
            **s,
            "new_fn": hex(nfn),
            "new_site": hex(top[1]),
            "score": top[0],
            "max_score": len(before) + len(after),
            "second_score": second,
            "old_ins": [f"{x.bytes.hex()} {x.mnemonic} {x.op_str}" for x in old_ins],
            "new_ins": [f"{x.bytes.hex()} {x.mnemonic} {x.op_str}" for x in top[2]],
        })
    json.dump(results, open(out_path, "w"), indent=1)
    for r in results:
        print(f"{r['site']} -> {r.get('new_site')} score {r.get('score')}/{r.get('max_score')} 2nd {r.get('second_score')} {r.get('why','')}")
        for a, b in zip(r.get("old_ins", [])[:2], r.get("new_ins", [])[:2]):
            print(f"      old {a:45} | new {b}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
