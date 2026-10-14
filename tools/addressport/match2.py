"""Instruction-level matcher: old (protected, re-encoded) functions -> new exe functions.

Compares normalized disassembly (mnemonic + operands, with branch targets / RIP-relative
displacements / image addresses abstracted) so that different encodings of the same
instruction compare equal. Candidates are function starts from the new exe's .pdata.
"""
import json
import os
import re
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
import match as m1  # noqa: E402  (sets up capstone)
from match import md, X, capstone  # noqa: E402

IMG_LO, IMG_HI = 0x140000000, 0x150000000
HEX = re.compile(r"0x[0-9a-f]+")


def pdata_starts(pe):
    d = pe.data
    peo = struct.unpack_from("<I", d, 0x3C)[0]
    opt = peo + 24
    # data directory 3 = exception
    rva, size = struct.unpack_from("<II", d, opt + 112 + 3 * 8)
    off = pe.va2off(pe.image_base + rva)
    starts = []
    for i in range(size // 12):
        b, e, u = struct.unpack_from("<III", d, off + i * 12)
        if b:
            starts.append(pe.image_base + b)
    return sorted(set(starts))


def norm(ins):
    """Normalized text of one instruction."""
    mn = ins.mnemonic
    ops = ins.op_str
    if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL):
        if any(op.type == X.X86_OP_IMM for op in ins.operands):
            return mn + " T"
    if "rip" in ops:
        ops = re.sub(r"\[rip [+-] 0x[0-9a-f]+\]", "[rip+G]", ops)
    def repl(mt):
        v = int(mt.group(0), 16)
        return "A" if IMG_LO <= v < IMG_HI else mt.group(0)
    ops = HEX.sub(repl, ops)
    return mn + " " + ops


JUNK_STOP = ("ret", "int3")


def tokens(pe, va, max_ins=48, follow_jmp=True):
    """Normalized instruction list for function at va. Follows a leading jmp stub once."""
    out = []
    off = pe.va2off(va)
    if off is None:
        return out
    code = bytes(pe.data[off:off + max_ins * 15])
    for ins in md.disasm(code, va):
        t = norm(ins)
        if t == "nop " or ins.mnemonic == "nop":
            continue
        out.append(t)
        if len(out) >= max_ins:
            break
        if ins.mnemonic in JUNK_STOP:
            break
        if ins.mnemonic == "jmp":
            break
    return out


def common_prefix(a, b):
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


class NewIndex:
    def __init__(self, pe, k=4):
        self.pe = pe
        self.k = k
        self.starts = pdata_starts(pe)
        self.idx = defaultdict(list)
        self.cache = {}
        for s in self.starts:
            t = tokens(pe, s, max_ins=k)
            if len(t) >= 1:
                self.idx[tuple(t[:k])].append(s)

    def toks(self, va):
        if va not in self.cache:
            self.cache[va] = tokens(self.pe, va)
        return self.cache[va]

    def query(self, old_toks):
        k = min(self.k, len(old_toks))
        key = tuple(old_toks[:k])
        if k < self.k:
            # short function: scan bucket keys with this prefix
            cands = [s for kk, v in self.idx.items() if kk[:k] == key for s in v]
        else:
            cands = self.idx.get(key, [])
        scored = []
        for c in cands:
            ct = self.toks(c)
            p = common_prefix(old_toks, ct)
            full = p == len(old_toks) or p == len(ct)
            scored.append((p, full, c))
        scored.sort(reverse=True)
        return scored


def resolve(old, idx, va):
    ot = tokens(old, va)
    if not ot:
        return None, "cannot disassemble", ot
    scored = idx.query(ot)
    if not scored:
        return None, f"no candidate ({len(ot)} ins)", ot
    best = scored[0][0]
    top = [s for s in scored if s[0] == best]
    need = min(len(ot), 10)
    if best < need and not top[0][1]:
        return [hex(s[2]) for s in top[:5]], f"weak: prefix {best}/{len(ot)}", ot
    if len(top) > 1:
        return [hex(s[2]) for s in top[:5]], f"ambiguous: {len(top)} with prefix {best}/{len(ot)}", ot
    return top[0][2], f"prefix {best}/{len(ot)}" + (", 2nd " + str(scored[1][0]) if len(scored) > 1 else ""), ot


if __name__ == "__main__":
    old = PE(sys.argv[1])
    new = PE(sys.argv[2])
    entries = m1.parse_addresses(sys.argv[3])
    idx = NewIndex(new)
    print(f"new exe: {len(idx.starts)} functions from .pdata", flush=True)
    results = {}
    for name, va in entries:
        res, why, ot = resolve(old, idx, va)
        results[name] = {"old": hex(va), "new": hex(res) if isinstance(res, int) else res, "why": why, "n_ins": len(ot)}
        print(f"{name:66} {hex(va)} -> {results[name]['new']} [{why}]", flush=True)
    json.dump(results, open(sys.argv[4], "w"), indent=1)
    print("unique:", sum(1 for r in results.values() if isinstance(r["new"], str)), "/", len(results))
