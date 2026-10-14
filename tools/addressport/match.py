"""Map function addresses from old mgsvtpp.exe to new mgsvtpp.exe by masked byte signatures.

For each old address: disassemble from the function start, mask bytes that change between builds
(RIP-relative displacements, relative branch targets, absolute addresses), then search the new exe's
executable sections. Signature grows until the match is unique.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402

# capstone: `pip install capstone`, or a local build in ./cs (bindings/python + build/libcapstone.so)
CS = os.path.join(os.path.dirname(__file__), "cs")
if os.path.isdir(CS):
    os.environ.setdefault("LIBCAPSTONE_PATH", os.path.join(CS, "build"))
    sys.path.insert(0, os.path.join(CS, "bindings", "python"))
import capstone  # noqa: E402
from capstone import x86_const as X  # noqa: E402

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

IMG_LO, IMG_HI = 0x140000000, 0x150000000


def masked_signature(pe, va, max_bytes):
    """Return (bytes, mask) where mask[i] True = byte must match. Stops at ret/int3/jmp."""
    off = pe.va2off(va)
    code = bytes(pe.data[off:off + max_bytes + 16])
    sig, mask = bytearray(), []
    for ins in md.disasm(code, va):
        b = bytes(ins.bytes)
        m = [True] * len(b)
        enc_disp_off = ins.disp_offset
        enc_disp_size = ins.disp_size
        enc_imm_off = ins.imm_offset
        enc_imm_size = ins.imm_size
        rip_rel = False
        for op in ins.operands:
            if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
                rip_rel = True
            if op.type == X.X86_OP_MEM and IMG_LO <= (op.mem.disp & 0xFFFFFFFFFFFFFFFF) < IMG_HI:
                rip_rel = True
        if rip_rel and enc_disp_size:
            for i in range(enc_disp_off, enc_disp_off + enc_disp_size):
                m[i] = False
        is_branch = ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)
        if enc_imm_size:
            imm_abs = False
            for op in ins.operands:
                if op.type == X.X86_OP_IMM and IMG_LO <= (op.imm & 0xFFFFFFFFFFFFFFFF) < IMG_HI:
                    imm_abs = True
            if is_branch or imm_abs:
                for i in range(enc_imm_off, enc_imm_off + enc_imm_size):
                    m[i] = False
        sig += b
        mask += m
        if len(sig) >= max_bytes:
            break
        if ins.mnemonic in ("ret", "int3") or (ins.mnemonic == "jmp" and ins.op_str.startswith("0x")):
            break
        if ins.mnemonic == "jmp":
            break
    return bytes(sig), mask


def exec_ranges(pe):
    res = []
    for name, va, vsize, raw, rsize, chars in pe.sections:
        if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            res.append((raw, raw + rsize))
    return res


def anchor(sig, mask):
    """Longest run of fixed bytes: (start, length)."""
    best, cur_s, cur_l = (0, 0), 0, 0
    for i, m in enumerate(mask):
        if m:
            if cur_l == 0:
                cur_s = i
            cur_l += 1
            if cur_l > best[1]:
                best = (cur_s, cur_l)
        else:
            cur_l = 0
    return best


def find_all(pe, ranges, sig, mask, limit=50):
    a_s, a_l = anchor(sig, mask)
    if a_l < 4:
        return None  # too generic
    needle = sig[a_s:a_s + a_l]
    data = pe.data
    hits = []
    for lo, hi in ranges:
        i = data.find(needle, lo, hi)
        while i >= 0:
            start = i - a_s
            if start >= lo and start + len(sig) <= hi:
                window = data[start:start + len(sig)]
                if all((not m) or window[k] == sig[k] for k, m in enumerate(mask)):
                    hits.append(start)
                    if len(hits) >= limit:
                        return hits
            i = data.find(needle, i + 1, hi)
    return hits


def match(old, new, va, ranges):
    tried = []
    for size in (48, 96, 160, 256, 512):
        sig, mask = masked_signature(old, va, size)
        if len(sig) < 6:
            return None, f"signature too short ({len(sig)} bytes)", tried
        hits = find_all(new, ranges, sig, mask)
        n = None if hits is None else len(hits)
        tried.append((len(sig), n))
        if hits is None:
            continue
        if len(hits) == 1:
            return new.off2va(hits[0]), f"unique, sig {len(sig)}b, {sum(mask)} fixed", tried
        if len(hits) == 0:
            # longer signature won't help
            return None, "no match", tried
        if len(sig) < size:
            # function ended, can't extend: pick nothing, ambiguous
            return [new.off2va(h) for h in hits], f"ambiguous ({len(hits)} hits, whole function {len(sig)}b)", tried
    return [new.off2va(h) for h in hits] if hits else None, "ambiguous after max length", tried


def parse_addresses(path):
    out = []
    for line in open(path):
        m = re.search(r'\{"(\w+)",\s*(0x[0-9a-fA-F]+)\}', line)
        if m and not line.strip().startswith("//"):
            out.append((m.group(1), int(m.group(2), 16)))
    return out


if __name__ == "__main__":
    old = PE(sys.argv[1])
    new = PE(sys.argv[2])
    entries = parse_addresses(sys.argv[3])
    ranges = exec_ranges(new)
    results = {}
    for name, va in entries:
        res, why, tried = match(old, new, va, ranges)
        results[name] = {"old": hex(va), "new": hex(res) if isinstance(res, int) else ([hex(x) for x in res] if res else None), "why": why, "tried": tried}
        print(f"{name:70} {hex(va)} -> {results[name]['new']}  [{why}]", flush=True)
    json.dump(results, open(sys.argv[4], "w"), indent=1)
    ok = sum(1 for r in results.values() if isinstance(r["new"], str))
    print(f"\nunique: {ok}/{len(results)}")
