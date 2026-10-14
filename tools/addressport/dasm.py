"""Disassembly helper: python3 dis.py old|new VA [count]"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from pe import PE  # noqa: E402
from match import md  # noqa: E402

S = os.path.dirname(__file__)
PES = {}


def pe(which):
    if which not in PES:
        PES[which] = PE(os.path.join(S, "exe", f"{which}_mgsvtpp.exe"))
    return PES[which]


def dis(which, va, count=14, stop_at_ret=True):
    p = pe(which)
    off = p.va2off(va)
    out = []
    for ins in md.disasm(bytes(p.data[off:off + count * 15]), va):
        out.append(f"  {ins.address:#x}: {ins.bytes.hex():<22} {ins.mnemonic} {ins.op_str}")
        if len(out) >= count or (stop_at_ret and ins.mnemonic in ("ret", "int3")):
            break
    return "\n".join(out)


if __name__ == "__main__":
    print(dis(sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3]) if len(sys.argv) > 3 else 14))
