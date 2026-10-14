"""Minimal PE64 reader: sections, VA<->file offset, version string."""
import mmap
import re
import struct
import sys


class PE:
    def __init__(self, path):
        f = open(path, "rb")
        self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        assert d[pe:pe + 4] == b"PE\0\0"
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        optsz = struct.unpack_from("<H", d, pe + 20)[0]
        opt = pe + 24
        assert struct.unpack_from("<H", d, opt)[0] == 0x20B, "not PE32+"
        self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
        self.timestamp = struct.unpack_from("<I", d, pe + 8)[0]
        self.sections = []
        s = opt + optsz
        for i in range(nsec):
            name = d[s:s + 8].rstrip(b"\0").decode(errors="replace")
            vsize, va, rsize, raw = struct.unpack_from("<IIII", d, s + 8)
            chars = struct.unpack_from("<I", d, s + 36)[0]
            self.sections.append((name, va, vsize, raw, rsize, chars))
            s += 40

    def va2off(self, va):
        rva = va - self.image_base
        for name, sva, vsize, raw, rsize, _ in self.sections:
            if sva <= rva < sva + max(vsize, rsize):
                o = rva - sva
                return raw + o if o < rsize else None
        return None

    def off2va(self, off):
        for name, sva, vsize, raw, rsize, _ in self.sections:
            if raw <= off < raw + rsize:
                return self.image_base + sva + (off - raw)
        return None

    def section_of(self, va):
        rva = va - self.image_base
        for sec in self.sections:
            if sec[1] <= rva < sec[1] + max(sec[2], sec[4]):
                return sec[0]
        return None

    def version(self):
        # VS_FIXEDFILEINFO signature 0xFEEF04BD
        i = self.data.find(struct.pack("<I", 0xFEEF04BD))
        if i < 0:
            return None
        ms, ls = struct.unpack_from("<II", self.data, i + 8)
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


if __name__ == "__main__":
    p = PE(sys.argv[1])
    print("image base", hex(p.image_base), "timestamp", p.timestamp, "version", p.version())
    for s in p.sections:
        print(f"  {s[0]:8} va={s[1]:#x} vsize={s[2]:#x} raw={s[3]:#x} rsize={s[4]:#x} chars={s[5]:#x}")
