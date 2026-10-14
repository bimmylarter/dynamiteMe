import sys,struct,re
sys.path.insert(0,'.')
from pe import PE
import numpy as np
def rel32_xrefs(p, targets, opcodes=(0xE8,0xE9)):
    """find E8/E9 rel32 in executable sections whose destination is in targets. returns {target:[(srcva,opcode)]}"""
    res={t:[] for t in targets}
    tset=np.array(sorted(targets),dtype=np.int64)
    for name,va,vsize,raw,rsize,ch in p.sections:
        if not ch & 0x20000000: continue
        buf=np.frombuffer(p.data,dtype=np.uint8,count=rsize,offset=raw)
        for opc in opcodes:
            idx=np.nonzero(buf[:-5]==opc)[0]
            rel=(buf[idx+1].astype(np.int64)|(buf[idx+2].astype(np.int64)<<8)|(buf[idx+3].astype(np.int64)<<16)|(buf[idx+4].astype(np.int64)<<24))
            rel=np.where(rel>=2**31,rel-2**32,rel)
            src=p.image_base+va+idx
            dst=src+5+rel
            hit=np.isin(dst,tset)
            for s,d in zip(src[hit],dst[hit]):
                res[int(d)].append((int(s),opc))
    return res
