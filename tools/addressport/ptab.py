import struct
def pdata_raw(pe):
    d=pe.data
    peo=struct.unpack_from("<I",d,0x3C)[0]; opt=peo+24
    rva,size=struct.unpack_from("<II",d,opt+112+3*8)
    off=pe.va2off(pe.image_base+rva)
    out=[]
    for i in range(size//12):
        b,e,u=struct.unpack_from("<III",d,off+i*12)
        out.append((pe.image_base+b,pe.image_base+e,u))
    return out
