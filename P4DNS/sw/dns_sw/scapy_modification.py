# this function goes inside /usr/lib/python2.7/dist-packages/scapy/layers/dns.py
def DNSgetstr(s,p):
    name = ""
    q = 0
    jpath = [p]
    while 1:
        if p >= len(s):
            warning("DNS RR prematured end (ofs=%i, len=%i)"%(p,len(s)))
            break
        l = ord(s[p])
        p += 1
        if l & 0xc0:
            if not q:
                q = p+1
            if p >= len(s):
                warning("DNS incomplete jump token at (ofs=%i)" % p)
                break
            p = ((l & 0x3f) << 8) + ord(s[p]) - 12
            if p in jpath:
                warning("DNS decompression loop detected")
                break
            jpath.append(p)
            continue
        elif l > 0:
            name += s[p:p+l]+"."
            p += l
            continue
        break
    # if q:
    #     p = q
    return name,p
        
