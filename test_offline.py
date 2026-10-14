"""Offline self-test (no sockets): build/parse round trips and checksum validation."""
import socket
import struct

from layers import Ether, IP, ICMP, UDP, TCP, DNS, checksum, ip_to_bytes, SYN, encode_name


def pseudo_ok(ip_bytes, proto):
    src, dst = ip_bytes[12:16], ip_bytes[16:20]
    seg = ip_bytes[20:]
    return checksum(src + dst + struct.pack("!BBH", 0, proto, len(seg)) + seg) == 0


# ICMP
pkt = Ether(src_mac="00:0c:29:a8:d0:96", dst_mac="00:50:56:f5:9e:21") / \
    IP(src_ip="192.168.159.129", dst_ip="8.8.8.8") / ICMP(id=1, seq=3, type=8)
raw = pkt.build()
assert raw[14:].hex() == "4500001c0000000040010aa8c0a89f81080808080800f7fb00010003", raw[14:].hex()
assert checksum(raw[14:34]) == 0
back = Ether(raw)
assert back.get_layer("ICMP").seq == 3 and back.get_layer("IP").dst_ip == "8.8.8.8"
back.show()

# DNS over UDP
pkt = Ether() / IP(src_ip="192.168.159.129", dst_ip="8.8.8.8") / UDP(sport=12345, dport=53) / \
    DNS(qname="vibrantcloud.org", id=0x030c)
ipb = pkt.payload.build()
assert pseudo_ok(ipb, 17) and checksum(ipb[:20]) == 0
assert ipb[28:].hex().startswith("030c01000001000000000000" + encode_name("vibrantcloud.org").hex())

# Parse a DNS response with a compressed name, a CNAME, and an A record
q = encode_name("www.example.com") + struct.pack("!HH", 1, 1)
resp = struct.pack("!HHHHHH", 7, 0x8180, 1, 2, 0, 0) + q
resp += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x0c"
resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
d = DNS(resp)
assert d.addr == "93.184.216.34" and len(d.answers) == 2 and d.answers[0]["rdata"] == "www.example.com"

# TCP with data, then round trip
pkt = IP(src_ip="10.0.0.2", dst_ip="1.2.3.4") / TCP(sport=1234, dport=80, seq=5, flags=SYN, data=b"hi")
ipb = pkt.build()
assert pseudo_ok(ipb, 6) and checksum(ipb[:20]) == 0
t = IP(ipb).get_layer("TCP")
assert (t.sport, t.dport, t.seq, t.flags, t.data) == (1234, 80, 5, SYN, b"hi")
print("all offline tests passed")
