"""
Name:    Eva Tate
Course:  Computer Networks - Lab 3 (Packet crafting, a mini Scapy)
Date:    October 2025

A small Scapy-like library: Ether / IP / ICMP / UDP / TCP / DNS layers that can
be built from header fields or parsed from raw bytes, stacked with "/", and
transmitted with send / sendp / sr / sniff_packet.

AI assistance: this code was written with the help of Claude (Anthropic's
Claude Code, model Sonnet 5.5). All design and output should be reviewed by the
author.
"""

import os
import random
import socket
import struct
import subprocess
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
PACKET_OUTGOING = 4

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def checksum(data: bytes) -> int:
    """16-bit one's complement of the one's complement sum of 16-bit words."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def bytes_to_mac(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def bytes_to_ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


def get_route(dst_ip: str):
    """Return (interface, source ip) the kernel would use to reach dst_ip (Linux)."""
    iface = src = None
    try:
        out = subprocess.run(["ip", "route", "get", dst_ip], capture_output=True,
                             text=True, check=True).stdout.split()
        if "dev" in out:
            iface = out[out.index("dev") + 1]
        if "src" in out:
            src = out[out.index("src") + 1]
    except (OSError, subprocess.CalledProcessError):
        pass
    if src is None:  # portable fallback: let the kernel pick via a UDP "connect"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((dst_ip, 9))
            src = s.getsockname()[0]
        finally:
            s.close()
    return iface, src


def get_my_mac(iface: str) -> str:
    with open("/sys/class/net/%s/address" % iface) as f:
        return f.read().strip()


def get_gateway_mac(dst_ip: str = "8.8.8.8") -> str:
    """MAC of the default gateway, read from the ARP cache (pings it once if needed)."""
    out = subprocess.run(["ip", "route", "show", "default"], capture_output=True,
                         text=True, check=True).stdout.split()
    gw = out[out.index("via") + 1]
    for attempt in range(2):
        with open("/proc/net/arp") as f:
            for line in f.read().splitlines()[1:]:
                cols = line.split()
                if cols[0] == gw and cols[3] != "00:00:00:00:00:00":
                    return cols[3]
        subprocess.run(["ping", "-c", "1", "-W", "1", gw], capture_output=True)
    raise RuntimeError("could not find MAC for gateway %s" % gw)


def _fmt_data(data: bytes) -> str:
    """Show payload bytes as text when printable, otherwise hex."""
    try:
        text = data.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            return text
    except UnicodeDecodeError:
        pass
    return data.hex()


# --------------------------------------------------------------------------
# Base class
# --------------------------------------------------------------------------
class Layer:
    name = "Layer"

    def __init__(self):
        self.payload = None

    # Stack layers: (Ether / IP) / ICMP. The new layer goes on the end of the chain.
    def __truediv__(self, other):
        last = self
        while last.payload is not None:
            last = last.payload
        last.payload = other
        # Layer 4 over layer 3: hand the IP addresses down for the pseudo header.
        node, ip = self, None
        while node is not None:
            if isinstance(node, IP):
                ip = node
            elif ip is not None and hasattr(node, "src_ip"):
                node.src_ip, node.dst_ip = ip.src_ip, ip.dst_ip
            node = node.payload
        return self

    def build(self) -> bytes:
        raise NotImplementedError

    def _show_fields(self):
        return []

    def show(self, indent=0):
        pad = "  " * indent
        print("%s### %s ###" % (pad, self.name))
        for key, value in self._show_fields():
            print("%s  %s: %s" % (pad, key, value))
        if self.payload is not None:
            self.payload.show(indent + 1)

    def get_layer(self, name):
        node = self
        while node is not None:
            if node.name == name:
                return node
            node = node.payload
        return None

    def __bytes__(self):
        return self.build()


def _payload_bytes(layer) -> bytes:
    return layer.payload.build() if layer.payload is not None else b""


# --------------------------------------------------------------------------
# Layer 2: Ethernet
# --------------------------------------------------------------------------
class Ether(Layer):
    name = "Ether"

    def __init__(self, raw=None, src_mac="00:00:00:00:00:00", dst_mac="ff:ff:ff:ff:ff:ff",
                 type=ETH_P_IP):
        super().__init__()
        if raw is not None:
            self.dst_mac = bytes_to_mac(raw[0:6])
            self.src_mac = bytes_to_mac(raw[6:12])
            self.type = struct.unpack("!H", raw[12:14])[0]
            rest = raw[14:]
            if self.type == ETH_P_IP:
                self.payload = IP(rest)
            elif rest:
                self.payload = Raw(rest)
        else:
            self.src_mac, self.dst_mac, self.type = src_mac, dst_mac, type

    def build(self) -> bytes:
        header = mac_to_bytes(self.dst_mac) + mac_to_bytes(self.src_mac) + \
            struct.pack("!H", self.type)
        return header + _payload_bytes(self)

    def _show_fields(self):
        return [("dst_mac", self.dst_mac), ("src_mac", self.src_mac),
                ("type", "0x%04x" % self.type)]


class Raw(Layer):
    """Opaque bytes for protocols we do not decode."""
    name = "Raw"

    def __init__(self, data=b""):
        super().__init__()
        self.data = data

    def build(self) -> bytes:
        return self.data

    def _show_fields(self):
        return [("data", self.data.hex())]


# --------------------------------------------------------------------------
# Layer 3: IPv4
# --------------------------------------------------------------------------
class IP(Layer):
    name = "IP"
    PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def __init__(self, raw=None, src_ip=None, dst_ip="0.0.0.0", ttl=64, proto=None,
                 tos=0, ident=0, flags_frag=0, options=b""):
        super().__init__()
        self.checksum = None
        if raw is not None:
            vihl, self.tos, self.total_len, self.ident, self.flags_frag, self.ttl, \
                self.proto, self.checksum = struct.unpack("!BBHHHBBH", raw[:12])
            self.version, self.ihl = vihl >> 4, vihl & 0xF
            self.src_ip = bytes_to_ip(raw[12:16])
            self.dst_ip = bytes_to_ip(raw[16:20])
            hdr_len = self.ihl * 4
            self.options = raw[20:hdr_len]
            body = raw[hdr_len:self.total_len]  # drops Ethernet padding
            if self.proto == 1:
                self.payload = ICMP(body)
            elif self.proto == 6:
                self.payload = TCP(body)
            elif self.proto == 17:
                self.payload = UDP(body)
            elif body:
                self.payload = Raw(body)
        else:
            self.version, self.tos, self.ident, self.flags_frag = 4, tos, ident, flags_frag
            self.ttl, self.proto, self.options = ttl, proto, options
            self.src_ip, self.dst_ip = src_ip, dst_ip
            self.ihl = 5 + len(options) // 4
            self.total_len = None

    def _resolve_src(self):
        return self.src_ip or get_route(self.dst_ip)[1]

    def build(self) -> bytes:
        src = self._resolve_src()
        proto = self.proto
        if proto is None:
            proto = {"ICMP": 1, "TCP": 6, "UDP": 17}.get(
                self.payload.name if self.payload else None, 0)
        # layer 4 needs the addresses for its pseudo header checksum
        if self.payload is not None and hasattr(self.payload, "src_ip"):
            self.payload.src_ip, self.payload.dst_ip = src, self.dst_ip
        body = _payload_bytes(self)
        self.ihl = 5 + len(self.options) // 4
        self.total_len = self.ihl * 4 + len(body)
        header = struct.pack("!BBHHHBBH4s4s", (4 << 4) | self.ihl, self.tos, self.total_len,
                             self.ident, self.flags_frag, self.ttl, proto, 0,
                             ip_to_bytes(src), ip_to_bytes(self.dst_ip)) + self.options
        self.checksum = checksum(header)
        header = header[:10] + struct.pack("!H", self.checksum) + header[12:]
        return header + body

    def _show_fields(self):
        return [("version", self.version), ("ihl", self.ihl), ("tos", self.tos),
                ("total_len", self.total_len), ("ident", self.ident),
                ("flags_frag", "0x%04x" % self.flags_frag), ("ttl", self.ttl),
                ("proto", self.proto if self.proto is not None else "auto"),
                ("checksum", "0x%04x" % self.checksum if self.checksum is not None else None),
                ("src_ip", self.src_ip), ("dst_ip", self.dst_ip)]


# --------------------------------------------------------------------------
# Layer 3: ICMP
# --------------------------------------------------------------------------
class ICMP(Layer):
    name = "ICMP"

    def __init__(self, raw=None, type=8, code=0, id=0, seq=0, data=b""):
        super().__init__()
        self.checksum = None
        if raw is not None:
            self.type, self.code, self.checksum, self.id, self.seq = \
                struct.unpack("!BBHHH", raw[:8])
            self.data = raw[8:]
        else:
            self.type, self.code, self.id, self.seq, self.data = type, code, id, seq, data

    def build(self) -> bytes:
        body = self.data if self.payload is None else self.payload.build()
        msg = struct.pack("!BBHHH", self.type, self.code, 0, self.id, self.seq) + body
        self.checksum = checksum(msg)
        return msg[:2] + struct.pack("!H", self.checksum) + msg[4:]

    def _show_fields(self):
        return [("type", self.type), ("code", self.code),
                ("checksum", "0x%04x" % self.checksum if self.checksum is not None else None),
                ("id", self.id), ("seq", self.seq), ("data", self.data.hex())]


# --------------------------------------------------------------------------
# Layer 4: UDP
# --------------------------------------------------------------------------
class UDP(Layer):
    name = "UDP"

    def __init__(self, raw=None, sport=12345, dport=53, data=b""):
        super().__init__()
        self.src_ip = self.dst_ip = None  # filled in when stacked on an IP layer
        self.checksum = None
        self.length = None
        if raw is not None:
            self.sport, self.dport, self.length, self.checksum = struct.unpack("!HHHH", raw[:8])
            body = raw[8:self.length] if 8 <= self.length <= len(raw) else raw[8:]
            self.data = b""
            if 53 in (self.sport, self.dport) and body:
                self.payload = DNS(body)
            else:
                self.data = body
        else:
            self.sport, self.dport, self.data = sport, dport, data

    def build(self) -> bytes:
        body = self.data if self.payload is None else self.payload.build()
        self.length = 8 + len(body)
        header = struct.pack("!HHHH", self.sport, self.dport, self.length, 0)
        pseudo = ip_to_bytes(self.src_ip) + ip_to_bytes(self.dst_ip) + \
            struct.pack("!BBH", 0, 17, self.length)
        self.checksum = checksum(pseudo + header + body) or 0xFFFF
        return header[:6] + struct.pack("!H", self.checksum) + body

    def _show_fields(self):
        f = [("sport", self.sport), ("dport", self.dport), ("length", self.length),
             ("checksum", "0x%04x" % self.checksum if self.checksum is not None else None)]
        if self.payload is None:
            f.append(("data", _fmt_data(self.data)))
        return f


# --------------------------------------------------------------------------
# Layer 4: TCP
# --------------------------------------------------------------------------
class TCP(Layer):
    name = "TCP"

    def __init__(self, raw=None, sport=12345, dport=80, seq=0, ack=0, flags=SYN,
                 window=8192, urg=0, options=b"", data=b""):
        super().__init__()
        self.src_ip = self.dst_ip = None
        self.checksum = None
        if raw is not None:
            self.sport, self.dport, self.seq, self.ack, off_flags, self.window, \
                self.checksum, self.urg = struct.unpack("!HHIIHHHH", raw[:20])
            self.offset = (off_flags >> 12) * 4
            self.flags = off_flags & 0x1FF
            self.options = raw[20:self.offset]
            self.data = raw[self.offset:]
        else:
            self.sport, self.dport, self.seq, self.ack = sport, dport, seq, ack
            self.flags, self.window, self.urg, self.data = flags, window, urg, data
            pad = (-len(options)) % 4
            self.options = options + b"\x00" * pad
            self.offset = 20 + len(self.options)

    def flag_names(self):
        names = [n for n, bit in (("FIN", FIN), ("SYN", SYN), ("RST", RST), ("PSH", PSH),
                                  ("ACK", ACK), ("URG", URG)) if self.flags & bit]
        return ",".join(names) or "none"

    def build(self) -> bytes:
        body = self.data if self.payload is None else self.payload.build()
        self.offset = 20 + len(self.options)
        header = struct.pack("!HHIIHHHH", self.sport, self.dport, self.seq & 0xFFFFFFFF,
                             self.ack & 0xFFFFFFFF, ((self.offset // 4) << 12) | self.flags,
                             self.window, 0, self.urg) + self.options
        seg_len = len(header) + len(body)
        pseudo = ip_to_bytes(self.src_ip) + ip_to_bytes(self.dst_ip) + \
            struct.pack("!BBH", 0, 6, seg_len)
        self.checksum = checksum(pseudo + header + body)
        return header[:16] + struct.pack("!H", self.checksum) + header[18:] + body

    def seg_len(self) -> int:
        """Sequence space consumed by this segment (data, plus 1 each for SYN and FIN)."""
        return len(self.data) + bool(self.flags & SYN) + bool(self.flags & FIN)

    def _show_fields(self):
        return [("sport", self.sport), ("dport", self.dport), ("seq", self.seq),
                ("ack", self.ack), ("flags", "%s (0x%02x)" % (self.flag_names(), self.flags)),
                ("offset", self.offset), ("window", self.window),
                ("checksum", "0x%04x" % self.checksum if self.checksum is not None else None),
                ("urg", self.urg), ("header_data", self.options.hex()),
                ("message", _fmt_data(self.data))]


# --------------------------------------------------------------------------
# Layer 7: DNS
# --------------------------------------------------------------------------
def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def decode_name(msg: bytes, off: int):
    """Decode a (possibly compressed) DNS name. Returns (name, offset after the name)."""
    labels, end, hops = [], None, 0
    while True:
        length = msg[off]
        if length & 0xC0 == 0xC0:  # compression pointer
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | msg[off + 1]
            hops += 1
            if hops > 32:
                raise ValueError("DNS compression loop")
        elif length == 0:
            return ".".join(labels), (end if end is not None else off + 1)
        else:
            labels.append(msg[off + 1:off + 1 + length].decode(errors="replace"))
            off += 1 + length


class DNS(Layer):
    name = "DNS"
    RR_A = 1

    def __init__(self, raw=None, qname="", qtype=1, qclass=1, id=None, rd=1):
        super().__init__()
        self.answers = []   # list of dicts: name, type, class, ttl, rdata
        self.addr = None    # RDATA of the first A record in the answer section
        if raw is not None:
            self._parse(raw)
        else:
            self.id = random.getrandbits(16) if id is None else id
            self.qr = self.opcode = self.aa = self.tc = self.ra = self.z = self.rcode = 0
            self.rd = rd
            self.qdcount, self.ancount, self.nscount, self.arcount = 1, 0, 0, 0
            self.qname, self.qtype, self.qclass = qname, qtype, qclass

    def _parse(self, msg):
        self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount = \
            struct.unpack("!HHHHHH", msg[:12])
        self.qr, self.opcode = flags >> 15, (flags >> 11) & 0xF
        self.aa, self.tc, self.rd = (flags >> 10) & 1, (flags >> 9) & 1, (flags >> 8) & 1
        self.ra, self.z, self.rcode = (flags >> 7) & 1, (flags >> 4) & 7, flags & 0xF
        self.qname, self.qtype, self.qclass = "", 0, 0
        off = 12
        try:
            for i in range(self.qdcount):
                name, off = decode_name(msg, off)
                qtype, qclass = struct.unpack("!HH", msg[off:off + 4])
                off += 4
                if i == 0:
                    self.qname, self.qtype, self.qclass = name, qtype, qclass
            # walk the answer section using the header's answer count
            for _ in range(self.ancount):
                name, off = decode_name(msg, off)
                rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
                off += 10
                rdata = msg[off:off + rdlen]
                if rtype == 1 and rdlen == 4:
                    value = bytes_to_ip(rdata)
                elif rtype == 28 and rdlen == 16:
                    value = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype in (2, 5, 12):  # NS, CNAME, PTR
                    value = decode_name(msg, off)[0]
                else:
                    value = rdata.hex()
                off += rdlen
                self.answers.append({"name": name, "type": rtype, "class": rclass,
                                     "ttl": ttl, "rdata": value})
                if rtype == 1 and self.addr is None:
                    self.addr = value
        except (struct.error, IndexError, ValueError):
            pass  # truncated or malformed: keep whatever we decoded

    def build(self) -> bytes:
        flags = (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | (self.tc << 9) | \
            (self.rd << 8) | (self.ra << 7) | (self.z << 4) | self.rcode
        header = struct.pack("!HHHHHH", self.id, flags, self.qdcount, self.ancount,
                             self.nscount, self.arcount)
        return header + encode_name(self.qname) + struct.pack("!HH", self.qtype, self.qclass)

    def _show_fields(self):
        f = [("id", self.id), ("qr", self.qr), ("opcode", self.opcode), ("aa", self.aa),
             ("tc", self.tc), ("rd", self.rd), ("ra", self.ra), ("z", self.z),
             ("rcode", self.rcode), ("qdcount", self.qdcount), ("ancount", self.ancount),
             ("nscount", self.nscount), ("arcount", self.arcount),
             ("qname", self.qname), ("qtype", self.qtype), ("qclass", self.qclass)]
        for i, a in enumerate(self.answers):
            f.append(("answer[%d]" % i, "%s type=%d ttl=%d rdata=%s" %
                      (a["name"], a["type"], a["ttl"], a["rdata"])))
        if self.addr:
            f.append(("addr", self.addr))
        return f


# --------------------------------------------------------------------------
# Sending and receiving
# --------------------------------------------------------------------------
def _ip_layer(pkt):
    """Return the IP layer of pkt (skipping Ether if present)."""
    ip = pkt.get_layer("IP")
    if ip is None:
        raise ValueError("packet has no IP layer")
    return ip


def send(pkt):
    """Transmit at layer 3; the kernel adds the Ethernet header."""
    ip = _ip_layer(pkt)
    data = ip.build()
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    try:
        sock.sendto(data, (ip.dst_ip, 0))
    finally:
        sock.close()
    print("Sent packet to %s (Layer 3)" % ip.dst_ip)


def sendp(pkt, interface):
    """Transmit a full frame at layer 2 on the given interface."""
    if pkt.name != "Ether":
        raise ValueError("sendp needs a packet that starts with Ether")
    frame = pkt.build()
    frame += b"\x00" * max(0, 60 - len(frame))  # pad to the Ethernet minimum
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((interface, 0))
        sock.send(frame)
    finally:
        sock.close()
    print("Sent packet on %s (Layer 2)" % interface)


def _open_recv(iface=None):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if iface:
        sock.bind((iface, 0))
    return sock


def _recv_matching(sock, match, timeout):
    """Read frames until match(Ether) is true; None on timeout."""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            raw, addr = sock.recvfrom(65535)
        except socket.timeout:
            return None
        if addr[2] == PACKET_OUTGOING or len(raw) < 14:
            continue  # our own transmissions, runts
        try:
            frame = Ether(raw)
            if match is None or match(frame):
                return frame
        except Exception:
            continue  # malformed or unrelated frame


def _is_reply(req, frame):
    """Does frame answer the request (req is the IP layer parsed from the sent bytes)?"""
    rip = frame.get_layer("IP")
    if rip is None or rip.src_ip != req.dst_ip or rip.dst_ip != req.src_ip:
        return False
    p, q = req.payload, rip.payload
    if isinstance(p, ICMP):
        return isinstance(q, ICMP) and q.id == p.id and q.seq == p.seq and q.type != p.type
    if isinstance(p, UDP):
        if not (isinstance(q, UDP) and q.sport == p.dport and q.dport == p.sport):
            return False
        if isinstance(p.payload, DNS):
            return isinstance(q.payload, DNS) and q.payload.id == p.payload.id
        return True
    if isinstance(p, TCP):
        if not (isinstance(q, TCP) and q.sport == p.dport and q.dport == p.sport):
            return False
        return bool(q.flags & RST) or (bool(q.flags & ACK) and
                                       q.ack == (p.seq + p.seg_len()) & 0xFFFFFFFF)
    return True


def sr(pkt, timeout=3, iface=None, verbose=True):
    """Send at layer 3, return the first frame (as Ether) that answers it, or None."""
    ip = _ip_layer(pkt)
    req = IP(ip.build())  # re-parse so defaults (src ip, proto, lengths) are real values
    if iface is None:
        iface = get_route(ip.dst_ip)[0]
    recv_sock = _open_recv(iface)  # open BEFORE sending so we cannot miss the reply
    try:
        print("SR is sending")
        send(pkt)
        print("Sent packet to %s, waiting for reply..." % ip.dst_ip)
        reply = _recv_matching(recv_sock, lambda f: _is_reply(req, f), timeout)
    finally:
        recv_sock.close()
    if reply is None:
        print("Timed out waiting for reply")
    elif verbose:
        print("Received reply from %s" % iface)
        reply.show()
    return reply


def sniff_packet(timeout=10, iface=None, match=None, verbose=True):
    """Receive one frame at layer 2 (optionally the first one satisfying match)."""
    sock = _open_recv(iface)
    try:
        frame = _recv_matching(sock, match, timeout)
    finally:
        sock.close()
    if frame is None:
        print("Timed out waiting for packet")
    elif verbose:
        frame.show()
    return frame


sniff = sniff_packet
