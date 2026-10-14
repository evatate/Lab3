"""
Name:    Eva Tate
Course:  Computer Networks - Lab 3
Date:    October 2025

Test driver for layers.py: ping (send / sendp / sr), DNS A lookup, and an HTTP GET
over a hand-built TCP handshake. Run on Linux as root:  sudo python3 main.py [iface]

AI assistance: written with the help of Claude (Anthropic's Claude Code, Sonnet 5.5).
"""

import random
import subprocess
import sys
import time

from layers import (Ether, IP, ICMP, UDP, TCP, DNS, send, sr, sendp, sniff_packet,
                    get_route, get_my_mac, get_gateway_mac, _open_recv, _recv_matching,
                    SYN, ACK, PSH, FIN, RST)

IPT_RULE = ["-p", "tcp", "-m", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]


def dns_lookup(domain, my_ip, my_mac, dst_mac, resolver="8.8.8.8"):
    sport = random.randint(1024, 65535)
    pkt = Ether(src_mac=my_mac, dst_mac=dst_mac) / IP(src_ip=my_ip, dst_ip=resolver) / \
        UDP(sport=sport, dport=53) / DNS(qname=domain)
    reply = sr(pkt)
    if reply is None:
        raise RuntimeError("no DNS reply")
    return reply.get_layer("DNS").addr


def http_get(host, server_ip, my_ip, iface, my_mac, dst_mac, path="/index.html"):
    sport = random.randint(1024, 65535)
    isn = random.getrandbits(32)
    base = Ether(src_mac=my_mac, dst_mac=dst_mac) / IP(src_ip=my_ip, dst_ip=server_ip)

    def tcp_pkt(**kw):
        return IP(src_ip=my_ip, dst_ip=server_ip) / TCP(sport=sport, dport=80, **kw)

    # 1. SYN -> SYN/ACK
    synack = sr(Ether(src_mac=my_mac, dst_mac=dst_mac) / tcp_pkt(seq=isn, flags=SYN))
    if synack is None:
        raise RuntimeError("no SYN-ACK")
    srv = synack.get_layer("TCP")
    my_seq, srv_next = isn + 1, srv.seq + 1

    # 2. ACK completes the handshake
    send(tcp_pkt(seq=my_seq, ack=srv_next, flags=ACK))

    # 3. HTTP GET. Open the receive socket first so no response is missed.
    request = ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)).encode()
    from_server = lambda f: (f.get_layer("IP") and f.get_layer("TCP") and
                             f.get_layer("IP").src_ip == server_ip and
                             f.get_layer("TCP").sport == 80 and
                             f.get_layer("TCP").dport == sport)
    sock = _open_recv(iface)
    body = b""
    try:
        send(tcp_pkt(seq=my_seq, ack=srv_next, flags=PSH | ACK, data=request))
        my_seq += len(request)
        deadline = time.time() + 10
        while time.time() < deadline:
            frame = _recv_matching(sock, from_server, 3)
            if frame is None:
                break
            seg = frame.get_layer("TCP")
            if seg.flags & RST:
                break
            if seg.seq == srv_next and (seg.data or seg.flags & FIN):
                body += seg.data
                srv_next += len(seg.data) + bool(seg.flags & FIN)
                send(tcp_pkt(seq=my_seq, ack=srv_next, flags=ACK))
                if seg.flags & FIN:
                    break
            elif seg.data:  # retransmission or gap: re-ACK what we expect
                send(tcp_pkt(seq=my_seq, ack=srv_next, flags=ACK))
        # 4. close our side
        send(tcp_pkt(seq=my_seq, ack=srv_next, flags=FIN | ACK))
    finally:
        sock.close()
    return body


if __name__ == "__main__":
    dst = "8.8.8.8"
    iface, my_ip = get_route(dst)
    if len(sys.argv) > 1:
        iface = sys.argv[1]
    my_mac = get_my_mac(iface)
    dst_mac = get_gateway_mac()
    print("iface=%s my_ip=%s my_mac=%s gateway_mac=%s" % (iface, my_ip, my_mac, dst_mac))

    # Example 1: ICMP echo with send (L3), sendp (L2) and sr
    print("Ping example")
    eth = Ether(src_mac=my_mac, dst_mac=dst_mac)
    ip = IP(src_ip=my_ip, dst_ip=dst)
    icmp = ICMP(id=1, seq=1, type=8)
    pkt = eth / ip / icmp
    send(pkt)
    icmp.seq = 2  # new sequence number so the reply is distinguishable
    sendp(pkt, iface)
    time.sleep(1)
    icmp.seq = 3
    sr(pkt)
    print("\n")

    # Example 2: DNS A record
    print("DNS example")
    domain_name = "vibrantcloud.org"
    pkt = Ether(src_mac=my_mac, dst_mac=dst_mac) / IP(src_ip=my_ip, dst_ip=dst) / \
        UDP(sport=12345, dport=53) / DNS(qname=domain_name)
    dns = sr(pkt)
    addr = dns.get_layer("DNS").addr
    print("Address for %s: %s" % (domain_name, addr))
    print("\n")

    # Example 3: TCP handshake + HTTP GET (needs the RST-suppressing firewall rule)
    print("TCP example")
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT"] + IPT_RULE, check=True)
    try:
        html = http_get(domain_name, addr, my_ip, iface, my_mac, dst_mac)
    finally:
        subprocess.run(["sudo", "iptables", "-D", "OUTPUT"] + IPT_RULE)
    print(html.decode(errors="replace"))
