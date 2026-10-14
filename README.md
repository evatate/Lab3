# Lab 3: Packet crafting (mini Scapy)

- `layers.py` – Ether, IP, ICMP, UDP, TCP, DNS (build from fields or parse raw bytes), `/` stacking, `send`, `sendp`, `sr`, `sniff_packet`.
- `main.py` – ping (send/sendp/sr), DNS A lookup, TCP handshake + HTTP GET. Run on Linux: `sudo python3 main.py [iface]`.
- `test_offline.py` – socket-free checks of byte layout, checksums and parsing (runs anywhere).

Written with help from Claude (Anthropic Claude Code, Sonnet 5.5).

Note: the Wireshark screenshots and the handshake seq/ack numbers for the PDF must come from a run on the Linux VM.
