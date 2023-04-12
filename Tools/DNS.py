#!/usr/bin/env python3

import socket
from random import randint

dns_query = b"\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01"

print("Domain to query for:")
name = input().strip().split(".")

for part in name:
    dns_query += bytes([len(part)]) + part.encode("ASCII")

dns_query += b"\x00\x00\xff\x00\x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"

ip_saddr = "192.168.248.132"
ip_daddrs = ["8.8.4.4", "8.8.8.8"]  # list of DNS server IP addresses

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

udp_dst = 53
udp_src = randint(1024, 0xffff - 1)

dns_query_packet = (
    b"\x00\x00"  # source port
    + bytes([udp_dst >> 8, udp_dst & 0xff])  # destination port
    + bytes([(len(dns_query) + 8) >> 8, (len(dns_query) + 8) & 0xff])  # length
    + b"\x00\x00"  # checksum
    + dns_query
)

ip_packet = (
    b"\x45\x00"  # version and header length, type of service
    + bytes([(len(dns_query_packet) + 20) >> 8, (len(dns_query_packet) + 20) & 0xff])  # total length
    + b"\x00\x00\x00\x00\x40\x11\x00\x00"  # identification, flags, TTL, protocol
    + socket.inet_aton(ip_saddr)  # source IP
    + b"\x00\x00\x00\x00"  # destination IP (will be filled in later)
    + dns_query_packet
)

for ip_daddr in ip_daddrs:
    ip_packet = ip_packet[:16] + socket.inet_aton(ip_daddr) + ip_packet[20:]
    sock.sendto(ip_packet, (ip_daddr, 0))

sock.close()
