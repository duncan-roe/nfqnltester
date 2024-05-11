## Introduction
nfqnltester is an extension of [utils/nfqnl_test.c](https://git.netfilter.org/libnetfilter_queue/tree/utils/nfqnl_test.c) in the [netfilter.org "libnetfilter_queue" project](https://www.netfilter.org/projects/libnetfilter_queue/index.html).
## Purpose
The primary purpose of nfqnltester is to exercise libnetfilter_queue nfnl-API functions (that used to be implemented using functions in libnfnetlink) that have been converted to use libmnl functions (the mnl-API). Part of the test is that nfqnltester is built without **-lnfnetlink**.
## Testing nfq_open_nfnl()
nfq_open_nfnl() opens an nfqueue handler from an existing nfnetlink handler. To get the nfnetlink handler, one needs to call nfnl_open() which requires **-lnfnetlink**.
Branch ***N*** has a version of nfqnltester built with **-lnfnetlink**. To build this special version, do the following:
```
git clone https://github.com/duncan-roe/nfqnltester
cd nfqnltester
git checkout N
make
```
## collect2: error: ld returned 1 exit status
If you get this error, and 2 lines up from it you see
```
/usr/bin/ld: nfqnltester.o: undefined reference to symbol 'nlif_query@@NFNETLINK_1.0.1'
```
then checkout the ***P*** branch. You won't get this error on the ***N*** branch, only on ***main***. I did make a version of libnetfilter_queue which provided the **nlif_*()** functions but it made the patch series too long.
## USAGE
As of today (11th May 2024), **./nfqnltester -h** gives the following:
```
Usage: nfqnltester [-b <batch factor>] [-t <test #>],... queue_number
       nfqnltester -h
  -b <n>: send a batch verdict only when packet id is a multiple of <n>.
          If a packet is mangled, then ack any previous un-acked packets
          and send the mangled one.
  -h: give this Help and exit
  -t <n>: do Test <n>. Tests are:
    0: Exit nfqnltester if incoming packet starts "q[[:space:]]"
    1: Replace 1st ZXC by VBN
    2: If packet mark is not 0xfaceb00c, set it to 0xfaceb00c
       and give verdict NF_REPEAT
       If packet mark *is* 0xfaceb00c, accept the packet
    3: Call nfnl_open then call nfq_open_nfnl
```
One must run nfqnltester as root.
Test 3 is only available on the ***N*** branch.
### Generating traffic
I use netcat (**nc**) to generate UDP/IPv4 packets.Server side:
```
nc -4 -k -l -q0 -p1042 -u  -v
```
Client side:
```
nc -4 -q0 -u dimstar 1042
```
Here, *dimstar* is my development desktop and I run the netcat client on a laptop so that packets will come from or go to a real ethernet device. You can omit **-v** if your netcat doesn't support it. If you have trouble with other options, try [the version I use](https://github.com/duncan-roe/netcat-openbsd) or **socat**.
### Sample nft table
```
table inet INET \
{
  # Test mangling via local interface and eth1
  chain FILTER_INPUT{type filter hook input priority filter - 1; policy accept;
    iif "lo" udp dport 1042 counter queue num 24 bypass
    iif "eth1" udp dport 1042 counter queue num 24 bypass
    iif "eth1" udp sport 1042 counter queue num 24 bypass
    iif "eth1" tcp dport 1042 counter queue num 24 bypass
    iif "eth1" tcp sport 1042 counter queue num 24 bypass
    iif "lo" tcp dport 1042 counter queue num 24 bypass;}

   chain FILTER_OUTPUT{type filter hook output priority filter - 1;policy accept
    oif "eth1" udp dport 1042 counter queue num 24 bypass
    oif "eth1" tcp dport 1042 counter queue num 24 bypass
    oif "eth1" udp sport 1042 counter queue num 24 bypass
    oif "eth1" tcp sport 1042 counter queue num 24 bypass;}
}
```
My first NIC shows up as *eth1* (no idea why).
