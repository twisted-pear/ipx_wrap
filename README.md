# ipx_wrap

The idea is that IPv6 packets that are sent are turned into IPX packets on the
wire and IPX packets that are received are turned into IPv6 packets that can be
routed by the IPv6 network stack.

To rewrite the packets there are two BPF programs. To configure them there is a
simple command-line utility (`ipx_wrap_if_config`).

To allow transmission and reception of IPX traffic from and to the local
machine there is `ipx_wrap_mux`. This program, once started, can be utilized by
client programs to bind to IPX sockets and transmit IPX packets.

To propagate routes to real IPX hosts there is `ipx_wrap_ripd`. To advertise
services on the IPX internetwork there is `ipx_wrap_sapd`.

This most likely only works with a recent Linux kernel. Tested with Linux 6.15
and libbpf 1.4.6.

## Warning!

This is highly experimental and has only been sporadically tested against
NetWare 6.5. It will have bugs or exhibit unexpected behavior.

## BPF programs

There are two BPF programs for the TC hook. One for egress, one for ingress.
On egress IPv6 packets sent within the set prefix are changed into IPX packets.
On ingress IPX packets are changed into IPv6 packets with the source and
destination addresses within the set prefix.

### Interface Configuration

The node portion of the IPX addresses is expected to be derived from the
interface MAC address (EUI-64). The network portion is taken from bytes 5-8 of
the IPv6 address.

So to put an interface with MAC address `00:11:22:33:44:55` into IPX network
`0xdeadcafe`, you would assign it an address of the form `<32-bit prefix>:dead:cafe:0011:22ff:fe33:4455`.

### Neighbor Discovery

Neighbor solicitations sent by the configured interface will be intercepted,
modified into an appropriate neighbor advertisement and sent back to the
interface. This is possible because the MAC address is always part of the IPX
address.

### Packet Conversion

There are two ways packets are converted between IPX and IPv6. The first is
intended to carry arbitrary IPv6 traffic over IPX. Here both the source and
destination IPX socket numbers have a value of `(0xd6 << 8) | <next header>`.
The IPX packet type is `0x1f`. On ingress, if both socket numbers have `0xd6`
in their most significant bit and the packet type is `0x1f`, the IPX header is
directly translated into an IPv6 header and the payload of the IPX packet is
appended to that IPv6 header. On egress, any IPv6 packet that is not a UDP
packet with source and destination port equal to `213` has its IPv6 header
converted into an IPX header and its payload is appended to that IPX header.

The second way to convert packets is intended to allow for routing of native
IPX traffic. On ingress the entire IPX packet (header + payload) is wrapped in
an IPv6 UDP packet with source and destination port `213`. The IPv6 header is
populated with information from the IPX header. On egress, any IPv6 UDP packet
with source and destination port equal to `213` has the IPv6 and UDP headers
stripped out and the UDP payload is appended directly to the Ethernet header.

Note that the first approach takes up all socket numbers between `0xd600` and
`0xd6ff`. These are "well-known" sockets. Since this is not a NetWare
application and what is left of Novell is now owned by OpenText, I have not
contacted anybody to have these sockets reserved. So it is possible that they
clash with existing applications.

### Loading

Load with:
```
tc qdisc add dev <if> clsact
tc filter add dev <if> ingress bpf object-file ipx_wrap_kern.o section tc/ingress direct-action
tc filter add dev <if> egress bpf object-file ipx_wrap_kern.o section tc/egress direct-action
```

Make sure that all the offloading is disabled or else you might get broken
packets:
```
ethtool -K <if> tx off
ethtool -K <if> rx off
ethtool -K <if> generic-segmentation-offload off
ethtool -K <if> scatter-gather off
ethtool -K <if> tx-gso-list off
ethtool -K <if> tx-ipxip4-segmentation off
ethtool -K <if> tx-ipxip6-segmentation off
ethtool -K <if> tx-udp_tnl-segmentation off
ethtool -K <if> tx-udp_tnl-csum-segmentation off
```

Afterwards, you still need to set the prefix and the network number for the BPF
program (see `ipx_wrap_if_config`).

The `install.sh` script will do all three tasks for you.

```
Usage: install.sh <if> <if ipv6 addr>
```

As an alternative to using the `tc` system to load the BPF programs, there is
also `ipx_wrap_ifd`. This program takes the same arguments as the `install.sh`
script but instead starts a process that installs the BPF programs and
configures them (doing the jobs of the `tc` commands and `ipx_wrap_if_config`).
As long as the program is running, the BPF programs remain active. Once the
program is stopped, the BPF programs are unloaded. Note that when using
`ipx_wrap_ifd`, the you will have to disable offloading yourself as described
above.

## ipx_wrap_if_config

Sets a 4 byte prefix and the IPX network number for the BPF programs on one
interface. The second parameter is the IPv6 address of the interface. Prefix
and network number are extracted from the address.

Usage:
```
Usage: ipx_wrap_if_config <if> <if ipv6 addr>
```

## ipx_wrap_ifd

Loads and configures the BPF programs for one interface. As long as the program
is running, the BPF programs remain active. When the program is stopped, the
BPF programs are unloaded. The parameters and their meanings are the same as
for `ipx_wrap_if_config`.

It is crucial that this program is started _after_ `ipx_wrap_mux` for all
participating interfaces. This is necessary to ensure the correct order of BPF
programs.

Usage:
```
Usage: ipx_wrap_ifd <if> <if ipv6 addr>
```

## ipx_wrap_mux

This program offers a simple API that can be used to send and receive native
IPX packets (those wrapped in IPv6 and UDP, see above). The API is specified in
the file `ipx_wrap_mux_proto.h`.

The program will fork off a process for every interface within the specified
prefix. These sub-processes then communicate with client processes and allow
them to send and receive IPX traffic on a given IPX address.

The sockets returned from the API should only be written to and received from
using the functions of the API. However, the sockets are compatible with
`epoll` and similar interfaces.

Sending `SIGHUP` to the process will cause it to scan again for network
interfaces within the specified prefix.

Usage:
```
Usage: ipx_wrap_mux <32-bit hex prefix>
```

## ipx_wrap_ripd

Sends and receives routes on all interfaces within the specified prefix. It
will transmit all known routes within the prefix, except those that are routed
via the same interface it sends from. It will also learn routes it receives and
enter them into the main routing table.

This program depends on a running `ipx_wrap_mux`.

Sending `SIGHUP` to the process will cause it to scan again for network
interfaces within the specified prefix.

Usage:
```
Usage: ipx_wrap_ripd <32-bit hex prefix>
```

## ipx_wrap_sapd

Sends and receives service information using the Service Advertisement Protocol
(SAP). In addition to learning service information from other SAP servers, it
will also advertise the services configured in the configuration file. The
program will listen and send on all interfaces in the specified prefix.

Sending a `SIGUSR1` to the process will cause it to print all services it knows
about to `stdout` in the same format as the configuration file.

This program depends on a running `ipx_wrap_mux`.

Sending `SIGHUP` to the process will cause it to scan again for network
interfaces within the specified prefix.

Usage:
```
Usage: ipx_wrap_sapd <32-bit hex prefix> <cfg file>
```

Config File Format:
```
# IPX_addr                 hops type name
00000001.000000000001.0001 0000 0001 SRV01
00000002.000000000002.0002 0000 0002 SRV02
...
```

## ipxcat

This is a netcat-like program for sending and receiving IPX packets. Both plain
IPX and SPX are supported.

This program depends on a running `ipx_wrap_mux`.

Usage:
```
Usage: ipxcat [-v] [-d <maximum data bytes>] [-t <packet type>] <local IPX address> <remote IPX address>
       ipxcat [-v] -s [-d <maximum data bytes>] <local IPX address> <remote IPX address>
       ipxcat [-v] -l [-t <packet type>] [-b] <local IPX address>
       ipxcat [-v] -l -s [-d <maximum data bytes>] <local IPX address>
```

The IPX addresses are of the form `<4 byte hex network>.<6 byte hex node
number>.<2 byte hex socket>`. For example: `deadcafe.000000000001.f00f`. If the
socket number of the local IPX address is specified as zero, a random dynamic
socket will be chosen.

The `-l` flag puts the program in listening mode. In this mode IPX packets will
be received or SPX connections accepted. A program in listening mode cannot
send data unless it has accepted an SPX connection.

The `-s` flag instructs the program to use SPX. In listening mode, the program
will wait for an incoming SPX connection. Otherwise, it will attempt to connect
to the remote IPX address. As SPX always uses the packet type `0x05`, the `-t`
option is not allowed when using SPX.

The `-b` flag instructs a program in listening mode to also accept broadcast
packets. When not in listening mode or when using SPX this flag is not allowed.

The `-t` option can be used to specify a packet type when SPX is not in use
(`-s` is not present). If no packet type is specified, then a listening process
will accept any packet type while a sending process will use the packet type
`0x1e`.

The `-d` option specifies the maximum amount of bytes of data transmitted per
packet. For SPX this value must be between 1 and 534 (inclusive). For IPX this
value must be between 1 and 65497 (inclusive). There is no MTU measurement.
This means that it is up to the user to ensure packets are not too large to be
transmitted. The default for both IPX and SPX is 534 and is used if the option
is not specified.

The `-v` flag will cause the program to print more detailed information to
`stderr`.

## Acknowledgements

### uthash

The hash table implementation used throughout this project is `uthash` which
was developed by Troy D. Hanson and kindly provided under a [revised BSD
license](https://troydhanson.github.io/uthash/license.html).

The documentation for `uthash` is available
[here](https://troydhanson.github.io/uthash/).
