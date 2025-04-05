# ipx_wrap

The idea is that IPv6 packets that are sent are turned into IPX packets on the
wire and IPX packets that are received are turned into IPv6 packets that can be
routed by the IPv6 network stack.

To rewrite the packets there are two BPF programs. To configure them there is a
simple command-line utility (`ipx_wrap_if_config`). To propagate routes to real
IPX hosts there is `ipx_wrap_ripd`.

Most likely only works with a recent Linux kernel. Tested with 6.13.

## Warning!

This is highly experimental and has only been sporadically tested against
NetWare 6.5. It will have bugs or exhibit unexpected behavior.

## BPF programs

There are two BPF programs for the TC hook. One for egress, one for ingress.
On egress IPv6 packets sent within the set prefix are changed into IPX packets.
On ingress IPX packets are changed into IPv6 packets with the set prefix for
source and destination address.

The node portion of the IPX addresses is expected to be derived from the
interface MAC address (EUI-64). The network portion is taken from bytes 5-8 of
the IPv6 address.

So to put an interface with MAC address `00:11:22:33:44:55` into IPX network
`0xdeadcafe`, you would assign it an address of the form `<32-bit prefix>:dead:cafe:0011:22ff:fe33:4455`.

Neighbor solicitations sent by the configured interface will be intercepted,
modified into an appropriate neighbor advertisement and sent back to the
interface. This is possible because the MAC address is always part of the IPX
address.

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

The `install.sh` script will do both for you.
You still need to set the prefix and network! See below.

## ipx_wrap_if_config

Sets a 4 byte prefix and the IPX network number for the BPF programs on one
interface.

Usage:
```
Usage: ipx_wrap_if_config <if> <ipv6 /32 prefix>-<ipx net hex>
```

So for a prefix of `fdaa:bbbb` and the network `0xdeadcafe` you would call:
```
./ipx_wrap_if_config <if> fdaa:bbbb-deadcafe
```

## ipx_wrap_ripd

Sends and receives routes on the given interface. It will transmit all known
routes within the prefix, except those that are routed via the same interface
it sends from. It will also learn routes it receives and enter them into the
main routing table.

Usage:
```
Usage: ipx_wrap_ripd <if> <bind ipv6 addr>
```

The second parameter is the address assigned to the interface (which is the
first parameter).
