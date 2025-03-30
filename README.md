# ipx_wrap

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

Currently the destination socket is used to encode the protocol number (UDP,
ICMPv6, TCP etc.).

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

## ipx_wrap_set_prefix

Sets a 4 byte prefix for the BPF programs.

Usage:
```
Usage: ipx_wrap_set_prefix <ipv6 /32 prefix>
```
