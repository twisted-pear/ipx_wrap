/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_ALEN 6
#define ETH_P_IPV6 0x86DD
#define ETH_P_IPX 0x8137
#define IPPROTO_ICMPV6 58
#define ICMPV6_ND_SOL 135
#define ICMPV6_ND_ADV 136
#define ICMPV6_OPT_SRC_LLADDR 1
#define ICMPV6_OPT_TGT_LLADDR 2

/* IPv6 extension headers */
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ESP 50
#define IPPROTO_AH 51
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60
#define IPPROTO_MH 135
#define IPPROTO_HOSTID 139
#define IPPROTO_SHIM6 140
#define MAX_EXT_HEADERS 9

#define IPV6_PREFIX_LEN 4
/* according to Novell docs this is the type for "NetBIOS and other propagated
 * packets" */
#define IPX_PKT_TYPE 0x14
/* Socket numbers between 0x4000 and 0x7FFF are dynamic sockets */
#define IPX_DST_SOCK_BASE 0x4700
#define IPX_SRC_SOCK_BASE 0x7400
#define IPX_TO_IPV6_REINJECT_MARK 0xdead4774

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ipx_wrap_prefix SEC(".maps");

struct ext_hdr_def {
	__u8 nexthdr;
	__u8 hdrlen; /* Length of the header in 8-octet units, not including
			the first 8 octets. */
	__be16 unspec1;
	__be32 unspec2;
} __attribute__((packed));

struct ext_hdr_frag {
	__u8 nexthdr;
	__u8 unspec1;
	__be16 unspec2;
	__be32 unspec3;
} __attribute__((packed));

struct ext_hdr_ah {
	__u8 nexthdr;
	__u8 ahlen; /* This 8-bit field specifies the length of AH in 32-bit
		       words (4-byte units), minus "2". For IPv6, the total
		       length of the header must be a multiple of 8-octet
		       units. */
	__be16 reserved;
	__be32 spi;
	__be32 seq;
	__be32 unspec1;
} __attribute__((packed));

struct icmpv6_nd {
	/* the reserved bits are already part of the ICMPv6 header struct */
	struct in6_addr tgt_addr;
} __attribute__((packed));

struct icmpv6_nd_opt {
	__u8 type;
	__u8 length;
	__be16 unspec1;
	__be32 unspec2;
} __attribute__((packed));

struct icmpv6_opt_lladdr_eth {
	__u8 type;
	__u8 length;
	unsigned char lladdr_eth[ETH_ALEN];
} __attribute__((packed));

struct ipx_addr {
	__be32 net;
	__u8 node[6];
	__be16 sock;
} __attribute__((packed));

struct ipxhdr {
	__be16 csum;
	__be16 pktlen;
	__u8 tc;
	__u8 type;
	struct ipx_addr daddr;
	struct ipx_addr saddr;
} __attribute__((packed));

struct ipv6_eui64_addr {
	__u8 prefix[IPV6_PREFIX_LEN];
	__be32 ipx_net;
	__u8 ipx_node_fst[3];
	__be16 fffe;
	__u8 ipx_node_snd[3];
} __attribute__((packed));

struct hdr_cursor {
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *cur, void *data_end, struct
		ethhdr **ethhdr)
{
	struct ethhdr *eth = cur->pos;
	if (eth + 1 > data_end)
		return -1;

	cur->pos = eth + 1;
	*ethhdr = eth;

	return eth->h_proto;
}

static __always_inline int skip_ext_headers(struct hdr_cursor *cur, void
		*data_end, __u8 nexthdr, bool *can_mangle)
{
	struct ext_hdr_def *normalh;
	struct ext_hdr_frag *fragh;
	struct ext_hdr_ah *ah;
	void *hdrend;
	size_t hdrlen;

	*can_mangle = true;

	int i;
	for (i = 0; i < MAX_EXT_HEADERS; i++) {
		switch (nexthdr) {
			/* regular headers */
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
			case IPPROTO_MH:
			case IPPROTO_HOSTID:
			case IPPROTO_SHIM6:
				normalh = cur->pos;
				if (normalh + 1 > data_end) {
					return -1;
				}

				hdrend = ((void *)(normalh + 1)) +
					(normalh->hdrlen * 8);
				if (hdrend > data_end) {
					return -1;
				}

				cur->pos = hdrend;
				nexthdr = normalh->nexthdr;
				break;

			/* fragment header */
			case IPPROTO_FRAGMENT:
				fragh = cur->pos;
				if (fragh + 1 > data_end) {
					return -1;
				}

				cur->pos = fragh + 1;
				nexthdr = fragh->nexthdr;
				break;

			/* AH is extra */
			case IPPROTO_AH:
				ah = cur->pos;
				if (ah + 1 > data_end) {
					return -1;
				}

				hdrlen = (ah->ahlen + 2) * 4;
				if (hdrlen % 8 != 0) {
					return -1;
				}

				hdrend = ((void *) ah) + hdrlen;
				if (hdrend > data_end) {
					return -1;
				}

				cur->pos = hdrend;
				nexthdr = ah->nexthdr;

				/* further processing cannot change the packet,
				 * because it is authenticated */
				*can_mangle = false;
				break;

			/* None, ESP, or some L4 proto */
			case IPPROTO_ESP:
			case IPPROTO_NONE:
			default:
				return nexthdr;
		}
	}

	/* too many headers, give up */
	return nexthdr;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *cur, void *data_end,
		struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = cur->pos;
	if (ip6h + 1 > data_end)
		return -1;

	cur->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int parse_ipxhdr(struct hdr_cursor *cur, void *data_end,
		struct ipxhdr **ipxhdr)
{
	struct ipxhdr *ipxh = cur->pos;

	if (ipxh + 1 > data_end) {
		return -1;
	}

	int pktsize = (__u16) bpf_ntohs(ipxh->pktlen);
	asm volatile("%0 &= 0xffff" : "=r"(pktsize) : "0"(pktsize));
	if (pktsize < sizeof(*ipxh)) {
		return -1;
	}

	if (cur->pos + pktsize > data_end) {
		return -1;
	}

	cur->pos = ipxh + 1;
	*ipxhdr = ipxh;

	return ipxh->type;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *cur, void
		*data_end, struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6h = cur->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	/* This is incorrect. The actual length of the header depends on type
	 * and code. Since we are only interested in whether or not this is a
	 * neighbor advertisment it's fine though. */
	cur->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

SEC("tc/ingress")
int ipx_wrap_in(struct __sk_buff *ctx)
{
	/* packet was already processed and reinjected, just accept */
	if (ctx->cb[0] == IPX_TO_IPV6_REINJECT_MARK) {
		return TC_ACT_OK;
	}

	__u32 key = 0;
	__u32 *prefix = bpf_map_lookup_elem(&ipx_wrap_prefix, &key);
	if (prefix == NULL) {
		return TC_ACT_SHOT;
	}

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor cur;
	cur.pos = data;

	struct ethhdr *eth;
	if (parse_ethhdr(&cur, data_end, &eth) < 0) {
		bpf_printk("ethparse fail");
		return TC_ACT_SHOT;
	}
	if (bpf_ntohs(eth->h_proto) != ETH_P_IPX) {
		bpf_printk("no ipx");
		return TC_ACT_SHOT;
	}

	struct ipxhdr *ipxh;
	if (parse_ipxhdr(&cur, data_end, &ipxh) < 0) {
		bpf_printk("ipxparse fail");
		return TC_ACT_SHOT;
	}

	/* TODO: handle extension headers */

	/* build new IPv6 header */
	struct ipv6hdr newhdr;
	newhdr.version = 6;
	newhdr.priority = 0;
	newhdr.flow_lbl[0] = 0;
	newhdr.flow_lbl[1] = 0;
	newhdr.flow_lbl[2] = 0;
	newhdr.payload_len = bpf_htons(bpf_ntohs(ipxh->pktlen) - sizeof(struct
				ipxhdr));
	newhdr.nexthdr = bpf_ntohs(ipxh->daddr.sock) & 0xff;
	newhdr.hop_limit = 255; // TODO: calculate IPv6 hop limit from TC

	struct ipv6_eui64_addr *saddr6 = (void *) &newhdr.saddr;
	struct ipv6_eui64_addr *daddr6 = (void *) &newhdr.daddr;

	__builtin_memcpy(saddr6->prefix, prefix, sizeof(saddr6->prefix));
	saddr6->ipx_net = ipxh->saddr.net;
	__builtin_memcpy(saddr6->ipx_node_fst, ipxh->saddr.node,
			sizeof(saddr6->ipx_node_fst));
	saddr6->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(saddr6->ipx_node_snd, ipxh->saddr.node +
			sizeof(saddr6->ipx_node_fst),
			sizeof(saddr6->ipx_node_snd));

	__builtin_memcpy(daddr6->prefix, prefix, sizeof(daddr6->prefix));
	daddr6->ipx_net = ipxh->daddr.net;
	__builtin_memcpy(daddr6->ipx_node_fst, ipxh->daddr.node,
			sizeof(daddr6->ipx_node_fst));
	daddr6->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(daddr6->ipx_node_snd, ipxh->daddr.node +
			sizeof(daddr6->ipx_node_fst),
			sizeof(daddr6->ipx_node_snd));

	eth->h_proto = bpf_htons(ETH_P_IPV6);

	bpf_printk("preinstall");

	/* install new IPv6 header */

	__s32 hlen_diff = sizeof(struct ipv6hdr) - sizeof(struct ipxhdr); // 10
	if (bpf_skb_change_head(ctx, hlen_diff, 0) < 0) {
		bpf_printk("failinstall");
		return TC_ACT_SHOT;
	}

	bpf_skb_pull_data(ctx, 0);
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	if (data + hlen_diff + sizeof(struct ethhdr) > data_end) {
		bpf_printk("no data");
		return TC_ACT_SHOT;
	}
	__builtin_memmove(data, data + hlen_diff, sizeof(struct ethhdr));

	cur.pos = data;
	if (parse_ethhdr(&cur, data_end, &eth) < 0) {
		bpf_printk("ethparse2 fail");
		return TC_ACT_SHOT;
	}
	if (cur.pos + sizeof(struct ipv6hdr) > data_end) {
		bpf_printk("no room");
		return TC_ACT_SHOT;
	}

	__builtin_memcpy(cur.pos, &newhdr, sizeof(newhdr));
	bpf_printk("postinstall");

	/* mark and reinject the packet to trick the network stack */
	ctx->cb[0] = IPX_TO_IPV6_REINJECT_MARK;
	return bpf_redirect(ctx->ingress_ifindex, BPF_F_INGRESS);
}

SEC("tc/egress")
int ipx_wrap_out(struct __sk_buff *ctx)
{
	/*__u8 key = 0;
	__u8 *rec = bpf_map_lookup_elem(&ipx_wrap_prefix, &key);
	if (rec == NULL) {
		return TC_ACT_SHOT;
	}*/

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor cur;
	cur.pos = data;

	struct ethhdr *eth;
	if (parse_ethhdr(&cur, data_end, &eth) < 0) {
		bpf_printk("ethparse fail");
		return TC_ACT_SHOT;
	}
	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6) {
		bpf_printk("no ipv6");
		return TC_ACT_SHOT;
	}

	struct ipv6hdr *ip6h;
	if (parse_ip6hdr(&cur, data_end, &ip6h) < 0) {
		bpf_printk("ipv6parse fail");
		return TC_ACT_SHOT;
	}

	/* TODO: handle extension headers */

	/* build new IPX header */
	struct ipxhdr newhdr;
	newhdr.csum = 0xFFFF;
	newhdr.pktlen = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(struct
				ipxhdr));
	newhdr.tc = 0; // TODO: calculate TC from IPv6 hop limit
	newhdr.type = IPX_PKT_TYPE;

	struct ipv6_eui64_addr *daddr6 = (void *) &ip6h->daddr;
	struct ipv6_eui64_addr *saddr6 = (void *) &ip6h->saddr;

	newhdr.daddr.net = daddr6->ipx_net;
	__builtin_memcpy(&newhdr.daddr.node, daddr6->ipx_node_fst,
			sizeof(newhdr.daddr.node) / 2);
	__builtin_memcpy(((__u8 *) &newhdr.daddr.node) +
			(sizeof(newhdr.daddr.node) / 2), daddr6->ipx_node_snd,
			sizeof(newhdr.daddr.node) / 2);
	newhdr.daddr.sock = bpf_htons(IPX_DST_SOCK_BASE | ip6h->nexthdr);

	newhdr.saddr.net = saddr6->ipx_net;
	__builtin_memcpy(&newhdr.saddr.node, saddr6->ipx_node_fst,
			sizeof(newhdr.saddr.node) / 2);
	__builtin_memcpy(((__u8 *) &newhdr.saddr.node) +
			(sizeof(newhdr.saddr.node) / 2), saddr6->ipx_node_snd,
			sizeof(newhdr.saddr.node) / 2);
	newhdr.saddr.sock = bpf_htons(IPX_DST_SOCK_BASE | ip6h->nexthdr);

	eth->h_proto = bpf_htons(ETH_P_IPX);

	bpf_printk("preinstall");
	/* install new IPX header */
	__s32 hlen_diff = sizeof(struct ipv6hdr) - sizeof(struct ipxhdr); // 10
	__builtin_memcpy(((void *)ip6h) + hlen_diff, &newhdr, sizeof(newhdr));
	if (bpf_skb_adjust_room(ctx, -hlen_diff, BPF_ADJ_ROOM_MAC, 0) < 0) {
		bpf_printk("failinstall");
		return TC_ACT_SHOT;
	}
	bpf_printk("postinstall");

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
