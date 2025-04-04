/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IFINDEX_MAX 64

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_IPX 0x8137
#define IPPROTO_ICMPV6 58
#define ICMPV6_ND_SOL 135
#define ICMPV6_ND_ADV 136
#define ICMPV6_OPT_SRC_LLADDR 1
#define ICMPV6_OPT_TGT_LLADDR 2

#define IPV6_IN_IPX_PKT_TYPE 0x1F
#define IPV6_IN_IPX_SOCK_BASE 0xD600

#define IPX_IN_IPV6_PORT 213

/* based on the maximum IPX TC when using RIP */
#define IPV6_HOP_LIMIT_MAX 16
#define IPX_TC_MAX 16

#define IPX_MAX_PKTLEN (65535-17) /* should be 65535 but this is the largest
				     value I got past the verifier */

#define IPX_TO_IPV6_REINJECT_MARK 0xdead4774

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct if_config {
	__be32 prefix;
	__be32 network;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct if_config);
	__uint(max_entries, IFINDEX_MAX);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ipx_wrap_if_config SEC(".maps");

struct icmpv6_nd {
	/* the reserved bits are already part of the ICMPv6 header struct */
	struct in6_addr tgt_addr;
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
	__be32 prefix;
	__be32 ipx_net;
	__u8 ipx_node_fst[3];
	__be16 fffe;
	__u8 ipx_node_snd[3];
} __attribute__((packed));

struct ipv6_and_udphdr {
	struct ipv6hdr ip6h;
	struct udphdr udph;
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
	/* hack so that the verifier knows this value's bounds */
	asm volatile("%0 &= 0xffff" : "=r"(pktsize) : "0"(pktsize));

	if (pktsize < sizeof(*ipxh)) {
		return -1;
	}

	if (pktsize > IPX_MAX_PKTLEN) {
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

static __always_inline int parse_udphdr(struct hdr_cursor *cur, void *data_end,
		struct udphdr **udphdr)
{
	struct udphdr *udph = cur->pos;

	if (udph + 1 > data_end)
		return -1;

	cur->pos = udph + 1;
	*udphdr = udph;

	int len = bpf_ntohs(udph->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

static __always_inline int mk_nd_adv(struct __sk_buff *ctx, struct ethhdr *eth,
		struct ipv6hdr *ip6h, struct icmp6hdr *icmp6h)
{
	void *data_end = (void *)(long)ctx->data_end;

	/* check that we have a full ND packet */
	struct icmpv6_nd *nd = (void *)(icmp6h + 1);
	if (nd + 1 > data_end) {
		return -1;
	}

	/* check that we have a src lladdr option */
	struct icmpv6_opt_lladdr_eth *opt_lladdr = (void *) (nd + 1);
	if (opt_lladdr + 1 > data_end) {
		return -1;
	}
	if (opt_lladdr->type != ICMPV6_OPT_SRC_LLADDR) {
		return -1;
	}
	if (opt_lladdr->length != 1) {
		return -1;
	}

	/* overwrite dst MAC with solicitation's src MAC */
	__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);

	/* create src MAC from target addr */
	struct ipv6_eui64_addr *tgt_addr = (void *) &nd->tgt_addr;
	__builtin_memcpy(eth->h_source, tgt_addr->ipx_node_fst,
			sizeof(tgt_addr->ipx_node_fst));
	__builtin_memcpy(eth->h_source + sizeof(tgt_addr->ipx_node_fst),
			tgt_addr->ipx_node_snd,
			sizeof(tgt_addr->ipx_node_snd));

	/* back up original IPv6 addrs */
	struct __attribute__((packed)) {
		struct in6_addr src;
		struct in6_addr dst;
	} ip6addr_orig;
	__builtin_memcpy(&ip6addr_orig, &ip6h->saddr, sizeof(ip6addr_orig));

	/* set dst IP from src IP */
	__builtin_memcpy(&ip6h->daddr, &ip6h->saddr, sizeof(ip6h->daddr));

	/* set source IP from tgt_IP, retain the link-local address part */
	__builtin_memcpy(((__u8 *) &ip6h->saddr) + 8, ((__u8 *) tgt_addr) + 8,
			sizeof(ip6h->saddr) / 2);

	/* calculate checksum update */
	__s64 csum_diff = bpf_csum_diff((__be32 *) &ip6addr_orig,
			sizeof(ip6addr_orig), (__be32 *) &ip6h->saddr,
			sizeof(ip6addr_orig), 0);
	if (csum_diff < 0) {
		return -1;
	}

	/* back up original lladdr option */
	struct icmpv6_opt_lladdr_eth opt_lladdr_orig;
	__builtin_memcpy(&opt_lladdr_orig, opt_lladdr,
			sizeof(opt_lladdr_orig));

	/* change src lladdr opt to tgt lladdr opt */
	opt_lladdr->type = ICMPV6_OPT_TGT_LLADDR;

	/* change src lladdr to tgt lladdr */
	__builtin_memcpy(opt_lladdr->lladdr_eth, tgt_addr->ipx_node_fst,
			sizeof(tgt_addr->ipx_node_fst));
	__builtin_memcpy(opt_lladdr->lladdr_eth +
			sizeof(tgt_addr->ipx_node_fst), tgt_addr->ipx_node_snd,
			sizeof(tgt_addr->ipx_node_snd));

	/* calculate checksum update */
	csum_diff = bpf_csum_diff((__be32 *) &opt_lladdr_orig,
			sizeof(opt_lladdr_orig), (__be32 *) opt_lladdr,
			sizeof(opt_lladdr_orig), csum_diff);
	if (csum_diff < 0) {
		return -1;
	}

	/* original flags in ND sol (has no flags) */
	__be32 nothing = 0;

	/* set flags for ND adv */
	icmp6h->icmp6_dataun.u_nd_advt.override = 1;
	icmp6h->icmp6_dataun.u_nd_advt.solicited = 1;

	/* calculate checksum update */
	csum_diff = bpf_csum_diff(&nothing, sizeof(nothing), (__be32 *)
			&icmp6h->icmp6_dataun.u_nd_advt, sizeof(nothing),
			csum_diff);
	if (csum_diff < 0) {
		return -1;
	}

	/* change ICMP type to ND adv */
	icmp6h->icmp6_type = ICMPV6_ND_ADV;

	/* update the checksum in the ICMPv6 header */
	__u32 csum_offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) +
		offsetof(struct icmp6hdr, icmp6_cksum);
	if (bpf_l4_csum_replace(ctx, csum_offset, 0, csum_diff,
				BPF_F_PSEUDO_HDR) < 0) {
		return -1;
	}

	/* update the checksum again for the ICMPv6 type */
	if (bpf_l4_csum_replace(ctx, csum_offset, ICMPV6_ND_SOL, ICMPV6_ND_ADV,
				2 | BPF_F_PSEUDO_HDR) < 0) {
		return -1;
	}

	return 0;
}

static __always_inline bool is_nd_sol(struct ipv6hdr *ip6h, void *data_end,
		struct icmp6hdr **icmp6h)
{
	struct hdr_cursor cur;
	cur.pos = ip6h + 1;

	if (parse_icmp6hdr(&cur, data_end, icmp6h) < 0) {
		return false;
	}

	if ((*icmp6h)->icmp6_type != ICMPV6_ND_SOL) {
		return false;
	}

	if ((*icmp6h)->icmp6_code != 0) {
		return false;
	}

	return true;
}

static __always_inline void fill_ipv6_from_ipx_basic(struct ipxhdr *ipxh, __u32
		prefix, struct ipv6hdr *newhdr)
{
	/* obtain basic information from the IPX header and store it in the new
	 * IPv6 header */
	newhdr->version = 6;
	newhdr->priority = 0;
	newhdr->flow_lbl[0] = 0;
	newhdr->flow_lbl[1] = 0;
	newhdr->flow_lbl[2] = 0;
	newhdr->hop_limit = (ipxh->tc > IPX_TC_MAX) ? 0 : IPX_TC_MAX -
		ipxh->tc;

	struct ipv6_eui64_addr *saddr6 = (void *) &newhdr->saddr;
	struct ipv6_eui64_addr *daddr6 = (void *) &newhdr->daddr;

	saddr6->prefix = prefix;
	saddr6->ipx_net = ipxh->saddr.net;
	__builtin_memcpy(saddr6->ipx_node_fst, ipxh->saddr.node,
			sizeof(saddr6->ipx_node_fst));
	saddr6->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(saddr6->ipx_node_snd, ipxh->saddr.node +
			sizeof(saddr6->ipx_node_fst),
			sizeof(saddr6->ipx_node_snd));

	daddr6->prefix = prefix;
	daddr6->ipx_net = ipxh->daddr.net;
	__builtin_memcpy(daddr6->ipx_node_fst, ipxh->daddr.node,
			sizeof(daddr6->ipx_node_fst));
	daddr6->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(daddr6->ipx_node_snd, ipxh->daddr.node +
			sizeof(daddr6->ipx_node_fst),
			sizeof(daddr6->ipx_node_snd));
}

static __always_inline size_t mk_ipv6_from_ipx(struct ipxhdr *ipxh, __u32
		prefix, struct ipv6hdr *newhdr)
{
	/* build new IPv6 header */
	fill_ipv6_from_ipx_basic(ipxh, prefix, newhdr);

	newhdr->payload_len = bpf_htons(bpf_ntohs(ipxh->pktlen) - sizeof(struct
				ipxhdr));
	newhdr->nexthdr = bpf_ntohs(ipxh->daddr.sock) & 0xFF;

	return sizeof(struct ipv6hdr);
}

struct calc_ipx_in_ipv6_csum_loopctx {
	__u8 *dataptr;
	__s32 diff;
	size_t payload_len;
	void *data_end;
};

static long calc_ipx_in_ipv6_csum_loopfn(__u64 index, void* ctx)
{
	struct calc_ipx_in_ipv6_csum_loopctx *c = ctx;

	if (index > IPX_MAX_PKTLEN / 4) {
		c->diff = -1;
		return 1;
	}

	if ((index * 4) + 4 > c->payload_len) {
		return 1;
	}
	if (c->dataptr + (index * 4) + 4 > c->data_end) {
		c->diff = -1;
		return 1;
	}

	c->diff = bpf_csum_diff(NULL, 0, (__be32 *) (c->dataptr + (index * 4)),
			4, c->diff);

	return 0;
}

static __always_inline __wsum calc_ipx_in_ipv6_csum(struct ipxhdr *ipxh, struct
		ipv6hdr *ip6h, struct udphdr *udph, void *data_end)
{
	/* pseudo header */
	__s64 diff = bpf_csum_diff(NULL, 0, (__be32*) &ip6h->saddr,
			sizeof(ip6h->saddr), 0);
	diff = bpf_csum_diff(NULL, 0, (__be32 *) &ip6h->daddr,
			sizeof(ip6h->daddr), diff);
	__be32 pktlen = bpf_htonl(bpf_ntohs(udph->len) & 0x0000FFFF);
	diff = bpf_csum_diff(NULL, 0, &pktlen, sizeof(pktlen), diff);
	__be32 nexthdr = bpf_htonl(IPPROTO_UDP & 0x000000FF);
	diff = bpf_csum_diff(NULL, 0, &nexthdr, sizeof(nexthdr), diff);

	/* UDP header */
	udph->check = 0;
	diff = bpf_csum_diff(NULL, 0, (__be32 *) udph, sizeof(udph), diff);

	/* payload */
	size_t payload_len = (__u16) bpf_ntohs(ipxh->pktlen);
	/* hack so that the verifier knows this value's bounds */
	asm volatile("%0 &= 0xffff" : "=r"(payload_len) : "0"(payload_len));

	if (payload_len > IPX_MAX_PKTLEN) {
		return 0;
	}

	struct calc_ipx_in_ipv6_csum_loopctx lctx = {
		.dataptr = (__u8 *) ipxh,
		.diff = diff,
		.payload_len = payload_len,
		.data_end = data_end
	};

	long nloops = bpf_loop(IPX_MAX_PKTLEN / 4,
			&calc_ipx_in_ipv6_csum_loopfn, &lctx, 0);
	if (nloops < 0 || nloops > (IPX_MAX_PKTLEN / 4) || lctx.diff < 0) {
		return 0;
	}

	__be32 rest = 0;
	lctx.dataptr += (lctx.payload_len / 4) * 4;
	lctx.payload_len -= (lctx.payload_len / 4) * 4;
	int i;
	for (i = 0; i < 4; i++) {
		if (i + 1 > lctx.payload_len) {
			break;
		}
		if (lctx.dataptr + i + 1 > lctx.data_end) {
			return 0;
		}

		*(((__u8 *) &rest) + i) = *(lctx.dataptr + i);
	}
	diff = bpf_csum_diff(NULL, 0, &rest, 4, lctx.diff);

	return ~diff;
}

static __always_inline size_t pack_ipx_in_ipv6(struct ipxhdr *ipxh, __u32
		prefix, struct ipv6_and_udphdr *newhdr, void *data_end)
{
	/* increase TC here as it is not constructed from the IPv6 hop limit on
	 * egress */
	ipxh->tc++;

	/* build new IPv6 and UDP headers */
	fill_ipv6_from_ipx_basic(ipxh, prefix, &newhdr->ip6h);

	newhdr->ip6h.payload_len = bpf_htons(bpf_ntohs(ipxh->pktlen) +
			sizeof(struct udphdr));
	newhdr->ip6h.nexthdr = IPPROTO_UDP;

	newhdr->udph.source = bpf_htons(IPX_IN_IPV6_PORT);
	newhdr->udph.dest = bpf_htons(IPX_IN_IPV6_PORT);
	newhdr->udph.len = bpf_htons(bpf_ntohs(ipxh->pktlen) + sizeof(struct
				udphdr));

	/* fill the UDP checksum */
	newhdr->udph.check = calc_ipx_in_ipv6_csum(ipxh, &newhdr->ip6h,
			&newhdr->udph, data_end);

	return sizeof(struct ipv6_and_udphdr);
}

static __always_inline size_t mk_ipx_from_ipv6(struct ipv6hdr *ip6h, struct
		ipxhdr *newhdr)
{
	struct ipv6_eui64_addr *daddr6 = (void *) &ip6h->daddr;
	struct ipv6_eui64_addr *saddr6 = (void *) &ip6h->saddr;

	/* build new IPX header */
	newhdr->csum = 0xFFFF;
	newhdr->pktlen = bpf_htons(bpf_ntohs(ip6h->payload_len) + sizeof(struct
				ipxhdr));
	newhdr->tc = (ip6h->hop_limit > IPV6_HOP_LIMIT_MAX) ? 0 :
		IPV6_HOP_LIMIT_MAX - ip6h->hop_limit;
	newhdr->type = IPV6_IN_IPX_PKT_TYPE;

	newhdr->daddr.net = daddr6->ipx_net;
	__builtin_memcpy(&newhdr->daddr.node, daddr6->ipx_node_fst,
			sizeof(newhdr->daddr.node) / 2);
	__builtin_memcpy(((__u8 *) &newhdr->daddr.node) +
			(sizeof(newhdr->daddr.node) / 2), daddr6->ipx_node_snd,
			sizeof(newhdr->daddr.node) / 2);
	newhdr->daddr.sock = bpf_htons(IPV6_IN_IPX_SOCK_BASE | ip6h->nexthdr);

	newhdr->saddr.net = saddr6->ipx_net;
	__builtin_memcpy(&newhdr->saddr.node, saddr6->ipx_node_fst,
			sizeof(newhdr->saddr.node) / 2);
	__builtin_memcpy(((__u8 *) &newhdr->saddr.node) +
			(sizeof(newhdr->saddr.node) / 2), saddr6->ipx_node_snd,
			sizeof(newhdr->saddr.node) / 2);
	newhdr->saddr.sock = bpf_htons(IPV6_IN_IPX_SOCK_BASE | ip6h->nexthdr);

	return sizeof(struct ipxhdr);
}

static __always_inline size_t unpack_ipx_in_ipv6(void)
{
	return 0;
}

static __always_inline bool is_ipv6_in_ipx(struct ipxhdr *ipxh)
{
	if (ipxh->type != IPV6_IN_IPX_PKT_TYPE) {
		return false;
	}

	if ((bpf_ntohs(ipxh->daddr.sock) & 0xFF00) != IPV6_IN_IPX_SOCK_BASE) {
		return false;
	}
	if ((bpf_ntohs(ipxh->saddr.sock) & 0xFF00) != IPV6_IN_IPX_SOCK_BASE) {
		return false;
	}

	return true;
}

static __always_inline bool is_ipx_in_ipv6(struct ipv6hdr *ip6h, void
		*data_end)
{
	if (ip6h->nexthdr != IPPROTO_UDP) {
		return false;
	}

	size_t len = bpf_ntohs(ip6h->payload_len);
	/* hack so that the verifier knows this value's bounds */
	asm volatile("%0 &= 0xffff" : "=r"(len) : "0"(len));

	size_t min_len = sizeof(struct udphdr) + sizeof(struct ipxhdr);
	if (len < min_len) {
		return false;
	}

	struct hdr_cursor cur;
	cur.pos = ip6h + 1;

	if (cur.pos + len > data_end) {
		return false;
	}

	struct udphdr *udph;
	if (parse_udphdr(&cur, data_end, &udph) < 0) {
		return false;
	}

	if (bpf_ntohs(udph->len) != len) {
		return false;
	}

	if (bpf_ntohs(udph->source) != IPX_IN_IPV6_PORT ||
			bpf_ntohs(udph->dest) != IPX_IN_IPV6_PORT)
	{
		return false;
	}

	return true;
}

SEC("tc/ingress")
int ipx_wrap_in(struct __sk_buff *ctx)
{
	/* packet was already processed and reinjected, just accept */
	if (ctx->cb[0] == IPX_TO_IPV6_REINJECT_MARK) {
		return TC_ACT_OK;
	}

	__u32 ifidx = ctx->ingress_ifindex;
	if (ifidx == 0) {
		return TC_ACT_SHOT;
	}

	struct if_config *ifcfg = bpf_map_lookup_elem(&ipx_wrap_if_config,
			&ifidx);
	if (ifcfg == NULL) {
		return TC_ACT_SHOT;
	}

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor cur;
	cur.pos = data;

	struct ethhdr *eth;
	if (parse_ethhdr(&cur, data_end, &eth) < 0) {
		return TC_ACT_SHOT;
	}
	if (bpf_ntohs(eth->h_proto) != ETH_P_IPX) {
		return TC_ACT_SHOT;
	}

	struct ipxhdr *ipxh;
	if (parse_ipxhdr(&cur, data_end, &ipxh) < 0) {
		return TC_ACT_SHOT;
	}

	size_t oldhdr_size;
	size_t newhdr_size;
	struct ipv6_and_udphdr newhdr;
	if (is_ipv6_in_ipx(ipxh)) {
		oldhdr_size = sizeof(struct ipxhdr);
		newhdr_size = mk_ipv6_from_ipx(ipxh, ifcfg->prefix,
				&newhdr.ip6h);
	} else {
		oldhdr_size = 0;
		newhdr_size = pack_ipx_in_ipv6(ipxh, ifcfg->prefix, &newhdr,
				data_end);
	}

	/* install new IPv6 header */
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	__s32 hlen_diff = newhdr_size - oldhdr_size;
	if (bpf_skb_change_head(ctx, hlen_diff, 0) < 0) {
		return TC_ACT_SHOT;
	}

	bpf_skb_pull_data(ctx, 0);
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	if (data + hlen_diff + sizeof(struct ethhdr) > data_end) {
		return TC_ACT_SHOT;
	}
	__builtin_memmove(data, data + hlen_diff, sizeof(struct ethhdr));

	cur.pos = data;
	if (parse_ethhdr(&cur, data_end, &eth) < 0) {
		return TC_ACT_SHOT;
	}
	if (cur.pos + newhdr_size > data_end) {
		return TC_ACT_SHOT;
	}

	/* the compiler cannot handle using newhdr_size directly */
	if (newhdr_size == sizeof(struct ipv6hdr)) {
		__builtin_memcpy(cur.pos, &newhdr, sizeof(struct ipv6hdr));
	} else if (newhdr_size == sizeof(struct ipv6_and_udphdr)) {
		__builtin_memcpy(cur.pos, &newhdr, sizeof(struct
					ipv6_and_udphdr));
	} else {
		return TC_ACT_SHOT;
	}

	/* mark and reinject the packet to trick the network stack */
	ctx->cb[0] = IPX_TO_IPV6_REINJECT_MARK;
	return bpf_redirect(ctx->ingress_ifindex, BPF_F_INGRESS);
}

SEC("tc/egress")
int ipx_wrap_out(struct __sk_buff *ctx)
{
	__u32 ifidx = ctx->ifindex;
	if (ifidx == 0) {
		return TC_ACT_SHOT;
	}

	struct if_config *ifcfg = bpf_map_lookup_elem(&ipx_wrap_if_config,
			&ifidx);
	if (ifcfg == NULL) {
		return TC_ACT_SHOT;
	}

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor cur;
	cur.pos = data;

	struct ethhdr *eth;
	if (parse_ethhdr(&cur, data_end, &eth) < 0) {
		return TC_ACT_SHOT;
	}
	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6) {
		return TC_ACT_SHOT;
	}

	struct ipv6hdr *ip6h;
	if (parse_ip6hdr(&cur, data_end, &ip6h) < 0) {
		return TC_ACT_SHOT;
	}

	if (ip6h->nexthdr == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6h;
		/* check for neighbor solicitations */
		if (is_nd_sol(ip6h, data_end, &icmp6h)) {
			/* rewrite the packet into a neighbor advertisement */
			if (mk_nd_adv(ctx, eth, ip6h, icmp6h) < 0) {
				return TC_ACT_SHOT;
			}

			/* reinject the packet on ingress */
			ctx->cb[0] = IPX_TO_IPV6_REINJECT_MARK;
			return bpf_redirect(ctx->ifindex, BPF_F_INGRESS);
		}
	}

	struct ipv6_eui64_addr *daddr6 = (void *) &ip6h->daddr;
	struct ipv6_eui64_addr *saddr6 = (void *) &ip6h->saddr;

	/* discard packets from another prefix */
	if (daddr6->prefix != ifcfg->prefix || saddr6->prefix != ifcfg->prefix)
	{
		return TC_ACT_SHOT;
	}

	size_t oldhdr_size;
	size_t newhdr_size;
	struct ipxhdr newhdr;
	if (is_ipx_in_ipv6(ip6h, data_end)) {
		oldhdr_size = sizeof(struct iphdr) + sizeof(struct udphdr);
		newhdr_size = unpack_ipx_in_ipv6();
	} else {
		oldhdr_size = sizeof(struct iphdr);
		newhdr_size = mk_ipx_from_ipv6(ip6h, &newhdr);
	}

	/* install new IPX header */
	eth->h_proto = bpf_htons(ETH_P_IPX);

	/* linux won't allow us to make the packet shorter than the protocol
	 * (IPv4 or IPv6) header, so we first convert to IPv4 so that we can
	 * send smaller packets */
	if (bpf_skb_change_proto(ctx, bpf_htons(ETH_P_IP), 0) < 0) {
		return TC_ACT_SHOT;
	}
	__s32 hlen_diff = (newhdr_size - oldhdr_size);

	/* adjust packet room so that an IPX header fits, instead of an IPv4
	 * header */
	if (bpf_skb_adjust_room(ctx, hlen_diff, BPF_ADJ_ROOM_MAC, 0) < 0) {
		return TC_ACT_SHOT;
	}

	bpf_skb_pull_data(ctx, 0);
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	/* actually copy the IPX header */
	void *newhdr_start = data + sizeof(struct ethhdr);
	if (newhdr_start + newhdr_size > data_end) {
		return TC_ACT_SHOT;
	}
	if (newhdr_size == sizeof(struct ipxhdr)) {
		__builtin_memcpy(newhdr_start, &newhdr, sizeof(struct ipxhdr));
	} else if (newhdr_size == 0) {
		// do nothing
	} else {
		return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
