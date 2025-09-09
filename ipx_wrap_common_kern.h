#ifndef __IPX_WRAP_COMMON_KERN_H__
#define __IPX_WRAP_COMMON_KERN_H__

#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_IPX 0x8137

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

	cur->pos = ipxh + 1;
	*ipxhdr = ipxh;

	return ipxh->type;
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

	if (cur.pos + min_len > data_end) {
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

#endif /* __IPX_WRAP_COMMON_KERN_H__ */
