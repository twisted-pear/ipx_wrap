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

#endif /* __IPX_WRAP_COMMON_KERN_H__ */
