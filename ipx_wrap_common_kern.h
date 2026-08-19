#ifndef __IPX_WRAP_COMMON_KERN_H__
#define __IPX_WRAP_COMMON_KERN_H__

struct bpf_cb_mark_info {
	union {
		__u32 cb[5];
		struct {
			__u32 mark;
			struct spx_conn_key spx_conn_key;
			__u16 reinject_ctr;
		} __attribute__((packed));
	};
} __attribute__((packed));

_Static_assert(sizeof(struct bpf_cb_mark_info) == (sizeof(__u32) * 5),
		"bpf_cb_mark_info has invalid size");

#define SPX_TO_SCTP_REINJECT_MARK 0x47744703

#define SCTP_MAX_CHUNKSIZE 4096 // FIXME: this will do for our purposes but is
				// very ugly
#define SCTP_MAX_PKT_LEN (((MAX_DGRAM_LEN - (sizeof(struct ipv6hdr) + \
					sizeof(struct ethhdr))) / 4) * 4)
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

static __always_inline int parse_tcphdr(struct hdr_cursor *cur, void *data_end,
		struct tcphdr **tcphdr)
{
	struct tcphdr *tcph = cur->pos;

	if (tcph + 1 > data_end)
		return -1;

	int len = tcph->doff * 4;
	if(len < sizeof(*tcph))
		return -1;

	if (cur->pos + len > data_end)
		return -1;

	cur->pos += len;
	*tcphdr = tcph;

	return len;
}

static __always_inline int parse_sctphdr(struct hdr_cursor *cur, void
		*data_end, struct sctphdr **sctphdr)
{
	struct sctphdr *sctph = cur->pos;

	if (sctph + 1 > data_end)
		return -1;

	cur->pos = sctph + 1;
	*sctphdr = sctph;

	return sizeof(struct sctphdr);
}

static __always_inline int parse_sctp_chunk(struct hdr_cursor *cur, void
		*data_end, struct sctp_chunkhdr **sctp_chunkhdr)
{
	struct sctp_chunkhdr *sctp_chunkh = cur->pos;

	if (sctp_chunkh + 1 > data_end)
		return -1;

	size_t len = bpf_ntohs(sctp_chunkh->length);
	/* hack so that the verifier knows this value's bounds */
	asm volatile("%0 &= 0xffff" : "=r"(len) : "0"(len));
	if (len > SCTP_MAX_CHUNKSIZE)
		return -1;

	int padding_bytes = (len % 4 == 0) ? 0 : (4 - (len % 4));
	size_t actual_len = len + padding_bytes;
	if (len < sizeof(struct sctp_chunkhdr))
		return -1;

	if (cur->pos + actual_len > data_end)
		return -1;

	cur->pos += actual_len;
	*sctp_chunkhdr = sctp_chunkh;

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

static __always_inline __s64 csum_del(__be32 *data, __u32 len, __s64 csum_diff)
{
	__u32 len_mult_4 = (len / 4) * 4;
	csum_diff = bpf_csum_diff(data, len_mult_4, NULL, 0, csum_diff);
	if (csum_diff < 0) {
		return -1;
	}

	__be32 rest = 0;
	int i;
	for (i = 0; i < (len - len_mult_4); i++) {
		rest |= ((__be32) *((__u8 *) (((void*) data) + len_mult_4 +
						i))) << (i * 8);
	}
	csum_diff = bpf_csum_diff(&rest, sizeof(__be32), NULL, 0, csum_diff);
	if (csum_diff < 0) {
		return -1;
	}

	return csum_diff;
}

static __always_inline __s64 csum_add(__be32 *data, __u32 len, __s64 csum_diff)
{
	__u32 len_mult_4 = (len / 4) * 4;
	csum_diff = bpf_csum_diff(NULL, 0, data, len_mult_4, csum_diff);
	if (csum_diff < 0) {
		return -1;
	}

	__be32 rest = 0;
	int i;
	for (i = 0; i < (len - len_mult_4); i++) {
		rest |= ((__be32) *((__u8 *) (((void*) data) + len_mult_4 +
						i))) << (i * 8);
	}
	csum_diff = bpf_csum_diff(NULL, 0, &rest, sizeof(__be32), csum_diff);
	if (csum_diff < 0) {
		return -1;
	}

	return csum_diff;
}

static __always_inline __s64 csum_del_ipxhdr(struct ipxhdr *ipxh, __s64
		csum_diff)
{
	return csum_del((__be32 *) ipxh, sizeof(struct ipxhdr), csum_diff);
}

static __always_inline __s64 csum_add_ipxhdr(struct ipxhdr *ipxh, __s64
		csum_diff)
{
	return csum_add((__be32 *) ipxh, sizeof(struct ipxhdr), csum_diff);
}

static __always_inline __s64 csum_del_spxhdr(struct spxhdr *spxh, __s64
		csum_diff)
{
	return csum_del((__be32 *) spxh, sizeof(struct spxhdr), csum_diff);
}

static __always_inline __s64 csum_add_spxhdr(struct spxhdr *spxh, __s64
		csum_diff)
{
	return csum_add((__be32 *) spxh, sizeof(struct spxhdr), csum_diff);
}

#endif /* __IPX_WRAP_COMMON_KERN_H__ */
