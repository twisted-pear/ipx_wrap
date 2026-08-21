/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "ipx_wrap_common_kern.h"
#include "ipx_wrap_common_proto.h"

#define AF_INET6 10

#define SPX_SOCKETS_MAX	32768

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define SCTP_STATE_COOKIE_LEN 4
#define SCTP_RWND_DUMMY 1500

#define SCTP_HEAD_REINJECT_MARK 0x47744704
#define SCTP_MAX_CHUNKS 16

_Static_assert(SCTP_MAX_HEARTBEAT_CHUNK_LEN > sizeof(struct sctp_chunkhdr),
		"SCTP_MAX_HEARTBEAT_CHUNK_LEN too small");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct spx_conn_key);
	__type(value, struct bpf_kspx_state);
	__uint(max_entries, SPX_SOCKETS_MAX);
} ipx_wrap_mux_kspx_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__type(key, __u32);
	__type(value, struct spx_conn_key);
	__uint(max_entries, 0);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipx_wrap_mux_kspx_sock_key SEC(".maps");

/* CRC code copied from RFC 9260, Appendix A */
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])

__u32 crc_c[256] = {
	0x00000000UL, 0xF26B8303UL, 0xE13B70F7UL, 0x1350F3F4UL,
	0xC79A971FUL, 0x35F1141CUL, 0x26A1E7E8UL, 0xD4CA64EBUL,
	0x8AD958CFUL, 0x78B2DBCCUL, 0x6BE22838UL, 0x9989AB3BUL,
	0x4D43CFD0UL, 0xBF284CD3UL, 0xAC78BF27UL, 0x5E133C24UL,
	0x105EC76FUL, 0xE235446CUL, 0xF165B798UL, 0x030E349BUL,
	0xD7C45070UL, 0x25AFD373UL, 0x36FF2087UL, 0xC494A384UL,
	0x9A879FA0UL, 0x68EC1CA3UL, 0x7BBCEF57UL, 0x89D76C54UL,
	0x5D1D08BFUL, 0xAF768BBCUL, 0xBC267848UL, 0x4E4DFB4BUL,
	0x20BD8EDEUL, 0xD2D60DDDUL, 0xC186FE29UL, 0x33ED7D2AUL,
	0xE72719C1UL, 0x154C9AC2UL, 0x061C6936UL, 0xF477EA35UL,
	0xAA64D611UL, 0x580F5512UL, 0x4B5FA6E6UL, 0xB93425E5UL,
	0x6DFE410EUL, 0x9F95C20DUL, 0x8CC531F9UL, 0x7EAEB2FAUL,
	0x30E349B1UL, 0xC288CAB2UL, 0xD1D83946UL, 0x23B3BA45UL,
	0xF779DEAEUL, 0x05125DADUL, 0x1642AE59UL, 0xE4292D5AUL,
	0xBA3A117EUL, 0x4851927DUL, 0x5B016189UL, 0xA96AE28AUL,
	0x7DA08661UL, 0x8FCB0562UL, 0x9C9BF696UL, 0x6EF07595UL,
	0x417B1DBCUL, 0xB3109EBFUL, 0xA0406D4BUL, 0x522BEE48UL,
	0x86E18AA3UL, 0x748A09A0UL, 0x67DAFA54UL, 0x95B17957UL,
	0xCBA24573UL, 0x39C9C670UL, 0x2A993584UL, 0xD8F2B687UL,
	0x0C38D26CUL, 0xFE53516FUL, 0xED03A29BUL, 0x1F682198UL,
	0x5125DAD3UL, 0xA34E59D0UL, 0xB01EAA24UL, 0x42752927UL,
	0x96BF4DCCUL, 0x64D4CECFUL, 0x77843D3BUL, 0x85EFBE38UL,
	0xDBFC821CUL, 0x2997011FUL, 0x3AC7F2EBUL, 0xC8AC71E8UL,
	0x1C661503UL, 0xEE0D9600UL, 0xFD5D65F4UL, 0x0F36E6F7UL,
	0x61C69362UL, 0x93AD1061UL, 0x80FDE395UL, 0x72966096UL,
	0xA65C047DUL, 0x5437877EUL, 0x4767748AUL, 0xB50CF789UL,
	0xEB1FCBADUL, 0x197448AEUL, 0x0A24BB5AUL, 0xF84F3859UL,
	0x2C855CB2UL, 0xDEEEDFB1UL, 0xCDBE2C45UL, 0x3FD5AF46UL,
	0x7198540DUL, 0x83F3D70EUL, 0x90A324FAUL, 0x62C8A7F9UL,
	0xB602C312UL, 0x44694011UL, 0x5739B3E5UL, 0xA55230E6UL,
	0xFB410CC2UL, 0x092A8FC1UL, 0x1A7A7C35UL, 0xE811FF36UL,
	0x3CDB9BDDUL, 0xCEB018DEUL, 0xDDE0EB2AUL, 0x2F8B6829UL,
	0x82F63B78UL, 0x709DB87BUL, 0x63CD4B8FUL, 0x91A6C88CUL,
	0x456CAC67UL, 0xB7072F64UL, 0xA457DC90UL, 0x563C5F93UL,
	0x082F63B7UL, 0xFA44E0B4UL, 0xE9141340UL, 0x1B7F9043UL,
	0xCFB5F4A8UL, 0x3DDE77ABUL, 0x2E8E845FUL, 0xDCE5075CUL,
	0x92A8FC17UL, 0x60C37F14UL, 0x73938CE0UL, 0x81F80FE3UL,
	0x55326B08UL, 0xA759E80BUL, 0xB4091BFFUL, 0x466298FCUL,
	0x1871A4D8UL, 0xEA1A27DBUL, 0xF94AD42FUL, 0x0B21572CUL,
	0xDFEB33C7UL, 0x2D80B0C4UL, 0x3ED04330UL, 0xCCBBC033UL,
	0xA24BB5A6UL, 0x502036A5UL, 0x4370C551UL, 0xB11B4652UL,
	0x65D122B9UL, 0x97BAA1BAUL, 0x84EA524EUL, 0x7681D14DUL,
	0x2892ED69UL, 0xDAF96E6AUL, 0xC9A99D9EUL, 0x3BC21E9DUL,
	0xEF087A76UL, 0x1D63F975UL, 0x0E330A81UL, 0xFC588982UL,
	0xB21572C9UL, 0x407EF1CAUL, 0x532E023EUL, 0xA145813DUL,
	0x758FE5D6UL, 0x87E466D5UL, 0x94B49521UL, 0x66DF1622UL,
	0x38CC2A06UL, 0xCAA7A905UL, 0xD9F75AF1UL, 0x2B9CD9F2UL,
	0xFF56BD19UL, 0x0D3D3E1AUL, 0x1E6DCDEEUL, 0xEC064EEDUL,
	0xC38D26C4UL, 0x31E6A5C7UL, 0x22B65633UL, 0xD0DDD530UL,
	0x0417B1DBUL, 0xF67C32D8UL, 0xE52CC12CUL, 0x1747422FUL,
	0x49547E0BUL, 0xBB3FFD08UL, 0xA86F0EFCUL, 0x5A048DFFUL,
	0x8ECEE914UL, 0x7CA56A17UL, 0x6FF599E3UL, 0x9D9E1AE0UL,
	0xD3D3E1ABUL, 0x21B862A8UL, 0x32E8915CUL, 0xC083125FUL,
	0x144976B4UL, 0xE622F5B7UL, 0xF5720643UL, 0x07198540UL,
	0x590AB964UL, 0xAB613A67UL, 0xB831C993UL, 0x4A5A4A90UL,
	0x9E902E7BUL, 0x6CFBAD78UL, 0x7FAB5E8CUL, 0x8DC0DD8FUL,
	0xE330A81AUL, 0x115B2B19UL, 0x020BD8EDUL, 0xF0605BEEUL,
	0x24AA3F05UL, 0xD6C1BC06UL, 0xC5914FF2UL, 0x37FACCF1UL,
	0x69E9F0D5UL, 0x9B8273D6UL, 0x88D28022UL, 0x7AB90321UL,
	0xAE7367CAUL, 0x5C18E4C9UL, 0x4F48173DUL, 0xBD23943EUL,
	0xF36E6F75UL, 0x0105EC76UL, 0x12551F82UL, 0xE03E9C81UL,
	0x34F4F86AUL, 0xC69F7B69UL, 0xD5CF889DUL, 0x27A40B9EUL,
	0x79B737BAUL, 0x8BDCB4B9UL, 0x988C474DUL, 0x6AE7C44EUL,
	0xBE2DA0A5UL, 0x4C4623A6UL, 0x5F16D052UL, 0xAD7D5351UL,
};

struct sctp_csum_loopctx {
	__u8 *data_start;
	const void *data_end;
	size_t payload_len;
	__u32 crc32;
};

static long sctp_csum_loopfn(__u64 index, void *ctx)
{
	struct sctp_csum_loopctx *c = ctx;
	if (index >= c->payload_len) {
		return 1;
	}

	__u8 *current_byte = c->data_start + index;

	if (current_byte + 1 > c->data_end) {
		return 1;
	}

	CRC32C(c->crc32, *current_byte);

	return 0;
}

static bool sctp_csum_calc(const struct sctphdr *sctph, void *data_end, size_t
		payload_len, __u32 *csum)
{
	struct sctp_csum_loopctx ctx = {
		.data_start = (__u8 *) sctph,
		.data_end = data_end,
		.payload_len = payload_len,
		.crc32 =  0xffffffffUL
	};

	long nloops = bpf_loop(payload_len, &sctp_csum_loopfn, &ctx, 0);
	if (nloops != payload_len) {
		return false;
	}

	__u32 result = ~(ctx.crc32);
	__u32 byte0 = result & 0xff;
	__u32 byte1 = (result>>8) & 0xff;
	__u32 byte2 = (result>>16) & 0xff;
	__u32 byte3 = (result>>24) & 0xff;
	*csum = ((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);
	return true;
}

static __always_inline bool get_ingress_pointers(struct __sk_buff *skb, struct
		ethhdr **eth, struct ipv6hdr **ip6h, struct udphdr **udph,
		struct ipxhdr **ipxh, struct spxhdr **spxh, void **data_end)
{
	*data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	*eth = data;
	*ip6h = (void *) (*eth + 1);
	*udph = (void *) (*ip6h + 1);
	*ipxh = (void *) (*udph + 1);
	*spxh = (void *) (*ipxh + 1);

	if (*spxh + 1 > *data_end) {
		return false;
	}

	return true;
}

static __always_inline bool get_egress_pointers(struct __sk_buff *skb, struct
		ethhdr **eth, struct ipv6hdr **ip6h, struct sctphdr **sctph,
		struct sctp_chunkhdr **chunk1, struct sctp_chunkhdr **chunk2,
		void **data_end)
{
	*data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	*eth = data;
	*ip6h = (void *) (*eth + 1);
	*sctph = (void *) (*ip6h + 1);

	struct hdr_cursor cur = {
		.pos = *sctph + 1
	};

	/* at least one chunk is required */
	if (parse_sctp_chunk(&cur, *data_end, chunk1) < 0) {
		return false;
	}

	*chunk2 = NULL;
	parse_sctp_chunk(&cur, *data_end, chunk2);

	return true;
}

static __always_inline bool is_reinjected(struct __sk_buff *skb)
{
	__u32 cb_mark = ((struct bpf_cb_mark_info *) &(skb->cb[0]))->mark;
	return (cb_mark == SCTP_HEAD_REINJECT_MARK);
}

static __always_inline void mark_reinjected(struct __sk_buff *skb, const struct
		spx_conn_key *conn_key)
{
	struct bpf_cb_mark_info cbi;
	cbi.cb[0] = skb->cb[0];
	cbi.cb[1] = skb->cb[1];
	cbi.cb[2] = skb->cb[2];
	cbi.cb[3] = skb->cb[3];
	cbi.cb[4] = skb->cb[4];

	cbi.mark = SCTP_HEAD_REINJECT_MARK;
	cbi.spx_conn_key.bind_addr = conn_key->bind_addr;
	cbi.spx_conn_key.conn_id = conn_key->conn_id;

	skb->cb[0] = cbi.cb[0];
	skb->cb[1] = cbi.cb[1];
	skb->cb[2] = cbi.cb[2];
	skb->cb[3] = cbi.cb[3];
	skb->cb[4] = cbi.cb[4];
}

static __always_inline bool flatten_sctp(struct __sk_buff *skb, struct
		spx_conn_key *conn_key)
{
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct sctphdr *sctph;
	struct sctp_chunkhdr *chunk1;
	struct sctp_chunkhdr *chunk2;
	void *data_end;
	if (!get_egress_pointers(skb, &eth, &ip6h, &sctph, &chunk1, &chunk2,
				&data_end)) {
		return false;
	}

	/* only have one chunk, nothing to do */
	if (chunk2 == NULL) {
		return true;
	}

	/* packet was already copied and reinjected, delete all but the first
	 * chunk */
	if (is_reinjected(skb)) {
		size_t tail_len = data_end - ((void *) chunk2);
		size_t payload_len = bpf_ntohs(ip6h->payload_len) - tail_len;
		ip6h->payload_len = bpf_htons(payload_len);
		if (bpf_skb_change_tail(skb, skb->len - tail_len, 0) < 0) {
			return false;
		}
		return true;
	}

	/* we have a new multi-chunk packet */

	/* mark it for reinjection */
	mark_reinjected(skb, conn_key);

	/* save away the SCTP header */
	struct sctphdr sctph_backup;
	__builtin_memcpy(&sctph_backup, sctph, sizeof(struct sctphdr));

	/* for every chunk but the last one, we reinject the packet and then
	 * remove the first chunk */
	int i;
	for (i = 0; i < SCTP_MAX_CHUNKS && chunk2 != NULL; i++) {
		size_t payload_len = bpf_ntohs(ip6h->payload_len);
		__s32 len_diff = ((void *) chunk2) - ((void *) chunk1);

		/* clone the full packet, the code above will cut away
		 * everything but the first chunk */
		if (bpf_clone_redirect(skb, skb->ifindex, 0) != 0) {
			return false;
		}

		/* remove the first chunk */
		if (bpf_skb_adjust_room(skb, -len_diff, BPF_ADJ_ROOM_NET, 0) <
				0) {
			return false;
		}

		/* restore our pointers */
		bpf_skb_pull_data(skb, 0);
		if (!get_egress_pointers(skb, &eth, &ip6h, &sctph, &chunk1,
					&chunk2, &data_end)) {
			return false;
		}

		/* restore the SCTP header */
		__builtin_memcpy(sctph, &sctph_backup, sizeof(struct sctphdr));

		/* adjust the payload length */
		ip6h->payload_len = bpf_htons(payload_len - len_diff);
	}

	return true;
}

static __always_inline bool fill_conn_key(struct __sk_buff *skb, struct
		spx_conn_key *conn_key)
{
	struct bpf_cb_mark_info cbi;
	cbi.cb[0] = skb->cb[0];
	cbi.cb[1] = skb->cb[1];
	cbi.cb[2] = skb->cb[2];
	cbi.cb[3] = skb->cb[3];
	cbi.cb[4] = skb->cb[4];

	/* Check if this is the tail end of an already handled SCTP packet. In
	 * this case the socket association is lost and we need to look up the
	 * connection key from the CB */
	if (cbi.mark == SCTP_HEAD_REINJECT_MARK) {
		*conn_key = cbi.spx_conn_key;
		return true;
	}

	struct bpf_sock *client_sock = skb->sk;
	if (client_sock == NULL) {
		return false;
	}

	struct spx_conn_key *sock_conn_key = bpf_sk_storage_get(
			&ipx_wrap_mux_kspx_sock_key, client_sock, NULL, 0);
	if (sock_conn_key == NULL) {
		return false;
	}

	*conn_key = *sock_conn_key;
	return true;
}

#include "ipx_wrap_mux_spx_states.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, enum kspx_connection_state);
	__uint(max_entries, KSPX_MAX);
	__array(values, __u32 (void *));
} kspx_states_ingress SEC(".maps") = {
	.values = {
		[KSPX_INVALID] = (void *) &kspx_state_ingress_INVALID,
		[KSPX_NEW] = (void *) &kspx_state_ingress_NEW,
		[KSPX_ESTABLISHED] = (void *) &kspx_state_ingress_ESTABLISHED,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, enum kspx_connection_state);
	__uint(max_entries, KSPX_MAX);
	__array(values, __u32 (void *));
} kspx_states_egress SEC(".maps") = {
	.values = {
		[KSPX_INVALID] = (void *) &kspx_state_egress_INVALID,
		[KSPX_NEW] = (void *) &kspx_state_egress_NEW,
		[KSPX_ESTABLISHED] = (void *) &kspx_state_egress_ESTABLISHED,
	},
};

SEC("tc/ingress")
int ipx_wrap_spx_demux(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct hdr_cursor cur;
	cur.pos = data;

	/* TODO: intercept SCTP packets to one of our managed sockets */

	/* we are only interested in SPX packets */
	struct ethhdr *eth;
	if (parse_ethhdr(&cur, data_end, &eth) < 0) {
		return TC_ACT_UNSPEC;
	}
	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6) {
		return TC_ACT_UNSPEC;
	}

	struct ipv6hdr *ip6h;
	if (parse_ip6hdr(&cur, data_end, &ip6h) < 0) {
		return TC_ACT_UNSPEC;
	}
	if (ip6h->nexthdr != IPPROTO_UDP) {
		return TC_ACT_UNSPEC;
	}

	struct udphdr *udph;
	if (parse_udphdr(&cur, data_end, &udph) < 0) {
		return TC_ACT_UNSPEC;
	}
	if (!is_ipx_in_ipv6(ip6h, data_end)) {
		return TC_ACT_UNSPEC;
	}

	struct ipxhdr *ipxh;
	if (parse_ipxhdr(&cur, data_end, &ipxh) < 0) {
		return TC_ACT_UNSPEC;
	}

	if (ipxh->type != SPX_PKT_TYPE) {
		return TC_ACT_UNSPEC;
	}
	if (cur.pos + sizeof(struct spxhdr) > data_end) {
		return TC_ACT_UNSPEC;
	}
	if (bpf_ntohs(ipxh->pktlen) - sizeof(struct ipxhdr) < sizeof(struct
				spxhdr)) {
		return TC_ACT_UNSPEC;
	}
	struct spxhdr *spxh = cur.pos;

	/* determine if the packet is for the local machine */
	struct bpf_fib_lookup fib_params;
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = AF_INET6;
	__builtin_memcpy(fib_params.ipv6_dst, &(ip6h->daddr),
			sizeof(fib_params.ipv6_dst));
	__builtin_memcpy(fib_params.ipv6_src, &(ip6h->saddr),
			sizeof(fib_params.ipv6_src));
	fib_params.l4_protocol = IPPROTO_UDP;
	fib_params.sport = bpf_htons(IPX_IN_IPV6_PORT);
	fib_params.dport = bpf_htons(IPX_IN_IPV6_PORT);
	fib_params.ifindex = skb->ingress_ifindex;
	long fib_res = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params),
			BPF_FIB_LOOKUP_SKIP_NEIGH);
	if (fib_res != BPF_FIB_LKUP_RET_NOT_FWDED) {
		/* not for us */
		return TC_ACT_UNSPEC;
	}

	struct spx_conn_key conn_key = {
		.bind_addr = ipxh->daddr,
		.conn_id = spxh->dst_conn_id
	};
	struct bpf_kspx_state *spx_state = bpf_map_lookup_elem(
			&ipx_wrap_mux_kspx_state, &conn_key);
	if (spx_state == NULL) {
		return TC_ACT_UNSPEC;
	}

	bpf_tail_call(skb, &kspx_states_ingress, spx_state->state);

	bpf_printk("no ingress state program found");
	return TC_ACT_SHOT;
}

SEC("tc/egress")
int ipx_wrap_spx_mux(struct __sk_buff *skb)
{
	struct spx_conn_key conn_key;
	if (!fill_conn_key(skb, &conn_key)) {
		return TC_ACT_UNSPEC;
	}

	struct bpf_kspx_state *spx_state = bpf_map_lookup_elem(
			&ipx_wrap_mux_kspx_state, &conn_key);
	if (spx_state == NULL) {
		/* SPX connection is already closed, the conn_key is stale */
		return TC_ACT_SHOT;
	}

	bpf_printk("Got packet for kernel SPX conn %02x",
			bpf_ntohs(spx_state->local_id));

	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct hdr_cursor cur;
	cur.pos = data;

	/* we are only interested in TCP packets, the socket should not emit
	 * anything else */
	struct ethhdr *eth;
	if (parse_ethhdr(&cur, data_end, &eth) < 0) {
		return TC_ACT_SHOT;
	}
	/* packet already is a proper IPX packet, just allow it through */
	if (bpf_ntohs(eth->h_proto) == ETH_P_IPX) {
		return TC_ACT_UNSPEC;
	}
	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6) {
		return TC_ACT_SHOT;
	}

	struct ipv6hdr *ip6h;
	if (parse_ip6hdr(&cur, data_end, &ip6h) < 0) {
		return TC_ACT_SHOT;
	}
	if (ip6h->nexthdr != IPPROTO_SCTP) {
		return TC_ACT_UNSPEC;
	}

	struct sctphdr *sctph;
	if (parse_sctphdr(&cur, data_end, &sctph) < 0) {
		return TC_ACT_SHOT;
	}

	/* there should be at least one SCTP chunk, parse it */
	struct sctp_chunkhdr *chunk1;
	if (parse_sctp_chunk(&cur, data_end, &chunk1) < 0) {
		return TC_ACT_SHOT;
	}

	/* also see if there happen to be more chunks */
	struct sctp_chunkhdr *chunk2 = NULL;
	parse_sctp_chunk(&cur, data_end, &chunk2);
	if (!flatten_sctp(skb, &conn_key)) {
		return TC_ACT_SHOT;
	}

	/* we can only deal with one chunk at a time, hence we split up
	 * multi-chunk SCTP packets */
	bpf_tail_call(skb, &kspx_states_egress, spx_state->state);

	bpf_printk("no egress state program found");
	return TC_ACT_SHOT;
}

SEC("socket")
int ipx_wrap_spx_kcm(struct __sk_buff *skb)
{
	bpf_printk("kcm: %d bytes", skb->len);
	return skb->len;
}

char _license[] SEC("license") = "GPL";
