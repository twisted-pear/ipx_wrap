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

// TODO: implement locking for this data structure!
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
		//[KSPX_NEW] = (void *) &kspx_state_egress_NEW,
		//[KSPX_ESTABLISHED] = (void *) &kspx_state_egress_ESTABLISHED,
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

	bpf_printk("no state program found");
	return TC_ACT_SHOT;
}

static __always_inline bool check_for_chunk_type(__u8 chunk_type, const struct
		sctp_chunkhdr *chunk1, const struct sctp_chunkhdr *chunk2)
{
	if (chunk1->type == chunk_type) {
		return true;
	}

	if (chunk2 != NULL) {
		if (chunk2->type == chunk_type) {
			return true;
		}
	}

	return false;
}

static __always_inline bool check_sctp_msg_egress(const struct bpf_kspx_state
		*spx_state, const struct sctphdr *sctph, const struct
		sctp_chunkhdr *chunk1, const struct sctp_chunkhdr *chunk2)
{
	switch (spx_state->state) {
		case KSPX_NEW:
			/* once we have received a connection ack, a cookie
			 * echo is expected/allowed */
			if (chunk1->type == SCTP_CID_COOKIE_ECHO && chunk2 ==
					NULL) {
				break;
			}

			/* otherwise only an init chunk is allowed for new
			 * connections */
			if (chunk1->type != SCTP_CID_INIT || chunk2 != NULL) {
				return false;
			}

			return true;
		case KSPX_ESTABLISHED:
			break;
		default:
			return false;
	}

	if (sctph->source != spx_state->sctp_dport || sctph->dest !=
			spx_state->sctp_sport) {
		return false;
	}
	if (sctph->vtag != spx_state->sctp_svtag) {
		return false;
	}

	if (check_for_chunk_type(SCTP_CID_ERROR, chunk1, chunk2)) {
		bpf_printk("warn: error chunk");
		return false;
	}
	if (check_for_chunk_type(SCTP_CID_ABORT, chunk1, chunk2)) {
		bpf_printk("warn: abort chunk");
		return false;
	}

	/* this is not allowed */
	if (chunk1->type == SCTP_CID_DATA && chunk2 != NULL && chunk2->type !=
			SCTP_CID_DATA) {
		bpf_printk("warn: chunks after data");
		return false;
	}

	return true;
}

static __always_inline bool get_init(const struct sctp_chunkhdr *chunk1, void
		*data_end, bool *have_init, __be32 *initial_vtag, __u32
		*initial_tsn)
{
	*have_init = false;

	if (chunk1->type != SCTP_CID_INIT) {
		return true;
	}
	if (bpf_ntohs(chunk1->length) < sizeof(struct sctp_chunkhdr) +
			sizeof(struct sctp_inithdr)) {
		return true;
	}

	const struct sctp_inithdr *inith = (const struct sctp_inithdr *)
		(chunk1 + 1);
	if (inith + 1 > data_end) {
		return false;
	}

	*initial_vtag = inith->init_tag;
	*initial_tsn = bpf_ntohl(inith->initial_tsn);
	*have_init = true;
	return true;
}

static __always_inline bool get_cookie_echo(const struct sctp_chunkhdr *chunk1,
		void *data_end, bool *have_cookie_echo)
{
	*have_cookie_echo = false;
	if (chunk1->type != SCTP_CID_COOKIE_ECHO) {
		return true;
	}

	if (bpf_ntohs(chunk1->length) < sizeof(struct sctp_chunkhdr) +
			SCTP_STATE_COOKIE_LEN) {
		return true;
	}

	const __u8 *cookie = (const __u8 *) (chunk1 + 1);
	if (cookie + SCTP_STATE_COOKIE_LEN > data_end) {
		return false;
	}

	/* we don't check the actual cookie value, since we do not care */
	*have_cookie_echo = true;
	return true;
}

static __always_inline bool get_ack_tsn(const struct sctp_chunkhdr *chunk1,
		void *data_end, bool *have_ack_tsn, __u32 *ack_tsn)
{
	*have_ack_tsn = false;

	if (chunk1->type != SCTP_CID_SACK) {
		return true;
	}
	if (bpf_ntohs(chunk1->length) < sizeof(struct sctp_chunkhdr) +
			sizeof(struct sctp_sackhdr)) {
		return true;
	}

	const struct sctp_sackhdr *sackh = (const struct sctp_sackhdr
			*) (chunk1 + 1);
	if (sackh + 1 > data_end) {
		return false;
	}

	*ack_tsn = bpf_ntohl(sackh->cum_tsn_ack);
	*have_ack_tsn = true;
	return true;
}

static __always_inline bool get_data(const struct sctphdr *sctph, const struct
		sctp_chunkhdr *chunk1, void *data_end, size_t *data_ofs, size_t
		*data_len, size_t *padding_bytes)
{
	*data_ofs = 0;
	*data_len = 0;
	*padding_bytes = 0;

	/* we only handle data in the first chunk, mark the entire SCTP header
	 * for deletion */
	if (chunk1->type != SCTP_CID_DATA) {
		*data_ofs = data_end - ((void *) sctph);
		return true;
	}

	/* we have data */
	const struct sctp_datahdr *data = (const struct sctp_datahdr *) (chunk1
			+ 1);
	if (data + 1 > data_end) {
		return false;
	}
	bpf_printk("sending tsn: %u", bpf_ntohl(data->tsn));

	size_t data_overhead = sizeof(struct sctp_chunkhdr) + sizeof(struct
			sctp_datahdr);
	size_t chunk_len = bpf_ntohs(chunk1->length);
	*data_ofs = (((void *) chunk1) - ((void *) sctph)) + data_overhead;
	void *first_data_end = ((void *) chunk1) + chunk_len;
	*data_len = chunk_len - data_overhead;
	*padding_bytes = data_end - first_data_end;

	return true;
}

static __always_inline void update_spx_state_egress(struct bpf_kspx_state
		*spx_state, const struct sctphdr *sctph, __u32 tsn_ack, size_t
		data_len, __be32 initial_vtag, __u32 initial_tsn, bool
		have_cookie_echo)
{
	if (have_cookie_echo) {
		spx_state->state = KSPX_ESTABLISHED;
		return;
	}

	if (spx_state->state == KSPX_NEW) {
		spx_state->sctp_dvtag = initial_vtag;
		spx_state->sctp_svtag = bpf_get_prandom_u32();
		spx_state->sctp_sport = sctph->dest;
		spx_state->sctp_dport = sctph->source;
		__builtin_sub_overflow(initial_tsn, 1,
				&(spx_state->sctp_tsn_ack));
		return;
	}

	/* last message has been acknowledged by SCTP */
	if (spx_state->sctp_tsn == tsn_ack) {
		__builtin_add_overflow(spx_state->remote_expected_sequence, 1,
				&(spx_state->remote_expected_sequence));
		__builtin_add_overflow(spx_state->local_alloc_no, 1,
				&(spx_state->local_alloc_no));
		__builtin_add_overflow(spx_state->sctp_tsn, 1,
				&(spx_state->sctp_tsn));
		bpf_printk("reseq now %d", spx_state->remote_expected_sequence);
	}

	/* we have data */
	if (data_len != 0) {
		spx_state->last_sent_msg_data_len = data_len;
	}
}

static __always_inline void get_spx_packet_info_egress(struct bpf_kspx_state
		*spx_state, size_t data_len, __u8 *connection_control, __u8
		*datastream_type)
{
	*connection_control = 0;
	*datastream_type = 0;

	if (spx_state->state == KSPX_NEW) {
		*connection_control = SPX_CC_SYSTEM_PKT | SPX_CC_ACK_REQUIRED;
		return;
	}

	if (data_len == 0) {
		*connection_control |= SPX_CC_SYSTEM_PKT;
	} else {
		*connection_control |= SPX_CC_ACK_REQUIRED;
	}
}

SEC("tc/egress")
int ipx_wrap_spx_mux(struct __sk_buff *skb)
{
	struct bpf_sock *client_sock = skb->sk;
	if (client_sock == NULL) {
		return TC_ACT_UNSPEC;
	}

	struct spx_conn_key *conn_key = bpf_sk_storage_get(
			&ipx_wrap_mux_kspx_sock_key, client_sock, NULL, 0);
	if (conn_key == NULL) {
		return TC_ACT_UNSPEC;
	}

	struct bpf_kspx_state *spx_state = bpf_map_lookup_elem(
			&ipx_wrap_mux_kspx_state, conn_key);
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

	bpf_tail_call(skb, &kspx_states_egress, spx_state->state);

	/* try to parse a second chunk */
	struct sctp_chunkhdr *chunk2 = NULL;
	if (parse_sctp_chunk(&cur, data_end, &chunk2) >= 0) {
		bpf_printk("have second chunk");
	}

	bpf_printk("chunk1: %d", chunk1->type);
	if (chunk2 != NULL) {
		bpf_printk("chunk2: %d", chunk2->type);
	}

	if (!check_sctp_msg_egress(spx_state, sctph, chunk1, chunk2)) {
		bpf_printk("shot: SCTP msg check");
		return TC_ACT_SHOT;
	}

	bool have_init = false;
	__be32 initial_vtag = spx_state->sctp_dvtag;
	__u32 initial_tsn = spx_state->sctp_tsn_ack;
	if (!get_init(chunk1, data_end, &have_init, &initial_vtag,
				&initial_tsn)) {
		return TC_ACT_SHOT;
	}

	bool have_cookie_echo = false;
	if (!get_cookie_echo(chunk1, data_end, &have_cookie_echo)) {
		return TC_ACT_SHOT;
	}

	bool have_ack_tsn = false;
	__u32 ack_tsn;
	__builtin_sub_overflow(spx_state->sctp_tsn, 1, &ack_tsn);
	if (!get_ack_tsn(chunk1, data_end, &have_ack_tsn, &ack_tsn)) {
		return TC_ACT_SHOT;
	}

	size_t data_ofs = 0;
	size_t data_len = 0;
	size_t padding_bytes = 0;
	if (!get_data(sctph, chunk1, data_end, &data_ofs, &data_len,
				&padding_bytes)) {
		return TC_ACT_SHOT;
	}

	bpf_printk("data len: %u, data_ofs: %u, padding: %u", data_len,
			data_ofs, padding_bytes);

	update_spx_state_egress(spx_state, sctph, ack_tsn, data_len,
			initial_vtag, initial_tsn, have_cookie_echo);

	if (have_cookie_echo) {
		/* reflect the packet as a cookie ack */
		bpf_printk("reflecting cookie echo");

		/* swap Ethernet addrs */
		__u8 eth_dest_backup[ETH_ALEN];
		__builtin_memcpy(eth_dest_backup, eth->h_dest, ETH_ALEN);
		__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
		__builtin_memcpy(eth->h_source, eth_dest_backup, ETH_ALEN);

		/* swap the IPv6 addrs */
		struct in6_addr ip6_dest_backup;
		__builtin_memcpy(&ip6_dest_backup, &(ip6h->daddr),
				sizeof(struct in6_addr));
		__builtin_memcpy(&(ip6h->daddr), &(ip6h->saddr), sizeof(struct
					in6_addr));
		__builtin_memcpy(&(ip6h->saddr), &ip6_dest_backup,
				sizeof(struct in6_addr));

		/* adjust the payload length */
		size_t payload_len = sizeof(struct sctphdr) + sizeof(struct
				sctp_chunkhdr);
		ip6h->payload_len = bpf_htons(payload_len);

		/* create the SCTP cookie ack */
		sctph->source = spx_state->sctp_sport;
		sctph->dest = spx_state->sctp_dport;
		sctph->vtag = spx_state->sctp_dvtag;
		sctph->checksum = bpf_htonl(0);
		chunk1->type = SCTP_CID_COOKIE_ACK;
		chunk1->flags = 0;
		chunk1->length = bpf_htons(sizeof(struct sctp_chunkhdr));

		/* calculate CRC32c checksum */
		__u32 csum = 0;
		if (!sctp_csum_calc(sctph, data_end, payload_len, &csum)) {
			bpf_printk("sctp checksum calculation failed");
			return TC_ACT_SHOT;
		}
		sctph->checksum = bpf_htonl(csum);

		if (bpf_skb_change_tail(skb, payload_len + sizeof(struct
						ipv6hdr) + sizeof(struct
							ethhdr), 0) < 0) {
			return TC_ACT_SHOT;
		}

		/* mark the packet for reinjection so that the interface
		 * program accepts it */
		((struct bpf_cb_mark_info *) &(skb->cb[0]))->mark =
			SPX_TO_SCTP_REINJECT_MARK;
		return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
	}

	__u8 connection_control = 0;
	__u8 datastream_type = 0;
	get_spx_packet_info_egress(spx_state, data_len, &connection_control,
			&datastream_type);

	/* make room for the new headers */
	__s32 newhdrs_len = sizeof(struct udphdr) + sizeof(struct ipxhdr) +
		sizeof(struct spxhdr);
	__s32 len_diff = newhdrs_len - data_ofs;
	size_t payload_len = bpf_ntohs(ip6h->payload_len) + len_diff -
		padding_bytes;
	if (bpf_skb_adjust_room(skb, len_diff, BPF_ADJ_ROOM_NET, 0) < 0) {
		return TC_ACT_SHOT;
	}
	if (bpf_skb_change_tail(skb, payload_len + sizeof(struct ipv6hdr) +
				sizeof(struct ethhdr), 0) < 0) {
		return TC_ACT_SHOT;
	}
	bpf_skb_pull_data(skb, 0);

	/* adjust pointers and reverify */
	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;

	eth = data;
	ip6h = ((void *) eth) + sizeof(struct ethhdr);
	struct udphdr *udph = ((void *) ip6h) + sizeof(struct ipv6hdr);
	struct ipxhdr *ipxh = ((void *) udph) + sizeof(struct udphdr);
	struct spxhdr *spxh = ((void *) ipxh) + sizeof(struct ipxhdr);
	if (spxh + 1 > data_end) {
		return TC_ACT_SHOT;
	}

	/* calculate and verify length */
	if (payload_len < sizeof(struct udphdr) + sizeof(struct ipxhdr) +
			sizeof(struct spxhdr)) {
		return TC_ACT_SHOT;
	}
	if (payload_len > MAX_DGRAM_LEN) {
		return TC_ACT_SHOT;
	}
	if (payload_len + sizeof(struct ipv6hdr) + sizeof(struct ethhdr) !=
			skb->len) {
		return TC_ACT_SHOT;
	}

	/* fill in IPv6 header */
	ip6h->payload_len = bpf_htons(payload_len);
	ip6h->nexthdr = IPPROTO_UDP;

	struct ipv6_eui64_addr *ip6_saddr = (struct ipv6_eui64_addr *)
		&(ip6h->saddr);
	ip6_saddr->prefix = spx_state->prefix;
	ip6_saddr->ipx_net = spx_state->local_addr.net;
	__builtin_memcpy(ip6_saddr->ipx_node_fst, spx_state->local_addr.node,
			IPX_ADDR_NODE_BYTES / 2);
	ip6_saddr->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(ip6_saddr->ipx_node_snd,
			&(spx_state->local_addr.node[3]), IPX_ADDR_NODE_BYTES /
			2);

	struct ipv6_eui64_addr *ip6_daddr = (struct ipv6_eui64_addr *)
		&(ip6h->daddr);
	ip6_daddr->prefix = spx_state->prefix;
	ip6_daddr->ipx_net = spx_state->remote_addr.net;
	__builtin_memcpy(ip6_daddr->ipx_node_fst, spx_state->remote_addr.node,
			IPX_ADDR_NODE_BYTES / 2);
	ip6_daddr->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(ip6_daddr->ipx_node_snd,
			&(spx_state->remote_addr.node[3]), IPX_ADDR_NODE_BYTES
			/ 2);

	/* fill in the UDP header. */
	// TODO: calculate the UDP checksum properly
	udph->source = bpf_htons(IPX_IN_IPV6_PORT);
	udph->dest = bpf_htons(IPX_IN_IPV6_PORT);
	udph->check = bpf_htons(0xdead);
	udph->len = bpf_htons(payload_len);

	/* fill in the IPX header */
	ipxh->csum = IPX_CSUM_NONE;
	ipxh->pktlen = bpf_htons(payload_len - sizeof(struct udphdr));
	ipxh->tc = 0;
	ipxh->type = SPX_PKT_TYPE;
	ipxh->daddr = spx_state->remote_addr;
	ipxh->saddr = spx_state->local_addr;

	/* fill in the SPX header */
	spxh->connection_control = connection_control;
	spxh->datastream_type = datastream_type;
	spxh->src_conn_id = spx_state->local_id;
	spxh->dst_conn_id = spx_state->remote_id;
	spxh->seq_no = bpf_htons(spx_state->local_current_sequence);
	spxh->ack_no = bpf_htons(spx_state->remote_expected_sequence);
	spxh->alloc_no = bpf_htons(spx_state->local_alloc_no);

	return TC_ACT_UNSPEC;
}

SEC("socket")
int ipx_wrap_spx_kcm(struct __sk_buff *skb)
{
	bpf_printk("kcm: %d bytes", skb->len);
	return skb->len;
}

char _license[] SEC("license") = "GPL";
