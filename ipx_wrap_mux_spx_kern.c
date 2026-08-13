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

/* from linux/tcp.h */
#define tcp_flag_word(tp) (((union tcp_word_hdr *)(tp))->words[3])

#define TCP_WINDOW bpf_htonl(0x0000FFFF)

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

static __always_inline bool check_spx_msg_ingress(const struct bpf_kspx_state
		*spx_state, const struct spxhdr *spxh, size_t data_len)
{
	bool system = (spxh->connection_control & SPX_CC_SYSTEM_PKT) != 0;
	bool ack_required = (spxh->connection_control & SPX_CC_ACK_REQUIRED) !=
		0;
	__u8 datastream_type = spxh->datastream_type;

	/* check if the packet fits with our connection state */
	if (spxh->dst_conn_id != spx_state->local_id) {
		return false;
	}
	if (spx_state->remote_id != SPX_CONN_ID_UNKNOWN && spxh->src_conn_id !=
			spx_state->remote_id) {
		return false;
	}
	/* handle the loss of ACK packets that we send by also acking data
	 * packets with a seq no lower than the current epxected one (but not
	 * letting them go through to TCP) */
	if (spx_seq_less_than(bpf_ntohs(spxh->seq_no),
				spx_state->remote_expected_sequence) &&
			ack_required) {
		// TODO: need to construct an SPX ack for packets like this...
		return false;
	}

	if (system) {
		if (data_len != 0) {
			return false;
		}

		/* allow old system packets in case we get a lost ACK */
		__u16 cur_seq = bpf_ntohs(spxh->seq_no);
		__u16 next_seq;
		__builtin_add_overflow(cur_seq, 1, &next_seq);

		if (cur_seq != spx_state->remote_expected_sequence && next_seq
				!= spx_state->remote_expected_sequence) {
			return false;
		}
	} else {
		if (bpf_ntohs(spxh->seq_no) !=
				spx_state->remote_expected_sequence) {
			return false;
		}
	}

	/* closing the connection is always permitted */
	if (datastream_type == SPX_DS_END_OF_CONN) {
		return true;
	}

	if (spx_state->remote_id == SPX_CONN_ID_UNKNOWN) {
		/* accept a new connection ID only from a first packet */
		if (bpf_ntohs(spxh->seq_no) != 0 || bpf_ntohs(spxh->ack_no) !=
				0) {
			return false;
		}
	}

	/* check the connection state */
	switch (spx_state->state) {
		case KSPX_NEW:
			if ((spxh->connection_control & SPX_CC_MASK_SPX) !=
					SPX_CC_SYSTEM_PKT) {
				return false;
			}
			break;
		case KSPX_ESTABLISHED:
			break;
		default:
			return false;
	}

	return true;
}

static __always_inline bool spx_msg_is_current_ack(const struct bpf_kspx_state
		*spx_state, const struct spxhdr *spxh)
{
	/* message must be an ACK */
	if ((spxh->connection_control & SPX_CC_MASK_SPX) != SPX_CC_SYSTEM_PKT)
	{
		return false;
	}

	/* we want an ACK and it has to ACK the last packet we sent */
	__u16 local_next_sequence = spx_state->local_current_sequence;
	if (spx_state->last_sent_msg_data_len != 0) {
		/* last msg was a non-system packet, therefore we need the ack
		 * number to be one higher than its seq no */
		__builtin_add_overflow(local_next_sequence, 1,
				&local_next_sequence);
	}
	if (bpf_ntohs(spxh->ack_no) != local_next_sequence) {
		return false;
	}

	return true;
}

static __always_inline void update_spx_state_ingress(struct bpf_kspx_state
		*spx_state, const struct spxhdr *spxh, size_t data_len)
{
	spx_state->remote_id = spxh->src_conn_id;

	/* message is an ACK */
	if (spx_msg_is_current_ack(spx_state, spxh)) {
		/* increment sequence number and virtual TCP ACK no after
		 * receiving an ACK for a non-system message */
		if (spx_state->last_sent_msg_data_len != 0) {
			__builtin_add_overflow(
					spx_state->local_current_sequence, 1,
					&(spx_state->local_current_sequence));
			__builtin_add_overflow(spx_state->sctp_tsn_ack, 1,
					&(spx_state->sctp_tsn_ack));
		}
	} else {
		if (data_len != 0) {
			spx_state->last_rcvd_msg_data_len = data_len;
		}
	}

	spx_state->remote_alloc_no = spxh->alloc_no;
}

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
		bpf_printk("no kernel spx state");
		return TC_ACT_SHOT;
	}

	size_t data_len = bpf_ntohs(ipxh->pktlen) - (sizeof(struct ipxhdr) +
			sizeof(struct spxhdr));
	if (!check_spx_msg_ingress(spx_state, spxh, data_len)) {
		bpf_printk("shot: msg check failed");
		return TC_ACT_SHOT;
	}

	update_spx_state_ingress(spx_state, spxh, data_len);

	/* remove UDP, IPX and SPX headers, as well as the IPv6 payload length
	 * from the checksum */
	__s64 csum_diff = csum_del_spxhdr(spxh, 0);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	csum_diff = csum_del_ipxhdr(ipxh, csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	csum_diff = csum_del((__be32 *) udph, sizeof(struct udphdr),
			csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	__be32 pktlen_be32 = bpf_htonl(bpf_ntohs(ip6h->payload_len) &
			0x0000FFFF);
	csum_diff = csum_del(&pktlen_be32, sizeof(pktlen_be32), csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	__be32 nexthdr_be32 = bpf_htonl(IPPROTO_UDP & 0x000000FF);
	csum_diff = csum_del(&nexthdr_be32, sizeof(nexthdr_be32), csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}

	/* make room for the TCP header */
	__s32 oldhdrs_len = sizeof(struct udphdr) + sizeof(struct ipxhdr) +
		sizeof(struct spxhdr);
	__s32 len_diff = sizeof(struct tcphdr) - oldhdrs_len;
	size_t payload_len = bpf_ntohs(ip6h->payload_len) + len_diff;
	if (bpf_skb_adjust_room(skb, len_diff, BPF_ADJ_ROOM_NET, 0) < 0) {
		bpf_printk("shot: adjust room");
		return TC_ACT_SHOT;
	}
	bpf_skb_pull_data(skb, 0);

	/* adjust pointers and reverify */
	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;

	eth = data;
	ip6h = ((void *) eth) + sizeof(struct ethhdr);
	struct tcphdr *tcph = ((void *) ip6h) + sizeof(struct ipv6hdr);
	if (tcph + 1 > data_end) {
		bpf_printk("shot: not enough room");
		return TC_ACT_SHOT;
	}
	/* calculate and verify length */
	if (payload_len < sizeof(struct tcphdr)) {
		bpf_printk("shot: invalid payload len");
		return TC_ACT_SHOT;
	}
	if (payload_len > MAX_DGRAM_LEN) {
		bpf_printk("shot: invalid payload len 2");
		return TC_ACT_SHOT;
	}
	if (payload_len + sizeof(struct ipv6hdr) + sizeof(struct ethhdr) !=
			skb->len) {
		bpf_printk("shot: invalid payload len 3");
		return TC_ACT_SHOT;
	}

	/* fill in the new headers */
	ip6h->nexthdr = IPPROTO_TCP;
	ip6h->payload_len = bpf_htons(payload_len);
	tcph->source = spx_state->sctp_sport;
	tcph->dest = spx_state->sctp_dport;
	tcph->seq = bpf_htonl(spx_state->sctp_tsn);
	tcph->ack_seq = bpf_htonl(spx_state->sctp_tsn_ack);
	tcp_flag_word(tcph) = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->ack = 1;
	tcph->syn = spx_state->state == KSPX_NEW ? 1 : 0;
	tcph->psh = spx_state->state != KSPX_NEW ? 1 : 0;
	tcph->window = bpf_htons(spx_state->neg_size_to_remote); // TODO:
								 // account for
								 // alloc no
								 // here
	tcph->check = bpf_htons(0);
	tcph->urg_ptr = bpf_htons(0);

	/* add the new headers into the checksum */
	pktlen_be32 = bpf_htonl(bpf_ntohs(ip6h->payload_len) &
			0x0000FFFF);
	csum_diff = csum_add(&pktlen_be32, sizeof(pktlen_be32), csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	nexthdr_be32 = bpf_htonl(IPPROTO_TCP & 0x000000FF);
	csum_diff = csum_add(&nexthdr_be32, sizeof(nexthdr_be32), csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	csum_diff = csum_add((__be32 *) tcph, sizeof(struct tcphdr),
			csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}

	bpf_printk("tcp header constructed");

	/* do csum_replace last, as it invalidates our pointers again */
	if (bpf_l4_csum_replace(skb, (((void *) &(tcph->check)) - data), 0,
				csum_diff, 0) != 0) {
		bpf_printk("shot: csum replace");
		return TC_ACT_SHOT;
	}

	bpf_printk("passed on, seq: %d, ack: %d", spx_state->sctp_tsn,
			spx_state->sctp_tsn_ack);

	return TC_ACT_UNSPEC;
}

/*struct mv_payload_loopctx {
	struct __sk_buff *skb;
	size_t last_payload_byte_offset;
	size_t mv_offset;
};

static long mv_payload_loopfn(__u64 index, void* ctx)
{
	struct mv_payload_loopctx *c = ctx;

	if (index > c->last_payload_byte_offset) {
		return 1;
	}

	__u8 b;
	__u32 src_ofs = c->last_payload_byte_offset - index;
	if (bpf_skb_load_bytes(c->skb, src_ofs, &b, 1) < 0) {
		return 1;
	}
	if (bpf_skb_store_bytes(c->skb, src_ofs + c->mv_offset, &b, 1, 0) < 0)
	{
		return 1;
	}

	return 0;
}*/

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
			/* only an init chunk is allowed for new connections */
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
	if (chunk1->type == SCTP_CID_DATA && chunk2 != NULL) {
		bpf_printk("warn: chunks after data");
		return false;
	}

	/* we can't handle multiple data chunks */
	if (chunk1->type == SCTP_CID_DATA && (chunk2 != NULL && chunk2->type ==
				SCTP_CID_DATA)) {
		bpf_printk("warn: multiple data chunks");
		return false;
	}

	return true;
}

static __always_inline bool get_ack_tsn(const struct sctp_chunkhdr *chunk1,
		void *data_end, bool *have_ack_tsn, __u32 *ack_tsn)
{
	*ack_tsn = 0;
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
		sctp_chunkhdr *chunk1, const struct sctp_chunkhdr *chunk2, void
		*data_end, size_t *data_ofs, size_t *data_len, size_t
		*padding_bytes)
{
	*data_ofs = 0;
	*data_len = 0;
	*padding_bytes = 0;

	const struct sctp_chunkhdr *chunkh = NULL;
	if (chunk1->type == SCTP_CID_DATA) {
		chunkh = chunk1;
	} else {
		if (chunk2 != NULL && chunk2->type == SCTP_CID_DATA) {
			chunkh = chunk2;
		}
	}

	/* no data chunk, mark the entire SCTP header for deletion */
	if (chunkh == NULL) {
		bpf_printk("no data");
		*data_ofs = sizeof(struct sctphdr);
		size_t chunk1_len = bpf_ntohs(chunk1->length);
		size_t chunk1_padding = (chunk1_len % 4 == 0) ? 0 : (4 -
				(chunk1_len % 4));
		*data_ofs += chunk1_len + chunk1_padding;
		if (chunk2 != NULL) {
			size_t chunk2_len = bpf_ntohs(chunk2->length);
			size_t chunk2_padding = (chunk2_len % 4 == 0) ? 0 : (4
					- (chunk2_len % 4));
			*data_ofs += chunk2_len + chunk2_padding;
		}
		return true;
	}

	/* we have data */
	size_t data_overhead = sizeof(struct sctp_chunkhdr) + sizeof(struct
			sctp_datahdr);
	size_t chunk_len = bpf_ntohs(chunkh->length);
	*data_ofs = (((void *) chunkh) - ((void *) sctph)) + data_overhead;
	*data_len = chunk_len - data_overhead;
	*padding_bytes = (chunk_len % 4 == 0) ? 0 : (4 - (chunk_len % 4));

	return true;
}

static __always_inline void update_spx_state_egress(struct bpf_kspx_state
		*spx_state, __u32 tsn_ack, size_t data_len, __be32
		initial_vtag)
{
	if (spx_state->state == KSPX_NEW) {
		spx_state->sctp_svtag = initial_vtag;
	}

	/* last message has been acknowledged by SCTP */
	if (sctp_tsn_less_than(spx_state->sctp_tsn, tsn_ack)) {
		__builtin_add_overflow(spx_state->remote_expected_sequence, 1,
				&(spx_state->remote_expected_sequence));
		__builtin_add_overflow(spx_state->local_alloc_no, 1,
				&(spx_state->local_alloc_no));
		spx_state->sctp_tsn = tsn_ack;
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
		return TC_ACT_UNSPEC;
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

	bpf_printk("got SCTP packet");

	struct sctphdr *sctph;
	if (parse_sctphdr(&cur, data_end, &sctph) < 0) {
		return TC_ACT_SHOT;
	}

	/* there should be at least one SCTP chunk, parse it */
	struct sctp_chunkhdr *chunk1;
	if (parse_sctp_chunk(&cur, data_end, &chunk1) < 0) {
		return TC_ACT_SHOT;
	}

	/* try to parse a second chunk */
	struct sctp_chunkhdr *chunk2 = NULL;
	if (parse_sctp_chunk(&cur, data_end, &chunk2) >= 0) {
		bpf_printk("have second chunk");
	}

	/* we only support two chunks per packet */
	if (chunk2 != NULL) {
		struct sctp_chunkhdr *chunk3 = NULL;
		if (parse_sctp_chunk(&cur, data_end, &chunk3) >= 0) {
			bpf_printk("have third chunk, shot");
			return TC_ACT_SHOT;
		}
	}

	if (!check_sctp_msg_egress(spx_state, sctph, chunk1, chunk2)) {
		bpf_printk("shot: SCTP msg check");
		return TC_ACT_SHOT;
	}

	__be32 initial_vtag = bpf_htonl(0);

	bool have_ack_tsn = false;
	__u32 ack_tsn = 0;
	if (!get_ack_tsn(chunk1, data_end, &have_ack_tsn, &ack_tsn)) {
		return TC_ACT_SHOT;
	}

	size_t data_ofs = 0;
	size_t data_len = 0;
	size_t padding_bytes = 0;
	if (!get_data(sctph, chunk1, chunk2, data_end, &data_ofs, &data_len,
				&padding_bytes)) {
		return TC_ACT_SHOT;
	}

	bpf_printk("data len: %u, data_ofs: %u, padding: %u", data_len,
			data_ofs, padding_bytes);

	update_spx_state_egress(spx_state, ack_tsn, data_len, initial_vtag);

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
	if (bpf_skb_change_tail(skb, skb->len - padding_bytes, 0) < 0) {
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
	// TODO: remove unnecessary fills here, these should survive from the
	// original header
	ip6h->version = 6;
	ip6h->priority = 0;
	__builtin_memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
	ip6h->payload_len = bpf_htons(payload_len);
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = 16;

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
