/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "ipx_wrap_common_kern.h"
#include "ipx_wrap_common_proto.h"

#define AF_INET6 10

#define IPX_SOCKETS_MAX	32768
#define SPX_SOCKETS_MAX	32768

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct ipx_addr);
	__type(value, __u64);
	__uint(max_entries, IPX_SOCKETS_MAX);
	//__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_sock_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__type(key, __u32);
	__type(value, struct ipx_addr);
	__uint(max_entries, 0);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipx_wrap_mux_bind_egress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipx_addr);
	__type(value, struct bpf_bind_entry);
	__uint(max_entries, IPX_SOCKETS_MAX);
	__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_bind_entries_uc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct mc_bind_entry_key);
	__type(value, struct bpf_bind_entry);
	__uint(max_entries, IPX_SOCKETS_MAX);
	__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_bind_entries_mc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct spx_conn_key);
	__type(value, __u64);
	__uint(max_entries, SPX_SOCKETS_MAX);
	//__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_spx_sock_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__type(key, __u32);
	__type(value, struct bpf_spx_state);
	__uint(max_entries, 0);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipx_wrap_mux_spx_state SEC(".maps");

enum ipx_wrap_spx_ingress_verdict {
	SPX_DROP = 0,
	SPX_PASS,
	SPX_DROP_AND_ACK
};

static __always_inline bool csum_replace_with_zero_check(struct __sk_buff *skb,
		__u32 csum_ofs, __s64 csum_diff)
{
	/* replace the checksum normally */
	if (bpf_l4_csum_replace(skb, csum_ofs, 0, csum_diff, BPF_F_PSEUDO_HDR)
			!= 0) {
		return false;
	}

	/* get the new checksum from the packet */
	__sum16 udp_csum;
	if (bpf_skb_load_bytes(skb, csum_ofs, &udp_csum, sizeof(__sum16)) != 0)
	{
		return false;
	}

	/* if the BPF helper stored a zero checksum */
	if (udp_csum == 0x0000) {
		udp_csum = 0xFFFF;

		if (bpf_skb_store_bytes(skb, csum_ofs, &udp_csum,
					sizeof(__sum16), 0) != 0) {
			return false;
		}
	}

	return true;
}

static __always_inline enum ipx_wrap_spx_ingress_verdict
ipx_wrap_spx_check_ingress(struct bpf_spx_state *spx_state, struct
		ipxw_mux_spx_msg *spx_msg)
{
	struct spxhdr *spxh = &(spx_msg->spxh);

	bool system = (spxh->connection_control & SPX_CC_SYSTEM_PKT) != 0;
	bool ack_required = (spxh->connection_control & SPX_CC_ACK_REQUIRED) !=
		0;
	__u8 datastream_type = spxh->datastream_type;

	/* check if the packet fits with our connection state */
	if (spxh->dst_conn_id != spx_state->local_id) {
		return SPX_DROP;
	}
	if (spx_state->remote_id != SPX_CONN_ID_UNKNOWN && spxh->src_conn_id !=
			spx_state->remote_id) {
		return SPX_DROP;
	}
	/* handle the loss of ACK packets that we send by also acking data
	 * packets with a seq no lower than the current epxected one (but not
	 * letting them go through to user space) */
	if (spx_seq_less_than(bpf_ntohs(spxh->seq_no),
				spx_state->remote_expected_sequence) &&
			ack_required) {
		return SPX_DROP_AND_ACK;
	}

	if (system) {
		/* allow old system packets in case we get a lost ACK */
		__u16 cur_seq = bpf_ntohs(spxh->seq_no);
		__u16 next_seq;
		__builtin_add_overflow(cur_seq, 1, &next_seq);

		if (cur_seq != spx_state->remote_expected_sequence && next_seq
				!= spx_state->remote_expected_sequence) {
			return SPX_DROP;
		}
	} else {
		if (bpf_ntohs(spxh->seq_no) !=
				spx_state->remote_expected_sequence) {
			return SPX_DROP;
		}
	}

	/* closing the connection is always permitted */
	if (datastream_type == SPX_DS_END_OF_CONN) {
		return SPX_PASS;
	}

	if (spx_state->remote_id == SPX_CONN_ID_UNKNOWN) {
		/* accept a new connection ID only from a first packet */
		if (bpf_ntohs(spxh->seq_no) != 0 || bpf_ntohs(spxh->ack_no) !=
				0) {
			return SPX_DROP;
		}

		spx_state->remote_id = spxh->src_conn_id;
	}

	return SPX_PASS;
}

#define CB_INFO(ctx) ((struct bpf_cb_info *) &(ctx->cb[0]))

SEC("tc/ingress")
int ipx_wrap_demux(struct __sk_buff *skb)
{
	if (CB_INFO(skb)->mark != IPX_TO_IPV6UDP_REINJECT_MARK) {
		return TC_ACT_UNSPEC;
	}

	/* ugly but necessary to sneak it past the verifier */
	struct bpf_cb_info cb;
	cb.cb[0] = skb->cb[0];
	cb.cb[1] = skb->cb[1];
	cb.cb[2] = skb->cb[2];
	cb.cb[3] = skb->cb[3];
	cb.cb[4] = skb->cb[4];

	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct hdr_cursor cur;
	cur.pos = data;

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
	if (bpf_ntohs(udph->len) < sizeof(struct udphdr) + sizeof(struct
				ipxhdr)) {
		return TC_ACT_UNSPEC;
	}

	if (cur.pos + sizeof(struct ipxw_mux_msg) > data_end) {
		return TC_ACT_UNSPEC;
	}

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
	if (fib_res == 0) {
		cb.is_for_local = false;
		return TC_ACT_UNSPEC;
	} else if (fib_res == BPF_FIB_LKUP_RET_NOT_FWDED) {
		cb.is_for_local = true;
	} else {
		return TC_ACT_UNSPEC;
	}

	/* packet is destined for the local machine */

	struct ipxw_mux_msg *mux_msg = cur.pos;
	struct ipxw_mux_spx_msg *spx_msg = cur.pos;
	struct ipxhdr *ipxh = &(mux_msg->ipxh);

	struct bpf_bind_entry *e = NULL;

	if (cb.is_bcast) {
		struct mc_bind_entry_key key = {
			.ifidx = skb->ingress_ifindex,
			.dst_sock = ipxh->daddr.sock
		};

		/* try to get entry for broadcast */
		e = bpf_map_lookup_elem(&ipx_wrap_mux_bind_entries_mc, &key);
	} else {
		/* try to get entry for unicast dst address */
		e = bpf_map_lookup_elem(&ipx_wrap_mux_bind_entries_uc,
				&(ipxh->daddr));
	}

	/* no binding entry */
	if (e == NULL) {
		/* packet was for the local machine, drop it */
		return TC_ACT_SHOT;
	}

	if (cb.is_bcast && !e->recv_bcast) {
		return TC_ACT_SHOT;
	}

	/* check packet type */
	if (ipxh->type != e->pkt_type && !e->pkt_type_any) {
		return TC_ACT_SHOT;
	}

	struct bpf_sock *sock = NULL;
	struct bpf_spx_state *spx_state = NULL;
	struct spxhdr *spxh = NULL;

	/* if the packet is an SPX packet, see if it belongs to an existing
	 * connection */
	if (!cb.is_bcast && ipxh->type == SPX_PKT_TYPE) {
		if (cur.pos + sizeof(struct ipxhdr) + sizeof(struct spxhdr) <=
				data_end) {
			spxh = cur.pos + sizeof(struct ipxhdr);
			struct spx_conn_key conn_key = {
				.bind_addr = e->addr,
				.conn_id = spxh->dst_conn_id
			};
			sock = bpf_map_lookup_elem(
					&ipx_wrap_mux_spx_sock_ingress,
					&conn_key);
		}

		/* packet belongs to an SPX connection */
		if (sock != NULL) {
			spx_state = bpf_sk_storage_get(&ipx_wrap_mux_spx_state,
					sock, NULL, 0);

			/* weirdly no SPX state exists, handle the packet like
			 * a normal IPX packet instead */
			if (spx_state == NULL) {
				bpf_sk_release(sock);
				sock = NULL;
			}
		}
	}

	/* not an SPX packet or no SPX state, handle like a normal IPX packet
	 * instead */
	if (sock == NULL) {
		sock = bpf_map_lookup_elem(&ipx_wrap_mux_sock_ingress,
				&(e->addr));
	}

	if (sock == NULL) {
		return TC_ACT_SHOT;
	}

	long err = bpf_sk_assign(skb, sock, 0);
	bpf_sk_release(sock);
	if (err != 0) {
		return TC_ACT_SHOT;
	}

	struct ipx_addr saddr = ipxh->saddr;
	__u8 pkt_type = ipxh->type;
	__u8 tc = ipxh->tc;

	/* extract the correct data length */
	__u16 data_len = bpf_ntohs(ipxh->pktlen);
	if (data_len + sizeof(struct udphdr) + sizeof(struct ipv6hdr) +
			sizeof(struct ethhdr) != skb->len) {
		return TC_ACT_SHOT;
	}
	if (data_len < sizeof(struct ipxw_mux_msg)) {
		return TC_ACT_SHOT;
	}
	if (data_len > IPXW_MUX_MSG_LEN) {
		return TC_ACT_SHOT;
	}
	if (data_len + sizeof(struct udphdr) != bpf_ntohs(udph->len)) {
		return TC_ACT_SHOT;
	}
	data_len -= sizeof(struct ipxhdr);

	/* remove IPX header from checksum */
	__u32 ipxhdr_len_mult_4 = (sizeof(struct ipxhdr) / 4) * 4;
	__s64 csum_diff = bpf_csum_diff((__be32*) ipxh, ipxhdr_len_mult_4,
			NULL, 0, 0);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	__be32 rest = ((__be32) *((__be16 *) (((void*) ipxh) +
					ipxhdr_len_mult_4))) << 16;
	csum_diff = bpf_csum_diff(&rest, sizeof(__be32), NULL, 0, csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}

	/* clear the header so we can rewrite into a recv msg */
	__builtin_memset(mux_msg, 0, sizeof(struct ipxw_mux_msg));

	/* rewrite to recv msg */
	mux_msg->type = IPXW_MUX_RECV;
	mux_msg->recv.saddr = saddr;
	mux_msg->recv.pkt_type = pkt_type;
	mux_msg->recv.is_bcast = cb.is_bcast;
	mux_msg->recv.is_spx = (spx_state != NULL);
	mux_msg->recv.data_len = data_len;
	mux_msg->recv.tc = tc;

	/* add recv msg header to checksum */
	csum_diff = bpf_csum_diff(NULL, 0, (__be32*) mux_msg,
			ipxhdr_len_mult_4, csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	rest = ((__be32) *((__be16 *) (((void*) ipxh) + ipxhdr_len_mult_4))) <<
		16;
	csum_diff = bpf_csum_diff(NULL, 0, &rest, sizeof(__be32), csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}

	enum ipx_wrap_spx_ingress_verdict spx_verdict = SPX_DROP;
	if (spx_state != NULL) {
		spx_verdict = ipx_wrap_spx_check_ingress(spx_state, spx_msg);
		if (spx_verdict == SPX_DROP) {
			return TC_ACT_SHOT;
		}

		/* rewrite the SPX header to an SPX message */
		bool end_of_msg = (spxh->connection_control &
				SPX_CC_END_OF_MSG) != 0;
		bool attention = (spxh->connection_control & SPX_CC_ATTENTION)
			!= 0;
		bool system_pkt = (spxh->connection_control &
				SPX_CC_SYSTEM_PKT) != 0;
		bool ack_required = (spxh->connection_control &
				SPX_CC_ACK_REQUIRED) != 0;
		bool spxii = (spxh->connection_control & SPX_CC_SPXII) != 0;
		bool negotiate_size = (spxh->connection_control &
				SPX_CC_NEGOTIATE_SIZE) != 0;
		__u8 datastream_type = spxh->datastream_type;
		__u16 remote_alloc_no = bpf_ntohs(spxh->alloc_no);
		__u16 seq_no = bpf_ntohs(spxh->seq_no);
		__u16 ack_no = bpf_ntohs(spxh->ack_no);
		__u16 neg_size = 0;
		if (spxii && (&(spx_msg->spxii_negotiate_size_h) + 1) <=
				data_end) {
			neg_size =
				bpf_ntohs(spx_msg->spxii_negotiate_size_h.negotiation_size);
		}

		/* remove SPX header from checksum */
		csum_diff = bpf_csum_diff((__be32*) spxh, sizeof(struct
					spxhdr), NULL, 0, csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}

		/* clear the header so we can rewrite into an SPX msg */
		__builtin_memset(spxh, 0, sizeof(struct spxhdr));

		/* rewrite to SPX msg */
		spx_msg->end_of_msg = end_of_msg;
		spx_msg->attention = attention;
		spx_msg->system = system_pkt;
		spx_msg->ack_required = ack_required;
		spx_msg->spxii = spxii;
		spx_msg->negotiate_size = negotiate_size;
		spx_msg->datastream_type = datastream_type;
		spx_msg->remote_alloc_no = remote_alloc_no;
		spx_msg->seq_no = seq_no;
		spx_msg->remote_expected_sequence = ack_no;
		spx_msg->negotiation_size = neg_size;

		/* add SPX msg to checksum */
		csum_diff = bpf_csum_diff(NULL, 0, (__be32*) spxh,
				sizeof(struct spxhdr), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
	}

	__u32 csum_ofs = ((void *) &(udph->check)) - data;
	if (spx_state == NULL || spx_verdict != SPX_DROP_AND_ACK) {
		/* insert the modified checksum */
		if (!csum_replace_with_zero_check(skb, csum_ofs, csum_diff)) {
			return TC_ACT_SHOT;
		}

		return TC_ACT_OK;
	}

	/* we have to generate an ACK, we do this by rewriting the packet and
	 * reflecting it */

	/* FIB lookup for the ACK */
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = AF_INET6;
	__builtin_memcpy(fib_params.ipv6_dst, &(ip6h->saddr),
			sizeof(fib_params.ipv6_dst));
	__builtin_memcpy(fib_params.ipv6_src, &(ip6h->daddr),
			sizeof(fib_params.ipv6_src));
	fib_params.l4_protocol = IPPROTO_UDP;
	fib_params.sport = bpf_htons(IPX_IN_IPV6_PORT);
	fib_params.dport = bpf_htons(IPX_IN_IPV6_PORT);
	fib_params.ifindex = skb->ingress_ifindex;
	fib_res = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);
	if (fib_res != 0) {
		return TC_ACT_SHOT;
	}

	/* update ETH and IPv6 headers */
	__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	__builtin_memcpy(&(ip6h->saddr), fib_params.ipv6_src,
			sizeof(fib_params.ipv6_src));
	__builtin_memcpy(&(ip6h->daddr), fib_params.ipv6_dst,
			sizeof(fib_params.ipv6_dst));

	/* update cb */
	struct bpf_cb_info cb_new = {
		.mark = IPX_SPX_REFLECTED_ACK,
		.is_bcast = false,
		.is_for_local = false,
		.is_spx_end_of_conn_ack = (spx_msg->datastream_type ==
				SPX_DS_END_OF_CONN),
		.is_spxii = spx_msg->spxii,
		.is_negotiate_size = spx_msg->negotiate_size,
		.spx_src = e->addr,
		.spx_conn_id = spx_state->local_id
	};
	skb->cb[0] = cb_new.cb[0];
	skb->cb[1] = cb_new.cb[1];
	skb->cb[2] = cb_new.cb[2];
	skb->cb[3] = cb_new.cb[3];
	skb->cb[4] = cb_new.cb[4];

	/* cut the ACK packet down to size */
	size_t ack_len = spx_msg->spxii ? sizeof(struct
			spxii_negotiate_size_hdr) : 0;
	ack_len += sizeof(struct ipxhdr) + sizeof(struct spxhdr);
	mux_msg->recv.data_len = ack_len;

	ack_len += sizeof(struct udphdr);
	udph->len = bpf_htons(ack_len);
	ip6h->payload_len = bpf_htons(ack_len);

	ack_len += sizeof(struct ipv6hdr) + sizeof(struct
			ethhdr);

	if (bpf_skb_change_tail(skb, ack_len, 0) != 0) {
		return TC_ACT_SHOT;
	}

	/* redirect the thusly generated ACK */
	return bpf_redirect(fib_params.ifindex, 0);
}

static __always_inline bool ipx_wrap_spx_egress(struct bpf_spx_state
		*spx_state, struct ipxw_mux_spx_msg *spx_msg, bool
		have_negotiate_size_hdr, struct bpf_cb_info *cb_info)
{
	struct spxhdr *spxh = &(spx_msg->spxh);

	bool end_of_msg = spx_msg->end_of_msg;
	bool attention = spx_msg->attention;
	bool system = spx_msg->system;
	bool keep_alive = spx_msg->keep_alive;
	bool verify = spx_msg->keep_alive && spx_msg->ack_required;
	bool ack = spx_msg->ack;
	bool ack_required = spx_msg->ack_required;
	bool spxii = spx_msg->spxii;
	bool negotiate_size = spx_msg->negotiate_size;
	__u8 datastream_type = spx_msg->datastream_type;
	__u16 msg_seq = spx_msg->local_current_sequence;
	__u16 msg_ack = spx_msg->remote_expected_sequence;
	__u16 msg_loc_alloc = spx_msg->local_alloc_no;
	__u16 msg_rem_alloc = spx_msg->remote_alloc_no;
	__u16 msg_neg_size = spx_msg->negotiation_size;

	spxh->src_conn_id = spx_state->local_id;
	spxh->dst_conn_id = spx_state->remote_id;

	spxh->seq_no = bpf_htons(msg_seq);
	spxh->ack_no = bpf_htons(msg_ack);

	spxh->alloc_no = bpf_htons(msg_loc_alloc);

	/* fill in the negotiate size header */
	if (spxii && have_negotiate_size_hdr) {
		spx_msg->spxii_negotiate_size_h.negotiation_size =
			bpf_htons(msg_neg_size);
	}

	/* always allow reflected ACKs to go out, use the last known
	 * information to fill in the header */
	if (cb_info->mark == IPX_SPX_REFLECTED_ACK) {
		spxh->seq_no = bpf_htons(spx_state->local_current_sequence);
		spxh->ack_no = bpf_htons(spx_state->remote_expected_sequence);
		spxh->alloc_no = bpf_htons(spx_state->local_alloc_no);
		spxh->connection_control = SPX_CC_SYSTEM_PKT;
		if (cb_info->is_spxii) {
			/* fill in the negotiate size header */
			if (have_negotiate_size_hdr) {
				spx_msg->spxii_negotiate_size_h.negotiation_size
					=
					bpf_htons(spx_state->neg_size_to_local);
			}

			spxh->connection_control |= SPX_CC_SPXII;
			if (cb_info->is_negotiate_size) {
				spxh->connection_control |=
					SPX_CC_NEGOTIATE_SIZE;
			}
		}
		spxh->datastream_type = (cb_info->is_spx_end_of_conn_ack ?
				SPX_DS_END_OF_CONN_ACK : SPX_DS_NONE);
		return true;
	}

	spxh->connection_control = 0;
	if (spxii) {
		spxh->connection_control |= SPX_CC_SPXII;
	}

	spx_state->local_current_sequence = msg_seq;
	spx_state->remote_expected_sequence = msg_ack;
	spx_state->local_alloc_no = msg_loc_alloc;
	spx_state->remote_alloc_no = msg_rem_alloc;
	spx_state->neg_size_to_local = msg_neg_size;

	/* allow sending connection verification requests */
	if (verify) {
		spxh->connection_control |= SPX_CC_SYSTEM_PKT |
			SPX_CC_ACK_REQUIRED;
		spxh->datastream_type = SPX_DS_NONE;
		return true;
	}

	/* allow sending keep alive packets */
	if (keep_alive) {
		spxh->connection_control |= SPX_CC_SYSTEM_PKT;
		spxh->datastream_type = SPX_DS_NONE;
		return true;
	}

	if (spxii && negotiate_size) {
		spxh->connection_control |= SPX_CC_NEGOTIATE_SIZE;
	}

	/* allow sending ACK packets */
	if (ack) {
		spxh->connection_control |= SPX_CC_SYSTEM_PKT;
		spxh->datastream_type = SPX_DS_NONE;
		if (datastream_type == SPX_DS_END_OF_CONN_ACK) {
			spxh->datastream_type = SPX_DS_END_OF_CONN_ACK;
		}
		return true;
	}

	spxh->datastream_type = datastream_type;

	if (end_of_msg) {
		spxh->connection_control |= SPX_CC_END_OF_MSG;
	}
	if (attention) {
		spxh->connection_control |= SPX_CC_ATTENTION;
	}
	if (ack_required) {
		spxh->connection_control |= SPX_CC_ACK_REQUIRED;
	}
	if (system) {
		spxh->connection_control |= SPX_CC_SYSTEM_PKT;
	}

	return true;
}

static __always_inline struct bpf_sock *get_client_sock_from_spx_conn(struct
		bpf_cb_info *cb)
{
	if (cb->mark != IPX_SPX_REFLECTED_ACK) {
		return NULL;
	}

	struct spx_conn_key conn_key = {
		.bind_addr = cb->spx_src,
		.conn_id = cb->spx_conn_id
	};

	struct bpf_sock *ret = bpf_map_lookup_elem(
			&ipx_wrap_mux_spx_sock_ingress, &conn_key);
	return ret;
}

SEC("tc/egress")
int ipx_wrap_mux(struct __sk_buff *skb)
{
	struct bpf_cb_info cb_info;
	cb_info.cb[0] = skb->cb[0];
	cb_info.cb[1] = skb->cb[1];
	cb_info.cb[2] = skb->cb[2];
	cb_info.cb[3] = skb->cb[3];
	cb_info.cb[4] = skb->cb[4];

	bool client_sock_must_release = false;
	struct bpf_sock *client_sock = skb->sk;
	/* no client socket, see if we have an SPX connection in cb */
	if (client_sock == NULL) {
		client_sock = get_client_sock_from_spx_conn(&cb_info);
		client_sock_must_release = true;
	}

	/* no source socket, do nothing */
	if (client_sock == NULL) {
		return TC_ACT_UNSPEC;
	}

	struct ipx_addr *bind_addr = NULL;
	struct bpf_spx_state *spx_state = NULL;

	bind_addr = bpf_sk_storage_get(&ipx_wrap_mux_bind_egress, client_sock,
			NULL, 0);
	if (bind_addr == NULL) {
		spx_state = bpf_sk_storage_get(&ipx_wrap_mux_spx_state,
				client_sock, NULL, 0);

		/* not one of our client sockets, do nothing */
		if (spx_state == NULL) {
			if (client_sock_must_release) {
				bpf_sk_release(client_sock);
			}
			return TC_ACT_UNSPEC;
		}
	}
	if (client_sock_must_release) {
		bpf_sk_release(client_sock);
	}

	struct bpf_bind_entry spx_bind_entry;
	struct bpf_bind_entry *e = NULL;

	/* regular IPX socket */
	if (bind_addr != NULL) {
		/* get the bind entry */
		e = bpf_map_lookup_elem(&ipx_wrap_mux_bind_entries_uc,
				bind_addr);
	/* SPX socket */
	} else {
		spx_bind_entry.addr = spx_state->local_addr;
		spx_bind_entry.prefix = spx_state->prefix;
		e = &spx_bind_entry;
	}

	/* no bind entry, drop */
	if (e == NULL) {
		return TC_ACT_SHOT;
	}

	/* parse the packet and discard everything unexpected, we only want
	 * IPv6 UDP with enough room to contain an IPX header */
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

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
	if (ip6h->nexthdr != IPPROTO_UDP) {
		return TC_ACT_SHOT;
	}

	struct udphdr *udph;
	if (parse_udphdr(&cur, data_end, &udph) < 0) {
		return TC_ACT_SHOT;
	}
	if (bpf_ntohs(udph->len) < sizeof(struct udphdr) + sizeof(struct
				ipxhdr)) {
		return TC_ACT_SHOT;
	}

	if (cur.pos + sizeof(struct ipxw_mux_msg) > data_end) {
		return TC_ACT_SHOT;
	}

	struct ipxw_mux_msg *mux_msg = cur.pos;

	/* if we have an SPX socket, create the xmit message from the SPX state
	 */
	if (spx_state != NULL) {
		mux_msg->type = IPXW_MUX_XMIT;
		mux_msg->xmit.daddr = spx_state->remote_addr;
		mux_msg->xmit.pkt_type = SPX_PKT_TYPE;
		mux_msg->xmit.data_len = bpf_ntohs(udph->len) - (sizeof(struct
					udphdr) + sizeof(struct ipxhdr));
	}

	/* verify the xmit message against the bind entry */
	if (mux_msg->type != IPXW_MUX_XMIT) {
		return TC_ACT_SHOT;
	}
	size_t data_len = mux_msg->xmit.data_len;
	if (data_len + sizeof(struct ipxhdr) + sizeof(struct udphdr) +
			sizeof(struct ipv6hdr) + sizeof(struct ethhdr) !=
			skb->len) {
		return TC_ACT_SHOT;
	}
	if (data_len > IPX_MAX_DATA_LEN) {
		return TC_ACT_SHOT;
	}
	if (data_len != bpf_ntohs(udph->len) - (sizeof(struct udphdr) +
				sizeof(struct ipxhdr))) {
		return TC_ACT_SHOT;
	}

	/* fill in the IPv6 addresses */
	struct ipv6_eui64_addr *ip6_saddr = (struct ipv6_eui64_addr *)
		&(ip6h->saddr);
	ip6_saddr->prefix = e->prefix;
	ip6_saddr->ipx_net = e->addr.net;
	__builtin_memcpy(ip6_saddr->ipx_node_fst, e->addr.node,
			IPX_ADDR_NODE_BYTES / 2);
	ip6_saddr->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(ip6_saddr->ipx_node_snd, &(e->addr.node[3]),
			IPX_ADDR_NODE_BYTES / 2);

	struct ipv6_eui64_addr *ip6_daddr = (struct ipv6_eui64_addr *)
		&(ip6h->daddr);
	ip6_daddr->prefix = e->prefix;
	ip6_daddr->ipx_net = mux_msg->xmit.daddr.net;
	__builtin_memcpy(ip6_daddr->ipx_node_fst, mux_msg->xmit.daddr.node,
			IPX_ADDR_NODE_BYTES / 2);
	ip6_daddr->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(ip6_daddr->ipx_node_snd,
			&(mux_msg->xmit.daddr.node[3]), IPX_ADDR_NODE_BYTES /
			2);

	struct ipx_addr daddr = mux_msg->xmit.daddr;
	__u8 pkt_type = mux_msg->xmit.pkt_type;
	__u16 msg_len = mux_msg->xmit.data_len + sizeof(struct ipxhdr);

	/* build the IPX header */
	struct ipxhdr *ipx_msg = &(mux_msg->ipxh);
	ipx_msg->csum = IPX_CSUM_NONE;
	ipx_msg->pktlen = bpf_htons(msg_len);
	ipx_msg->tc = 0;
	ipx_msg->type = pkt_type;
	ipx_msg->daddr = daddr;
	ipx_msg->saddr = e->addr;

	udph->source = bpf_htons(IPX_IN_IPV6_PORT);

	/* also fill in the spx header */
	if (spx_state != NULL) {
		if (cur.pos + SPX_WIRE_OVERHEAD > data_end) {
			return TC_ACT_SHOT;
		}

		struct ipxw_mux_spx_msg *spx_msg = cur.pos;

		bool have_negotiate_size_hdr = false;
		if (cur.pos + SPXII_WIRE_OVERHEAD <= data_end) {
			have_negotiate_size_hdr = true;
		}

		/* prepare the SPX header */
		if (!ipx_wrap_spx_egress(spx_state, spx_msg,
					have_negotiate_size_hdr, &cb_info)) {
			return TC_ACT_SHOT;
		}
	}

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
