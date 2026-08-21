#ifndef __IPX_WRAP_MUX_SPX_STATES_H__
#define __IPX_WRAP_MUX_SPX_STATES_H__

static __always_inline struct bpf_kspx_state *get_kspx_state(struct
		spx_conn_key *key)
{
	struct bpf_kspx_state *state =
		bpf_map_lookup_elem(&ipx_wrap_mux_kspx_state, key);
	if (state == NULL) {
		return NULL;
	}

	bpf_spin_lock(&(state->lock));

	return state;
}

static __always_inline void put_kspx_state(struct bpf_kspx_state *state)
{
	bpf_spin_unlock(&(state->lock));
}

#define ENTER_INGRESS(state_var) \
	bpf_printk("%s: begin", __func__); \
	\
	struct ethhdr *eth; \
	struct ipv6hdr *ip6h; \
	struct udphdr *udph; \
	struct ipxhdr *ipxh; \
	struct spxhdr *spxh; \
	void *data_end; \
	if (!get_ingress_pointers(skb, &eth, &ip6h, &udph, &ipxh, &spxh, \
				&data_end)) { \
		bpf_printk("%s: shot, failed to get pointers", __func__); \
		return TC_ACT_SHOT; \
	} \
	\
	size_t data_len = bpf_ntohs(ipxh->pktlen) - (sizeof(struct ipxhdr) + \
			sizeof(struct spxhdr)); \
	\
	struct spx_conn_key conn_key = { \
		.bind_addr = ipxh->daddr, \
		.conn_id = spxh->dst_conn_id \
	}; \
	struct bpf_kspx_state *spx_state = get_kspx_state(&conn_key); \
	if (spx_state == NULL) { \
		bpf_printk("%s: shot, failed to get state", __func__); \
		return TC_ACT_SHOT; \
	} \
	if (spx_state->state != state_var) { \
		/* This can happen if the state is changed immediately after \
		 * it was selected in the main program but before the \
		 * tail-call is called. There is nothing we can do here. */ \
		put_kspx_state(spx_state); \
		bpf_printk("%s: shot, unexpected state", __func__); \
		return TC_ACT_SHOT; \
	} \

#define EXIT_UNLOCKED_INGRESS(verdict, message) \
	bpf_printk("%s: " message, __func__); \
	return verdict;

#define EXIT_INGRESS(verdict, message) \
	put_kspx_state(spx_state); \
	EXIT_UNLOCKED_INGRESS(verdict, message)

#define ENTER_EGRESS(state_var) \
	bpf_printk("%s: begin", __func__); \
	\
	struct ethhdr *eth; \
	struct ipv6hdr *ip6h; \
	struct sctphdr *sctph; \
	struct sctp_chunkhdr *chunk1; \
	struct sctp_chunkhdr *chunk2; \
	void *data_end; \
	if (!get_egress_pointers(skb, &eth, &ip6h, &sctph, &chunk1, &chunk2, \
				&data_end)) { \
		bpf_printk("%s: shot, failed to get pointers", __func__); \
		return TC_ACT_SHOT; \
	} \
	\
	struct spx_conn_key conn_key; \
	if (!fill_conn_key(skb, &conn_key)) { \
		bpf_printk("%s: shot, failed to get connection key", \
				__func__); \
		return TC_ACT_SHOT; \
	} \
	\
	struct bpf_kspx_state *spx_state = get_kspx_state(&conn_key); \
	if (spx_state == NULL) { \
		/* SPX connection is already closed, the conn_key is stale */ \
		bpf_printk("%s: shot, failed to get state", __func__); \
		return TC_ACT_SHOT; \
	} \
	\
	if (spx_state->state != state_var) { \
		/* This can happen if the state is changed immediately after \
		 * it was selected in the main program but before the \
		 * tail-call is called. There is nothing we can do here. */ \
		put_kspx_state(spx_state); \
		bpf_printk("%s: shot, unexpected state", __func__); \
		return TC_ACT_SHOT; \
	}

#define EXIT_UNLOCKED_EGRESS(verdict, message) \
	bpf_printk("%s: " message, __func__); \
	return verdict;

#define EXIT_EGRESS(verdict, message) \
	put_kspx_state(spx_state); \
	EXIT_UNLOCKED_EGRESS(verdict, message)

#define GENERIC_INGRESS(state_name) \
	ENTER_INGRESS(KSPX_##state_name); \
	\
	if (!admit_ingress_##state_name(spx_state, spxh, data_len)) { \
		EXIT_INGRESS(TC_ACT_SHOT, "message rejected"); \
	} \
	\
	update_state_ingress_##state_name(spx_state, spxh, data_len); \
	\
	struct ingress_transform_info info = { \
		.sctp_sport = spx_state->sctp_sport, \
		.sctp_dport = spx_state->sctp_dport, \
		.sctp_svtag = spx_state->sctp_svtag, \
		.sctp_dvtag = spx_state->sctp_dvtag, \
		.sctp_tsn = spx_state->sctp_tsn, \
		.local_sequence_offset = spx_state->local_sequence_offset, \
		.local_current_sequence = spx_state->last_sent_sequence, \
		.outstanding_heartbeat_len = \
			spx_state->outstanding_heartbeat_len \
	}; \
	__builtin_memcpy(info.heartbeat_buf, spx_state->heartbeat_buf, \
			SCTP_MAX_HEARTBEAT_CHUNK_LEN); \
	/* we assume that if we have a waiting heartbeat, it will be sent \
	 * with the next chunk */ \
	spx_state->outstanding_heartbeat_len = 0; \
	put_kspx_state(spx_state); \
	if (!transform_ingress_##state_name(skb, spxh, data_len, &info)) { \
		EXIT_UNLOCKED_INGRESS(TC_ACT_SHOT, \
				"transformation failed"); \
	} \
	\
	int verdict = bpf_redirect(skb->ifindex, BPF_F_INGRESS); \
	EXIT_UNLOCKED_INGRESS(verdict, "end"); \
	//EXIT_UNLOCKED_INGRESS(TC_ACT_UNSPEC, "end");
	// TODO: ^ change the above back! ^

struct ingress_transform_info {
	__be16 sctp_sport;
	__be16 sctp_dport;
	__be32 sctp_svtag;
	__be32 sctp_dvtag;
	__u32 sctp_tsn;
	__u32 local_sequence_offset;
	__u16 local_current_sequence;
	__u16 outstanding_heartbeat_len;
	__u8 heartbeat_buf[SCTP_MAX_HEARTBEAT_CHUNK_LEN];
};

struct egress_transform_info {
	__be32 prefix;
	struct ipx_addr local_addr;
	struct ipx_addr remote_addr;
	__be16 local_id;
	__be16 remote_id;
	__u32 local_sequence_offset;
	__u16 local_current_sequence;
	__u16 remote_expected_sequence;
	__u16 local_alloc_no;
	__be16 sctp_sport;
	__be16 sctp_dport;
	__be32 sctp_dvtag;
};

static __always_inline bool admit_ingress_NEW(const struct bpf_kspx_state
		*spx_state, const struct spxhdr *spxh, size_t data_len)
{
	/* check if the packet fits with our connection state */
	if (spxh->dst_conn_id != spx_state->local_id) {
		return false;
	}
	if (spx_state->remote_id != SPX_CONN_ID_UNKNOWN && spxh->src_conn_id !=
			spx_state->remote_id) {
		return false;
	}

	/* only system packets are allowed in this state */
	if ((spxh->connection_control & SPX_CC_MASK_SPX) != SPX_CC_SYSTEM_PKT)
	{
		return false;
	}
	if (data_len != 0) {
		return false;
	}

	/* must be an initial connection ack packet */
	if (bpf_ntohs(spxh->seq_no) != 0 || bpf_ntohs(spxh->ack_no) != 0) {
		return false;
	}

	return true;
}

static __always_inline void update_state_ingress_NEW(struct bpf_kspx_state
		*spx_state, const struct spxhdr *spxh, size_t data_len)
{
	spx_state->remote_id = spxh->src_conn_id;
	spx_state->remote_alloc_no = spxh->alloc_no;
}

static __always_inline bool transform_ingress_NEW(struct __sk_buff *skb, struct
		spxhdr *spxh, size_t data_len, const struct
		ingress_transform_info *info)
{
	size_t sctp_len = sizeof(struct sctphdr) + sizeof(struct sctp_chunkhdr)
		+ sizeof(struct sctp_inithdr) + sizeof(struct sctp_paramhdr) +
		SCTP_STATE_COOKIE_LEN;

	/* make room for the SCTP header */
	__s32 oldhdrs_len = sizeof(struct udphdr) + sizeof(struct ipxhdr) +
		sizeof(struct spxhdr);
	__s32 len_diff = sctp_len - oldhdrs_len;
	size_t payload_len = sctp_len;
	if (bpf_skb_adjust_room(skb, len_diff, BPF_ADJ_ROOM_NET, 0) < 0) {
		return false;
	}
	bpf_skb_pull_data(skb, 0);

	/* adjust pointers and reverify */
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h = ((void *) eth) + sizeof(struct ethhdr);
	struct sctphdr *sctph = ((void *) ip6h) + sizeof(struct ipv6hdr);
	if (sctph + 1 > data_end) {
		return false;
	}
	/* calculate and verify length */
	if (payload_len < sctp_len) {
		return false;
	}
	if (payload_len > SCTP_MAX_PKT_LEN) {
		return false;
	}
	if (payload_len + sizeof(struct ipv6hdr) + sizeof(struct ethhdr) !=
			skb->len) {
		return false;
	}

	/* fill in the new headers */
	ip6h->nexthdr = IPPROTO_SCTP;
	ip6h->payload_len = bpf_htons(payload_len);
	sctph->vtag = info->sctp_dvtag;
	sctph->source = info->sctp_sport;
	sctph->dest = info->sctp_dport;
	sctph->checksum = bpf_htonl(0);

	/* create the init ack chunk */
	struct sctp_chunkhdr *chunk = (struct sctp_chunkhdr *) (sctph + 1);
	struct sctp_inithdr *init = (struct sctp_inithdr *) (chunk + 1);
	struct sctp_paramhdr *param = (struct sctp_paramhdr *) (init + 1);
	__u8 *cookie = (__u8 *) (param + 1);
	if (cookie + SCTP_STATE_COOKIE_LEN > data_end) {
		return false;
	}

	chunk->type = SCTP_CID_INIT_ACK;
	chunk->flags = 0;
	chunk->length = bpf_htons(sizeof(struct sctp_chunkhdr) + sizeof(struct
				sctp_inithdr) + sizeof(struct sctp_paramhdr) +
			SCTP_STATE_COOKIE_LEN);
	init->init_tag = info->sctp_svtag;
	init->a_rwnd = bpf_htonl(SCTP_RWND_DUMMY);
	init->num_inbound_streams = bpf_htons(1);
	init->num_outbound_streams = bpf_htons(1);
	init->initial_tsn = bpf_htonl(info->sctp_tsn);
	param->type = SCTP_PARAM_STATE_COOKIE;
	param->length = bpf_htons(sizeof(struct sctp_paramhdr) +
			SCTP_STATE_COOKIE_LEN);
	__u32 cval = bpf_get_prandom_u32();
_Static_assert(SCTP_STATE_COOKIE_LEN >= sizeof(cval),
		"SCTP state cookie too short");
	__builtin_memset(cookie, 0, SCTP_STATE_COOKIE_LEN);
	__builtin_memcpy(cookie, &cval, sizeof(cval));

	/* calculate CRC32c checksum */
	__u32 csum = 0;
	if (!sctp_csum_calc(sctph, data_end, payload_len, &csum)) {
		return false;
	}
	sctph->checksum = bpf_htonl(csum);

	return true;
}

static __always_inline bool admit_ingress_ESTABLISHED(const struct
		bpf_kspx_state *spx_state, const struct spxhdr *spxh, size_t
		data_len)
{
	bool system = (spxh->connection_control & SPX_CC_SYSTEM_PKT) != 0;
	bool ack_required = (spxh->connection_control & SPX_CC_ACK_REQUIRED) !=
		0;

	/* check if the packet fits with our connection state */
	if (spxh->dst_conn_id != spx_state->local_id || spxh->src_conn_id !=
			spx_state->remote_id) {
		return false;
	}

	/* handle the loss of ACK packets that we send by also acking data
	 * packets with a seq no lower than the current epxected one (but not
	 * letting them go through to SCTP) */
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

	return true;
}

static __always_inline void update_state_ingress_ESTABLISHED(struct
		bpf_kspx_state *spx_state, const struct spxhdr *spxh, size_t
		data_len)
{
	if (data_len != 0) {
		spx_state->last_rcvd_msg_data_len = data_len;
	}

	spx_state->remote_alloc_no = spxh->alloc_no;
}

static __always_inline bool transform_ingress_ESTABLISHED(struct __sk_buff
		*skb, struct spxhdr *spxh, size_t data_len, const struct
		ingress_transform_info *info)
{
	size_t sctp_len = sizeof(struct sctphdr);
	size_t chunk_start_ofs = sizeof(struct sctphdr);
	size_t sctp_padding_bytes = 0;
	__u32 spx_ack = bpf_ntohs(spxh->ack_no);

	/* also insert a HEARTBEAT_ACK chunk, if necessary */
	size_t hb_ack_ofs = 0;
	if (info->outstanding_heartbeat_len != 0) {
		hb_ack_ofs = sctp_len;

		size_t hb_ack_len = info->outstanding_heartbeat_len;
		if (hb_ack_len % 4 != 0) {
			hb_ack_len += 4 - (hb_ack_len % 4);
		}

		sctp_len += hb_ack_len;
		chunk_start_ofs += hb_ack_len;
	}

	sctp_len += sizeof(struct sctp_chunkhdr);
	if (data_len != 0) {
		/* room for a data chunk */
		sctp_len += sizeof(struct sctp_datahdr);
		sctp_padding_bytes = (data_len % 4 == 0) ? 0 : (4 - data_len %
				4);
	} else {
		/* room for a sack chunk */
		sctp_len += sizeof(struct sctp_sackhdr);
		sctp_padding_bytes = 0;
	}

	/* make room for the SCTP header */
	__s32 oldhdrs_len = sizeof(struct udphdr) + sizeof(struct ipxhdr) +
		sizeof(struct spxhdr);
	__s32 len_diff = sctp_len - oldhdrs_len;
	size_t payload_len = sctp_len + data_len + sctp_padding_bytes;
	if (bpf_skb_adjust_room(skb, len_diff, BPF_ADJ_ROOM_NET, 0) < 0) {
		return false;
	}
	if (bpf_skb_change_tail(skb, skb->len + sctp_padding_bytes, 0) < 0) {
		return false;
	}
	bpf_skb_pull_data(skb, 0);

	/* adjust pointers and reverify */
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h = ((void *) eth) + sizeof(struct ethhdr);
	struct sctphdr *sctph = ((void *) ip6h) + sizeof(struct ipv6hdr);
	if (sctph + 1 > data_end) {
		return false;
	}

	/* calculate and verify length */
	if (payload_len < sctp_len) {
		return false;
	}
	if (payload_len > SCTP_MAX_PKT_LEN) {
		return false;
	}
	if (payload_len + sizeof(struct ipv6hdr) + sizeof(struct ethhdr) !=
			skb->len) {
		return false;
	}

	/* fill in the new headers */
	ip6h->nexthdr = IPPROTO_SCTP;
	ip6h->payload_len = bpf_htons(payload_len);
	sctph->vtag = info->sctp_dvtag;
	sctph->source = info->sctp_sport;
	sctph->dest = info->sctp_dport;
	sctph->checksum = bpf_htonl(0);

	/* fill in the HEARTBEAT_ACK chunk if necessary */
	if (info->outstanding_heartbeat_len != 0) {
		/* FIXME: this exists solely to appease the verifier */
		if (hb_ack_ofs > SCTP_MAX_CHUNKSIZE * 2) {
			return false;
		}
		if (info->outstanding_heartbeat_len < sizeof(struct
					sctp_chunkhdr)) {
			return false;
		}
		if (info->outstanding_heartbeat_len >
				SCTP_MAX_HEARTBEAT_CHUNK_LEN) {
			return false;
		}

		if (((void *) sctph) + hb_ack_ofs > data_end) {
			return false;
		}

		struct sctp_chunkhdr *hb_ack_chunk = (struct sctp_chunkhdr *)
			(((void *) sctph) + hb_ack_ofs);
		if (((void *) hb_ack_chunk) + info->outstanding_heartbeat_len >
				data_end) {
			return false;
		}

		size_t i;
		for (i = 0; i < info->outstanding_heartbeat_len; i++) {
			/* FIXME: this is necessary to appease the verifier,
			 * but really sucks */
			if (i >= SCTP_MAX_HEARTBEAT_CHUNK_LEN) {
				return false;
			}
			barrier_var(i);
			if (((__u8 *) hb_ack_chunk) + (i + 1) > data_end) {
				return false;
			}

			((__u8 *) hb_ack_chunk)[i] = info->heartbeat_buf[i];
		}

		hb_ack_chunk->type = SCTP_CID_HEARTBEAT_ACK;
	}

	/* FIXME: this exists solely to appease the verifier */
	if (chunk_start_ofs > SCTP_MAX_CHUNKSIZE * 2) {
		return false;
	}
	struct sctp_chunkhdr *chunk = (struct sctp_chunkhdr *) (((void *)
				sctph) + chunk_start_ofs);
	if (data_len != 0) {
		/* create the data chunk */
		struct sctp_datahdr *data = (struct sctp_datahdr *) (chunk +
				1);
		if (data + 1 > data_end) {
			return false;
		}

		chunk->type = SCTP_CID_DATA;
		chunk->flags = (0 << 3) | /* I-bit */
			       (0 << 2) | /* U-bit */
			       (1 << 1) | /* B-bit */
			       (1 << 0) ; /* E-bit */
		chunk->length = bpf_htons(sizeof(struct sctp_chunkhdr) +
				sizeof(struct sctp_datahdr) + data_len);
		data->tsn = bpf_htonl(info->sctp_tsn);
		data->stream = bpf_htons(0);
		data->ssn = bpf_htons(info->sctp_tsn);
		data->ppid = bpf_htonl(0);
	} else {
		/* create the sack chunk */
		struct sctp_sackhdr *sack = (struct sctp_sackhdr *) (chunk +
				1);
		if (sack + 1 > data_end) {
			return false;
		}

		chunk->type = SCTP_CID_SACK;
		chunk->flags = 0;
		chunk->length = bpf_htons(sizeof(struct sctp_chunkhdr) +
				sizeof(struct sctp_sackhdr));
		/* subtract 1 from the ack no because SPX acks the "next
		 * expected" packet, while SCTP acks the "last seen" one */
		__builtin_sub_overflow(spx_ack, 1, &spx_ack);
		__u32 cum_tsn_ack;
		__builtin_add_overflow(info->local_sequence_offset, spx_ack,
				&cum_tsn_ack);
		/* compensate for old SPX acks */
		__u32 prev_cum_tsn_ack;
		__builtin_add_overflow(info->local_sequence_offset,
				info->local_current_sequence,
				&prev_cum_tsn_ack);
		// TODO: fix this condition
		/*if (spx_seq_less_than(spx_ack, info->local_current_sequence) &&
				sctp_tsn_less_than(cum_tsn_ack,
					prev_cum_tsn_ack)) {
			__builtin_sub_overflow(cum_tsn_ack, 0x10000,
					&cum_tsn_ack);
		}*/
		sack->cum_tsn_ack = bpf_htonl(cum_tsn_ack);
		sack->a_rwnd = bpf_htonl(SCTP_RWND_DUMMY);
		sack->num_gap_ack_blocks = bpf_htons(0);
		sack->num_dup_tsns = bpf_htons(0);
	}

	/* calculate CRC32c checksum */
	__u32 csum = 0;
	if (!sctp_csum_calc(sctph, data_end, payload_len, &csum)) {
		return false;
	}
	sctph->checksum = bpf_htonl(csum);

	return true;
}

static __always_inline bool admit_egress_NEW(const struct bpf_kspx_state
		*spx_state, const struct sctphdr *sctph, const struct
		sctp_chunkhdr *chunk1, void *data_end)
{
	if (chunk1 + 1 > data_end) {
		return false;
	}

	/* allow the init chunk */
	if (chunk1->type == SCTP_CID_INIT) {
		if (bpf_ntohs(chunk1->length) < sizeof(struct sctp_chunkhdr) +
				sizeof(struct sctp_inithdr)) {
			return false;
		}
		const struct sctp_inithdr *inith = (const struct sctp_inithdr
				*) (chunk1 + 1);
		if (inith + 1 > data_end) {
			return false;
		}

		return true;
	}

	/* otherwise only a correct cookie echo is allowed (we do not check the
	 * cookie though) */
	if (chunk1->type != SCTP_CID_COOKIE_ECHO) {
		return false;
	}

	if (sctph->source != spx_state->sctp_dport || sctph->dest !=
			spx_state->sctp_sport) {
		return false;
	}
	if (sctph->vtag != spx_state->sctp_svtag) {
		return false;
	}

	if (bpf_ntohs(chunk1->length) < sizeof(struct sctp_chunkhdr) +
			SCTP_STATE_COOKIE_LEN) {
		return false;
	}
	const __u8 *cookie = (const __u8 *) (chunk1 + 1);
	if (cookie + SCTP_STATE_COOKIE_LEN > data_end) {
		return false;
	}

	return true;
}

/* Note that while it can, this function should never return false. If it does,
 * there is a bug in the admit function, which should already check if the
 * packet contains all the info we need. The return value here exists only to
 * satisfy the verifier. */
static __always_inline bool update_state_egress_NEW(struct bpf_kspx_state
		*spx_state, const struct sctphdr *sctph, const struct
		sctp_chunkhdr *chunk1, void *data_end, __u32
		initial_source_vtag)
{
	/* have an INIT */
	if (chunk1->type == SCTP_CID_INIT) {
		const struct sctp_inithdr *inith = (const struct sctp_inithdr
				*) (chunk1 + 1);
		if (inith + 1 > data_end) {
			return false;
		}

		__be32 initial_vtag = inith->init_tag;
		__u32 initial_tsn = bpf_ntohl(inith->initial_tsn);

		spx_state->sctp_dvtag = initial_vtag;
		spx_state->sctp_svtag = bpf_htonl(initial_source_vtag);
		spx_state->sctp_sport = sctph->dest;
		spx_state->sctp_dport = sctph->source;
		spx_state->local_sequence_offset = initial_tsn;

		return true;
	}

	/* once we have the cookie echo, we are established */
	spx_state->state = KSPX_ESTABLISHED;

	return true;
}

static __always_inline bool transform_egress_NEW_cookie(struct __sk_buff *skb,
		struct sctphdr *sctph, struct sctp_chunkhdr *chunk1, const
		struct egress_transform_info *info)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h = ((void *) eth) + sizeof(struct ethhdr);
	if (ip6h + 1 > data_end) {
		return false;
	}

	/* swap Ethernet addrs */
	__u8 eth_dest_backup[ETH_ALEN];
	__builtin_memcpy(eth_dest_backup, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth_dest_backup, ETH_ALEN);

	/* swap the IPv6 addrs */
	struct in6_addr ip6_dest_backup;
	__builtin_memcpy(&ip6_dest_backup, &(ip6h->daddr), sizeof(struct
				in6_addr));
	__builtin_memcpy(&(ip6h->daddr), &(ip6h->saddr), sizeof(struct
				in6_addr));
	__builtin_memcpy(&(ip6h->saddr), &ip6_dest_backup, sizeof(struct
				in6_addr));

	/* adjust the payload length */
	size_t payload_len = sizeof(struct sctphdr) + sizeof(struct
			sctp_chunkhdr);
	ip6h->payload_len = bpf_htons(payload_len);

	/* create the SCTP cookie ack */
	sctph->source = info->sctp_sport;
	sctph->dest = info->sctp_dport;
	sctph->vtag = info->sctp_dvtag;
	sctph->checksum = bpf_htonl(0);
	chunk1->type = SCTP_CID_COOKIE_ACK;
	chunk1->flags = 0;
	chunk1->length = bpf_htons(sizeof(struct sctp_chunkhdr));

	/* calculate CRC32c checksum */
	__u32 csum = 0;
	if (!sctp_csum_calc(sctph, data_end, payload_len, &csum)) {
		return false;
	}
	sctph->checksum = bpf_htonl(csum);

	if (bpf_skb_change_tail(skb, payload_len + sizeof(struct ipv6hdr) +
				sizeof(struct ethhdr), 0) < 0) {
		return false;
	}

	/* mark the packet for reinjection so that the interface
	 * program accepts it */
	((struct bpf_cb_mark_info *) &(skb->cb[0]))->mark =
		SPX_TO_SCTP_REINJECT_MARK;

	return true;
}

static __always_inline bool transform_egress_NEW(struct __sk_buff *skb, struct
		sctphdr *sctph, struct sctp_chunkhdr *chunk1, const struct
		egress_transform_info *info)
{
	/* make room for the new headers */
	__s32 newhdrs_len = sizeof(struct udphdr) + sizeof(struct ipxhdr) +
		sizeof(struct spxhdr);
	__s32 oldhdrs_len = sizeof(struct sctphdr) + bpf_ntohs(chunk1->length);
	__s32 len_diff = newhdrs_len - oldhdrs_len;
	size_t payload_len = newhdrs_len;
	if (bpf_skb_adjust_room(skb, len_diff, BPF_ADJ_ROOM_NET, 0) < 0) {
		return false;
	}
	bpf_skb_pull_data(skb, 0);

	/* adjust pointers and reverify */
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h = ((void *) eth) + sizeof(struct ethhdr);
	struct udphdr *udph = ((void *) ip6h) + sizeof(struct ipv6hdr);
	struct ipxhdr *ipxh = ((void *) udph) + sizeof(struct udphdr);
	struct spxhdr *spxh = ((void *) ipxh) + sizeof(struct ipxhdr);
	if (spxh + 1 > data_end) {
		return false;
	}

	/* calculate and verify length */
	if (payload_len + sizeof(struct ipv6hdr) + sizeof(struct ethhdr) !=
			skb->len) {
		return false;
	}

	/* fill in IPv6 header */
	ip6h->payload_len = bpf_htons(payload_len);
	ip6h->nexthdr = IPPROTO_UDP;

	struct ipv6_eui64_addr *ip6_saddr = (struct ipv6_eui64_addr *)
		&(ip6h->saddr);
	ip6_saddr->prefix = info->prefix;
	ip6_saddr->ipx_net = info->local_addr.net;
	__builtin_memcpy(ip6_saddr->ipx_node_fst, info->local_addr.node,
			IPX_ADDR_NODE_BYTES / 2);
	ip6_saddr->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(ip6_saddr->ipx_node_snd, &(info->local_addr.node[3]),
			IPX_ADDR_NODE_BYTES / 2);

	struct ipv6_eui64_addr *ip6_daddr = (struct ipv6_eui64_addr *)
		&(ip6h->daddr);
	ip6_daddr->prefix = info->prefix;
	ip6_daddr->ipx_net = info->remote_addr.net;
	__builtin_memcpy(ip6_daddr->ipx_node_fst, info->remote_addr.node,
			IPX_ADDR_NODE_BYTES / 2);
	ip6_daddr->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(ip6_daddr->ipx_node_snd, &(info->remote_addr.node[3]),
			IPX_ADDR_NODE_BYTES / 2);

	/* fill in the UDP header. */
	udph->source = bpf_htons(IPX_IN_IPV6_PORT);
	udph->dest = bpf_htons(IPX_IN_IPV6_PORT);
	/* we do not care about the UDP checksum here because the outer eBPF
	 * program discards the UDP header anyway */
	// TODO: calculate the UDP checksum properly
	udph->check = bpf_htons(0xdead);
	udph->len = bpf_htons(payload_len);

	/* fill in the IPX header */
	ipxh->csum = IPX_CSUM_NONE;
	ipxh->pktlen = bpf_htons(payload_len - sizeof(struct udphdr));
	ipxh->tc = 0;
	ipxh->type = SPX_PKT_TYPE;
	ipxh->daddr = info->remote_addr;
	ipxh->saddr = info->local_addr;

	/* fill in the SPX header */
	spxh->connection_control = SPX_CC_SYSTEM_PKT | SPX_CC_ACK_REQUIRED;
	spxh->datastream_type = SPX_DS_NONE;
	spxh->src_conn_id = info->local_id;
	spxh->dst_conn_id = info->remote_id;
	spxh->seq_no = bpf_htons(0);
	spxh->ack_no = bpf_htons(info->remote_expected_sequence);
	spxh->alloc_no = bpf_htons(info->local_alloc_no);

	return true;
}

static __always_inline bool admit_egress_ESTABLISHED(const struct
		bpf_kspx_state *spx_state, const struct sctphdr *sctph, const
		struct sctp_chunkhdr *chunk1, void *data_end)
{
	if (sctph->source != spx_state->sctp_dport || sctph->dest !=
			spx_state->sctp_sport) {
		return false;
	}
	if (sctph->vtag != spx_state->sctp_svtag) {
		return false;
	}

	return true;
}

static __always_inline bool update_state_egress_ESTABLISHED(struct
		bpf_kspx_state *spx_state, const struct sctphdr *sctph, const
		struct sctp_chunkhdr *chunk1, void *data_end)
{
	/* HEARTBEAT chunk */
	if (chunk1->type == SCTP_CID_HEARTBEAT) {
		size_t heartbeat_len = bpf_ntohs(chunk1->length);
		/* verifier hack */
		asm volatile("%0 &= 0xffff" : "=r"(heartbeat_len) :
				"0"(heartbeat_len));
		if (heartbeat_len > SCTP_MAX_HEARTBEAT_CHUNK_LEN) {
			return false;
		}
		if (heartbeat_len < sizeof(struct sctp_chunkhdr)) {
			return false;
		}

		/* FIXME: clang optimizes away this crucial check because it
		 * already did it during parsing, see below */
		if (((void *) chunk1) + heartbeat_len > data_end) {
			return false;
		}

		size_t i;
		for (i = 0; i < heartbeat_len; i++) {
			/* FIXME: this is necessary to appease the verifier,
			 * but really sucks */
			barrier_var(i);
			if (((__u8 *) chunk1) + (i + 1) > data_end) {
				return false;
			}
			spx_state->heartbeat_buf[i] = ((__u8 *) chunk1)[i];
		}

		spx_state->outstanding_heartbeat_len = heartbeat_len;

		return true;
	}

	/* SACK chunk */
	if (chunk1->type == SCTP_CID_SACK) {
		const struct sctp_sackhdr *sackh = (const struct sctp_sackhdr
				*) (chunk1 + 1);
		if (sackh + 1 > data_end) {
			return false;
		}

		__u32 tsn_ack = bpf_ntohl(sackh->cum_tsn_ack);
		/* last message has been acknowledged by SCTP */
		if (spx_state->sctp_tsn == tsn_ack) {
			__builtin_add_overflow(
					spx_state->remote_expected_sequence, 1,
					&(spx_state->remote_expected_sequence));
			__builtin_add_overflow(spx_state->local_alloc_no, 1,
					&(spx_state->local_alloc_no));
			__builtin_add_overflow(spx_state->sctp_tsn, 1,
					&(spx_state->sctp_tsn));
		}

		return true;
	}

	/* we can only handle SACK, HEARTBEAT and DATA chunks right now */
	if (chunk1->type != SCTP_CID_DATA) {
		return true; /* no state modification */
	}

	/* DATA chunk */
	const struct sctp_datahdr *datah = (const struct sctp_datahdr *)
		(chunk1 + 1);
	if (datah + 1 > data_end) {
		return false;
	}

	/* if the SPX seq no increased but the total TSN decreased, we assume
	 * the SPX seq no wrapped and increase the TSN offset */
	__u32 cur_tsn = bpf_ntohl(datah->tsn);
	__u32 prev_tsn;
	__builtin_add_overflow(spx_state->local_sequence_offset,
			spx_state->last_sent_sequence, &prev_tsn);
	__u32 spx_sequence_u32;
	__builtin_sub_overflow(cur_tsn, spx_state->local_sequence_offset,
			&spx_sequence_u32);
	__u16 spx_sequence_u16 = spx_sequence_u32;
	if (spx_seq_less_than(spx_state->last_sent_sequence, spx_sequence_u16)
			&& sctp_tsn_less_than(cur_tsn, prev_tsn)) {
		__builtin_add_overflow(spx_state->local_sequence_offset,
				0x10000, &(spx_state->local_sequence_offset));
	}
	spx_state->last_sent_sequence = spx_sequence_u16;

	return true;
}

static __always_inline bool transform_egress_ESTABLISHED(struct __sk_buff *skb,
		struct sctphdr *sctph, struct sctp_chunkhdr *chunk1, const
		struct egress_transform_info *info)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
	sctph = ((void *) ip6h) + sizeof(struct ipv6hdr);
	chunk1 = ((void *) sctph) + sizeof(struct sctphdr);
	if (chunk1 + 1 > data_end) {
		return false;
	}

	/* we can only handle SACK, HEARTBEAT and DATA chunks right now */
	if (chunk1->type != SCTP_CID_SACK && chunk1->type != SCTP_CID_DATA &&
			chunk1->type != SCTP_CID_HEARTBEAT) {
		bpf_printk("unknown chunk type %d", chunk1->type);
		return false; /* drop only this chunk */
	}

	size_t data_ofs = 0;
	size_t padding_bytes = 0;
	__u8 connection_control = 0;
	__u8 datastream_type = SPX_DS_NONE;
	__u16 seq_no = info->local_current_sequence;

	/* SACK chunk */
	if (chunk1->type == SCTP_CID_SACK) {
		data_ofs = data_end - ((void *) sctph);

		connection_control = SPX_CC_SYSTEM_PKT;
		datastream_type = SPX_DS_NONE;

	/* HEARTBEAT chunk */
	} else if (chunk1->type == SCTP_CID_HEARTBEAT) {
		data_ofs = data_end - ((void *) sctph);

		connection_control = SPX_CC_SYSTEM_PKT | SPX_CC_ACK_REQUIRED;
		datastream_type = SPX_DS_NONE;

	/* DATA chunk */
	} else {
		struct sctp_datahdr *datah = ((void *) chunk1) + sizeof(struct
				sctp_chunkhdr);
		if (datah + 1 > data_end) {
			return false;
		}

		size_t data_overhead = sizeof(struct sctp_chunkhdr) +
			sizeof(struct sctp_datahdr);
		size_t chunk_len = bpf_ntohs(chunk1->length);
		data_ofs = (((void *) chunk1) - ((void *) sctph)) +
			data_overhead;
		void *first_data_end = ((void *) chunk1) + chunk_len;
		padding_bytes = data_end - first_data_end;

		connection_control = SPX_CC_ACK_REQUIRED;
		datastream_type = SPX_DS_NONE;
		__builtin_sub_overflow(bpf_ntohl(datah->tsn),
				info->local_sequence_offset, &seq_no);
		bpf_printk("tsn: %u", bpf_ntohl(datah->tsn));
	}

	/* make room for the new headers */
	__s32 newhdrs_len = sizeof(struct udphdr) + sizeof(struct ipxhdr) +
		sizeof(struct spxhdr);
	__s32 len_diff = newhdrs_len - data_ofs;
	size_t payload_len = bpf_ntohs(ip6h->payload_len) + len_diff -
		padding_bytes;
	if (bpf_skb_adjust_room(skb, len_diff, BPF_ADJ_ROOM_NET, 0) < 0) {
		return false;
	}
	if (bpf_skb_change_tail(skb, payload_len + sizeof(struct ipv6hdr) +
				sizeof(struct ethhdr), 0) < 0) {
		return false;
	}
	bpf_skb_pull_data(skb, 0);

	/* adjust pointers and reverify */
	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;

	struct ethhdr *eth = data;
	ip6h = ((void *) eth) + sizeof(struct ethhdr);
	struct udphdr *udph = ((void *) ip6h) + sizeof(struct ipv6hdr);
	struct ipxhdr *ipxh = ((void *) udph) + sizeof(struct udphdr);
	struct spxhdr *spxh = ((void *) ipxh) + sizeof(struct ipxhdr);
	if (spxh + 1 > data_end) {
		return false;
	}

	/* calculate and verify length */
	if (payload_len < sizeof(struct udphdr) + sizeof(struct ipxhdr) +
			sizeof(struct spxhdr)) {
		return false;
	}
	if (payload_len > MAX_DGRAM_LEN) {
		return false;
	}
	if (payload_len + sizeof(struct ipv6hdr) + sizeof(struct ethhdr) !=
			skb->len) {
		return false;
	}

	/* fill in IPv6 header */
	ip6h->payload_len = bpf_htons(payload_len);
	ip6h->nexthdr = IPPROTO_UDP;

	struct ipv6_eui64_addr *ip6_saddr = (struct ipv6_eui64_addr *)
		&(ip6h->saddr);
	ip6_saddr->prefix = info->prefix;
	ip6_saddr->ipx_net = info->local_addr.net;
	__builtin_memcpy(ip6_saddr->ipx_node_fst, info->local_addr.node,
			IPX_ADDR_NODE_BYTES / 2);
	ip6_saddr->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(ip6_saddr->ipx_node_snd, &(info->local_addr.node[3]),
			IPX_ADDR_NODE_BYTES / 2);

	struct ipv6_eui64_addr *ip6_daddr = (struct ipv6_eui64_addr *)
		&(ip6h->daddr);
	ip6_daddr->prefix = info->prefix;
	ip6_daddr->ipx_net = info->remote_addr.net;
	__builtin_memcpy(ip6_daddr->ipx_node_fst, info->remote_addr.node,
			IPX_ADDR_NODE_BYTES / 2);
	ip6_daddr->fffe = bpf_htons(0xfffe);
	__builtin_memcpy(ip6_daddr->ipx_node_snd, &(info->remote_addr.node[3]),
			IPX_ADDR_NODE_BYTES / 2);

	/* fill in the UDP header. */
	udph->source = bpf_htons(IPX_IN_IPV6_PORT);
	udph->dest = bpf_htons(IPX_IN_IPV6_PORT);
	/* we do not care about the UDP checksum here because the outer eBPF
	 * program discards the UDP header anyway */
	// TODO: calculate the UDP checksum properly
	udph->check = bpf_htons(0xdead);
	udph->len = bpf_htons(payload_len);

	/* fill in the IPX header */
	ipxh->csum = IPX_CSUM_NONE;
	ipxh->pktlen = bpf_htons(payload_len - sizeof(struct udphdr));
	ipxh->tc = 0;
	ipxh->type = SPX_PKT_TYPE;
	ipxh->daddr = info->remote_addr;
	ipxh->saddr = info->local_addr;

	/* fill in the SPX header */
	spxh->connection_control = connection_control;
	spxh->datastream_type = datastream_type;
	spxh->src_conn_id = info->local_id;
	spxh->dst_conn_id = info->remote_id;
	spxh->seq_no = bpf_htons(seq_no);
	spxh->ack_no = bpf_htons(info->remote_expected_sequence);
	spxh->alloc_no = bpf_htons(info->local_alloc_no);

	return true;
}

SEC("tc/ingress")
int kspx_state_ingress_INVALID(struct __sk_buff *skb)
{
	bpf_printk("%s: shot", __func__);
	return TC_ACT_SHOT;
}

SEC("tc/egress")
int kspx_state_egress_INVALID(struct __sk_buff *skb)
{
	bpf_printk("%s: shot", __func__);
	return TC_ACT_SHOT;
}

SEC("tc/ingress")
int kspx_state_ingress_NEW(struct __sk_buff *skb)
{
	GENERIC_INGRESS(NEW);
}

SEC("tc/egress")
int kspx_state_egress_NEW(struct __sk_buff *skb)
{
	__u32 initial_source_vtag = bpf_get_prandom_u32();

	ENTER_EGRESS(KSPX_NEW);

	if (!admit_egress_NEW(spx_state, sctph, chunk1, data_end)) {
		EXIT_EGRESS(TC_ACT_SHOT, "message rejected");
	}

	if (!update_state_egress_NEW(spx_state, sctph, chunk1, data_end,
				initial_source_vtag)) {
		EXIT_EGRESS(TC_ACT_SHOT,
				"state update failed (this is a BUG!)");
	}

	struct egress_transform_info info = {
		.prefix = spx_state->prefix,
		.local_addr = spx_state->local_addr,
		.remote_addr = spx_state->remote_addr,
		.local_id = spx_state->local_id,
		.remote_id = spx_state->remote_id,
		.local_sequence_offset = spx_state->local_sequence_offset,
		.local_current_sequence = 0,
		.remote_expected_sequence =
			spx_state->remote_expected_sequence,
		.local_alloc_no = spx_state->local_alloc_no,
		.sctp_sport = spx_state->sctp_sport,
		.sctp_dport = spx_state->sctp_dport,
		.sctp_dvtag = spx_state->sctp_dvtag
	};
	put_kspx_state(spx_state);

	/* init chunk */
	if (chunk1->type == SCTP_CID_INIT) {
		if (!transform_egress_NEW(skb, sctph, chunk1, &info)) {
			EXIT_UNLOCKED_EGRESS(TC_ACT_SHOT,
					"transformation failed");
		}
		EXIT_UNLOCKED_EGRESS(TC_ACT_UNSPEC, "end");
	}

	/* cookie echo chunk */
	if (!transform_egress_NEW_cookie(skb, sctph, chunk1, &info)) {
		EXIT_UNLOCKED_EGRESS(TC_ACT_SHOT, "transformation failed");
	}
	int verdict = bpf_redirect(skb->ifindex, BPF_F_INGRESS);
	EXIT_UNLOCKED_EGRESS(verdict, "end");
}

SEC("tc/ingress")
int kspx_state_ingress_ESTABLISHED(struct __sk_buff *skb)
{
	GENERIC_INGRESS(ESTABLISHED);
}

SEC("tc/egress")
int kspx_state_egress_ESTABLISHED(struct __sk_buff *skb)
{
	ENTER_EGRESS(KSPX_ESTABLISHED);

	if (!admit_egress_ESTABLISHED(spx_state, sctph, chunk1, data_end)) {
		EXIT_EGRESS(TC_ACT_SHOT, "message rejected");
	}

	if (!update_state_egress_ESTABLISHED(spx_state, sctph, chunk1,
				data_end)) {
		EXIT_EGRESS(TC_ACT_SHOT,
				"state update failed (this is a BUG!)");
	}

	struct egress_transform_info info = {
		.prefix = spx_state->prefix,
		.local_addr = spx_state->local_addr,
		.remote_addr = spx_state->remote_addr,
		.local_id = spx_state->local_id,
		.remote_id = spx_state->remote_id,
		.local_sequence_offset = spx_state->local_sequence_offset,
		.local_current_sequence = spx_state->last_sent_sequence,
		.remote_expected_sequence =
			spx_state->remote_expected_sequence,
		.local_alloc_no = spx_state->local_alloc_no,
		.sctp_sport = spx_state->sctp_sport,
		.sctp_dport = spx_state->sctp_dport,
		.sctp_dvtag = spx_state->sctp_dvtag
	};
	put_kspx_state(spx_state);

	if (!transform_egress_ESTABLISHED(skb, sctph, chunk1, &info)) {
		EXIT_UNLOCKED_EGRESS(TC_ACT_SHOT, "transformation failed");
	}
	EXIT_UNLOCKED_EGRESS(TC_ACT_UNSPEC, "end");
}

#endif /* __IPX_WRAP_MUX_SPX_STATES_H__ */
