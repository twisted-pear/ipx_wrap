#ifndef __IPX_WRAP_MUX_SPX_STATES_H__
#define __IPX_WRAP_MUX_SPX_STATES_H__

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

#define PREAMBLE_INGRESS(state_var) \
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
		 *  it was selected in the main program but before the \
		 *  tail-call is called. There is nothing we can do here. */ \
		put_kspx_state(spx_state); \
		bpf_printk("%s: shot, unexpected state", __func__); \
		return TC_ACT_SHOT; \
	} \

#define POSTAMBLE_UNLOCKED_INGRESS(verdict, message) \
	bpf_printk("%s: " message, __func__); \
	return verdict;

#define POSTAMBLE_INGRESS(verdict, message) \
	put_kspx_state(spx_state); \
	POSTAMBLE_UNLOCKED_INGRESS(verdict, message)

#define GENERIC_INGRESS(state_name) \
	PREAMBLE_INGRESS(KSPX_##state_name); \
	\
	if (!admit_ingress_##state_name(spx_state, spxh, data_len)) { \
		POSTAMBLE_INGRESS(TC_ACT_SHOT, "message rejected"); \
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
		.sctp_tsn_ack = spx_state->sctp_tsn_ack \
	}; \
	put_kspx_state(spx_state); \
	if (!transform_ingress_##state_name(skb, spxh, data_len, &info)) { \
		POSTAMBLE_UNLOCKED_INGRESS(TC_ACT_SHOT, \
				"transformation failed"); \
	} \
	\
	int verdict = bpf_redirect(skb->ifindex, BPF_F_INGRESS); \
	POSTAMBLE_UNLOCKED_INGRESS(verdict, "end"); \
	//POSTAMBLE_UNLOCKED_INGRESS(TC_ACT_UNSPEC, "end");

struct ingress_transform_info {
	__be16 sctp_sport;
	__be16 sctp_dport;
	__be32 sctp_svtag;
	__be32 sctp_dvtag;
	__u32 sctp_tsn;
	__u32 sctp_tsn_ack;
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
	return false;
}

static __always_inline void update_state_ingress_ESTABLISHED(struct
		bpf_kspx_state *spx_state, const struct spxhdr *spxh, size_t
		data_len)
{
}

static __always_inline bool transform_ingress_ESTABLISHED(struct __sk_buff
		*skb, struct spxhdr *spxh, size_t data_len, const struct
		ingress_transform_info *info)
{
	return false;
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
	bpf_printk("%s: begin", __func__);
	bpf_printk("%s: end", __func__);
	return TC_ACT_SHOT;
}

SEC("tc/ingress")
int kspx_state_ingress_ESTABLISHED(struct __sk_buff *skb)
{
	GENERIC_INGRESS(ESTABLISHED);
}

SEC("tc/egress")
int kspx_state_egress_ESTABLISHED(struct __sk_buff *skb)
{
	bpf_printk("%s: begin", __func__);
	bpf_printk("%s: end", __func__);
	return TC_ACT_SHOT;
}

#endif /* __IPX_WRAP_MUX_SPX_STATES_H__ */
