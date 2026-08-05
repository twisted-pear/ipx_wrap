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

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct spx_conn_key);
	__type(value, __u64);
	__uint(max_entries, SPX_SOCKETS_MAX);
	//__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_kspx_sock_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct spx_conn_key);
	__type(value, struct bpf_kspx_wait_for_conn_ack);
	__uint(max_entries, SPX_SOCKETS_MAX);
} ipx_wrap_mux_kspx_outstanding_conn_acks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__type(key, __u32);
	__type(value, struct bpf_kspx_state);
	__uint(max_entries, 0);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipx_wrap_mux_kspx_state SEC(".maps");

SEC("tc/ingress")
int ipx_wrap_spx_demux(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct hdr_cursor cur;
	cur.pos = data;

	/* TODO: intercept TCP segments to one of our managed sockets */

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

	bpf_printk("net inspxprog: %08x", bpf_ntohl(ipxh->saddr.net));

	if (ipxh->type != SPX_PKT_TYPE) {
		return TC_ACT_UNSPEC;
	}
	if (cur.pos + sizeof(struct spxhdr) > data_end) {
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

	struct bpf_sock *spx_sock = NULL;
	spx_sock = bpf_map_lookup_elem(&ipx_wrap_mux_kspx_sock_ingress,
			&conn_key);
	if (spx_sock == NULL) {
		/* no SPX socket, check if we are waiting for a conn ack */
		struct bpf_kspx_wait_for_conn_ack *wait_conn_ack = NULL;
		wait_conn_ack = bpf_map_lookup_elem(
				&ipx_wrap_mux_kspx_outstanding_conn_acks,
				&conn_key);
		if (wait_conn_ack == NULL) {
			return TC_ACT_UNSPEC;
		}

		/* conn ack, do something with it */
		bpf_printk("got conn ack for ID %04x", spxh->dst_conn_id);
		// TODO

		return TC_ACT_UNSPEC;
	}

	// TODO
	bpf_sk_release(spx_sock);

	return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int ipx_wrap_spx_mux(struct __sk_buff *skb)
{
	struct bpf_sock *client_sock = skb->sk;
	if (client_sock == NULL) {
		bpf_printk("notsock");
		return TC_ACT_UNSPEC;
	}

	struct bpf_kspx_state *spx_state =
		bpf_sk_storage_get(&ipx_wrap_mux_kspx_state, client_sock, NULL,
				0);
	if (spx_state == NULL) {
		bpf_printk("notstate");
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
		bpf_printk("shot: not eth");
		return TC_ACT_SHOT;
	}
	/* packet already is a proper IPX packet, just allow it through */
	if (bpf_ntohs(eth->h_proto) == ETH_P_IPX) {
		bpf_printk("unspec: already IPX");
		return TC_ACT_UNSPEC;
	}
	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6) {
		bpf_printk("shot: not ipv6");
		return TC_ACT_SHOT;
	}

	struct ipv6hdr *ip6h;
	if (parse_ip6hdr(&cur, data_end, &ip6h) < 0) {
		bpf_printk("shot: not ipv6 2");
		return TC_ACT_SHOT;
	}
	if (ip6h->nexthdr != IPPROTO_TCP) {
		//bpf_printk("shot: not tcp");
		//return TC_ACT_SHOT;
		bpf_printk("unspec: not tcp");
		return TC_ACT_UNSPEC;
	}

	struct tcphdr *tcph;
	int tcph_len = parse_tcphdr(&cur, data_end, &tcph);
	if (tcph_len < 0) {
		bpf_printk("shot: not tcp 2");
		return TC_ACT_SHOT;
	}

	bpf_printk("tcph len: %d", tcph_len);

	/* check the connection state */
	__u8 connection_control = 0;
	__u8 datastream_type = SPX_DS_NONE;
	struct bpf_kspx_wait_for_conn_ack wait_conn_ack;
	switch (spx_state->state) {
		case KSPX_NEW:
			/* a new connection only gets to send SYN segments */
			if ((tcp_flag_word(tcph) & ~(TCP_RESERVED_BITS |
							TCP_DATA_OFFSET |
							TCP_WINDOW)) !=
					TCP_FLAG_SYN) {
				bpf_printk("not syn: %08x",
						(tcp_flag_word(tcph) &
						 ~(TCP_RESERVED_BITS |
							 TCP_DATA_OFFSET |
							 TCP_WINDOW)));
				return TC_ACT_SHOT;
			}

			/* we want to send an SPX connection request */
			connection_control = SPX_CC_SYSTEM_PKT |
				SPX_CC_ACK_REQUIRED;
			datastream_type = SPX_DS_NONE;

			/* we need to prepare the structure for receiving the
			 * appropriate connection ack */
			wait_conn_ack.tcp_sport = tcph->dest;
			wait_conn_ack.tcp_dport = tcph->source;
			__u32 tcp_ack;
			__builtin_add_overflow(bpf_ntohl(tcph->seq), 1,
					&tcp_ack);
			wait_conn_ack.tcp_ack = bpf_htonl(tcp_ack);
			break;
		default:
			bpf_printk("shot: inavlid state");
			return TC_ACT_SHOT;
	}

	/* back up Ethernet header */
	struct ethhdr eth_backup;
	__builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));

	/* make room for the new headers */
	__s32 newhdrs_len = sizeof(struct udphdr) + sizeof(struct ipxhdr) +
		sizeof(struct spxhdr);
	__s32 len_diff = newhdrs_len - tcph_len;
	size_t payload_len = bpf_ntohs(ip6h->payload_len) + len_diff;
	if (bpf_skb_adjust_room(skb, -tcph_len, BPF_ADJ_ROOM_NET, 0) < 0) {
		bpf_printk("shot: adjust room");
		return TC_ACT_SHOT;
	}
	/* we have to do a change_tail here instead of an adjust room, so that
	 * offloading gets reset */
	if (bpf_skb_change_tail(skb, skb->len + newhdrs_len, 0) < 0) {
		bpf_printk("shot: change tail");
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
		bpf_printk("shot: not enough room");
		return TC_ACT_SHOT;
	}

	/* calculate and verify length */
	if (payload_len < sizeof(struct udphdr) + sizeof(struct ipxhdr) +
			sizeof(struct spxhdr)) {
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

	/* restore the Ethernet header */
	__builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));

	/* fill in IPv6 header */
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
	/* TODO: calculate the UDP checksum properly */
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

	bpf_printk("net spxprog: %08x", bpf_ntohl(ipxh->daddr.net));

	/* insert the structure for the connection ack into the map */
	if (spx_state->state == KSPX_NEW) {
		struct spx_conn_key conn_key = {
			.bind_addr = spx_state->local_addr,
			.conn_id = spx_state->local_id
		};

		if (bpf_map_update_elem(
					&ipx_wrap_mux_kspx_outstanding_conn_acks,
					&conn_key, &wait_conn_ack, BPF_ANY) <
				0) {
			bpf_printk("conn req shot");
			return TC_ACT_SHOT;
		}
		bpf_printk("conn req sent");
	}

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
