/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "ipx_wrap_common_kern.h"
#include "ipx_wrap_common_proto.h"

#define AF_INET6 10

#define IPX_SOCKETS_MAX	32768

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

	if (cur.pos + sizeof(struct ipxw_mux_msg_min) > data_end) {
		return TC_ACT_UNSPEC;
	}

	/* determine if the packet is for the local machine */
	struct bpf_fib_lookup fib_params;
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
	} else if (fib_res == BPF_FIB_LKUP_RET_NOT_FWDED) {
		cb.is_for_local = true;
	} else {
		bpf_printk("FIB_lookup failed %d", fib_res);
		return TC_ACT_UNSPEC;
	}

	struct ipxw_mux_msg_min *mux_msg = cur.pos;
	struct ipxhdr *ipxh = &(mux_msg->ipxh);

	struct bpf_bind_entry *e = NULL;

	if (cb.is_bcast && cb.is_for_local) {
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

	/* no bindging entry */
	if (e == NULL) {
		/* if packet was for the local machine, drop it */
		if (cb.is_for_local) {
			bpf_printk("no bind entry for local machine");
			return TC_ACT_SHOT;
		}

		/* else handle the packet normally (i.e. route it) */
		bpf_printk("packet is not for this machine, handle normally");
		return TC_ACT_UNSPEC;
	}

	/* packet is destined for the local machine */

	if (cb.is_bcast && !e->recv_bcast) {
		bpf_printk("not interested in broadcast packet");
		return TC_ACT_SHOT;
	}

	/* check packet type */
	if (ipxh->type != e->pkt_type && !e->pkt_type_any) {
		bpf_printk("packet type mismatch");
		return TC_ACT_SHOT;
	}

	struct bpf_sock *sock = bpf_map_lookup_elem(&ipx_wrap_mux_sock_ingress,
			&(e->addr));
	if (sock == NULL) {
		bpf_printk("no socket found");
		return TC_ACT_SHOT;
	}

	long err = bpf_sk_assign(skb, sock, 0);
	if (err != 0) {
		bpf_printk("failed to assign socket: %d", err);
		bpf_sk_release(sock);
		return TC_ACT_SHOT;
	}
	bpf_sk_release(sock);

	bpf_printk("socket assigned!");

	struct ipx_addr saddr = ipxh->saddr;
	__u8 pkt_type = ipxh->type;

	/* extract the correct data length */
	__u16 data_len = bpf_ntohs(ipxh->pktlen);
	if (data_len + sizeof(struct udphdr) + sizeof(struct ipv6hdr) +
			sizeof(struct ethhdr) != skb->len) {
		return TC_ACT_SHOT;
	}
	if (data_len < sizeof(struct ipxw_mux_msg_min)) {
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
	__builtin_memset(mux_msg, 0, sizeof(struct ipxw_mux_msg_min));

	/* rewrite to recv msg */
	mux_msg->type = IPXW_MUX_RECV;
	mux_msg->recv.saddr = saddr;
	mux_msg->recv.pkt_type = pkt_type;
	mux_msg->recv.is_bcast = cb.is_bcast;
	mux_msg->recv.data_len = data_len;

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

	/* insert the modified checksum */
	__u32 csum_ofs = ((void *) &(udph->check)) - data;
	if (bpf_l4_csum_replace(skb, csum_ofs, 0, csum_diff, BPF_F_PSEUDO_HDR)
			!= 0) {
		return TC_ACT_SHOT;
	}

	bpf_printk("packet demuxed!");

	return TC_ACT_OK;
}

SEC("tc/egress")
int ipx_wrap_mux(struct __sk_buff *skb)
{
	bpf_printk("mux hit");

	struct bpf_sock *client_sock = skb->sk;
	/* no source socket, do nothing */
	if (client_sock == NULL) {
		return TC_ACT_UNSPEC;
	}

	struct ipx_addr *bind_addr =
		bpf_sk_storage_get(&ipx_wrap_mux_bind_egress, client_sock,
				NULL, 0);
	/* not one of our client sockets, do nothing */
	if (bind_addr == NULL) {
		return TC_ACT_UNSPEC;
	}

	/* get the bind entry */
	struct bpf_bind_entry *e =
		bpf_map_lookup_elem(&ipx_wrap_mux_bind_entries_uc, bind_addr);
	if (e == NULL) {
		return TC_ACT_SHOT;
	}

	bpf_printk("socket found!");

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

	if (cur.pos + sizeof(struct ipxw_mux_msg_min) > data_end) {
		return TC_ACT_SHOT;
	}

	bpf_printk("packet parsed");

	/* verify the xmit message against the bind entry */
	struct ipxw_mux_msg_min *mux_msg = cur.pos;
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

	bpf_printk("packet verified");

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

	bpf_printk("packet built");

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
