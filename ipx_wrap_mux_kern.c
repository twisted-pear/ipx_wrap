/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "ipx_wrap_common_kern.h"
#include "ipx_wrap_common_proto.h"

#define AF_INET6 10

#define IPX_SOCKETS_MAX	32768

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

static bool __always_inline is_to_managed_sock(struct __sk_buff *skb, struct
		ipv6hdr *ip6h, struct udphdr *udph)
{
	struct bpf_sock_tuple udp_sock_tuple;
	__builtin_memset(&udp_sock_tuple, 0, sizeof(struct bpf_sock_tuple));
	udp_sock_tuple.ipv6.sport = udph->source;
	udp_sock_tuple.ipv6.dport = udph->dest;
	__builtin_memcpy(udp_sock_tuple.ipv6.saddr, &(ip6h->saddr),
			sizeof(ip6h->saddr));
	__builtin_memcpy(udp_sock_tuple.ipv6.daddr, &(ip6h->daddr),
			sizeof(ip6h->daddr));

	/* get the probable target socket */
	struct bpf_sock *probable_target_sock = bpf_sk_lookup_udp(skb,
			&udp_sock_tuple, sizeof(udp_sock_tuple.ipv6), -1, 0);
	if (probable_target_sock == NULL) {
		return false;
	}

	/* check if target socket is one of our managed IPX or SPX sockets */
	struct ipx_addr *bind_addr =
		bpf_sk_storage_get(&ipx_wrap_mux_bind_egress,
				probable_target_sock, NULL, 0);

	bpf_sk_release(probable_target_sock);

	if (bind_addr != NULL) {
		return true;
	}

	return false;
}

SEC("tc/ingress")
int ipx_wrap_demux(struct __sk_buff *skb)
{
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

	/* see if the packet is directed towards one of the managed IPX or SPX
	 * sockets, we must drop packets to managed sockets that are not actual
	 * IPX or SPX traffic */
	bool to_managed_sock = is_to_managed_sock(skb, ip6h, udph);

	if (!is_ipx_in_ipv6(ip6h, data_end)) {
		return (to_managed_sock ? TC_ACT_SHOT : TC_ACT_UNSPEC);
	}

	if (cur.pos + sizeof(struct ipxw_mux_msg) > data_end) {
		return (to_managed_sock ? TC_ACT_SHOT : TC_ACT_UNSPEC);
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
	if (fib_res != BPF_FIB_LKUP_RET_NOT_FWDED) {
		/* not for us */
		return (to_managed_sock ? TC_ACT_SHOT : TC_ACT_UNSPEC);
	}

	/* packet is destined for the local machine */

	struct ipxw_mux_msg *mux_msg = cur.pos;
	struct ipxhdr *ipxh = &(mux_msg->ipxh);

	struct bpf_bind_entry *e = NULL;

	bool is_bcast = __builtin_memcmp(ipxh->daddr.node, IPX_BCAST_NODE,
			sizeof(ipxh->daddr.node)) == 0;
	if (is_bcast) {
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

	if (is_bcast && !e->recv_bcast) {
		return TC_ACT_SHOT;
	}

	/* check packet type */
	if (ipxh->type != e->pkt_type && !e->pkt_type_any) {
		return TC_ACT_SHOT;
	}

	struct bpf_sock *sock = bpf_map_lookup_elem(&ipx_wrap_mux_sock_ingress,
			&(e->addr));
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
	__s64 csum_diff = csum_del_ipxhdr(ipxh, 0);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}

	/* set the hop limit to the transport control field of the IPX header
	 * so that userspace can read it with IPV6_HOPLIMIT */
	ip6h->hop_limit = tc;

	/* direct reception, mangle the source IPv6 address and UDP port */
	if (e->recv_direct) {
		/* move the UDP header directly before the payload */
		__builtin_memcpy(((void *) (mux_msg + 1)) - sizeof(struct
					udphdr), udph, sizeof(struct udphdr));
		udph = ((void *) (mux_msg + 1)) - sizeof(struct udphdr);

		/* adjust the source IPv6 addr and update checksum */
		csum_diff = csum_del((__be32 *) &(ip6h->saddr), sizeof(struct
					ipv6_eui64_addr), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
		struct ipv6_eui64_addr *ip6_saddr = (struct ipv6_eui64_addr *)
			&(ip6h->saddr);
		ip6_saddr->ipx_net = saddr.net;
		__builtin_memcpy(ip6_saddr->ipx_node_fst, saddr.node,
				IPX_ADDR_NODE_BYTES / 2);
		ip6_saddr->fffe = bpf_htons((IPX_DIRECT_MARK << 8) | pkt_type);
		__builtin_memcpy(ip6_saddr->ipx_node_snd, &(saddr.node[3]),
				IPX_ADDR_NODE_BYTES / 2);
		csum_diff = csum_add((__be32 *) &(ip6h->saddr), sizeof(struct
					ipv6_eui64_addr), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}

		/* adjust the UDP source port and update checksum */
		csum_diff = csum_del((__be32 *) &(udph->source),
				sizeof(udph->source), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
		udph->source = saddr.sock;
		csum_diff = csum_add((__be32 *) &(udph->source),
				sizeof(udph->source), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}

		/* adjust the IPv6 payload length and update checksum */
		csum_diff = csum_del((__be32 *) &(ip6h->payload_len),
				sizeof(ip6h->payload_len), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
		ip6h->payload_len = bpf_htons(data_len + sizeof(struct udphdr));
		csum_diff = csum_add((__be32 *) &(ip6h->payload_len),
				sizeof(ip6h->payload_len), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}

		/* adjust the UDP length and update checksum */
		csum_diff = csum_del((__be32 *) &(udph->len),
				sizeof(udph->len), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
		udph->len = bpf_htons(data_len + sizeof(struct udphdr));
		csum_diff = csum_add((__be32 *) &(udph->len),
				sizeof(udph->len), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}

	/* indirect reception */
	} else {
		/* clear the header so we can rewrite into a recv msg */
		__builtin_memset(mux_msg, 0, sizeof(struct ipxw_mux_msg));

		/* rewrite to recv msg */
		mux_msg->type = IPXW_MUX_RECV;
		mux_msg->recv.saddr = saddr;
		mux_msg->recv.pkt_type = pkt_type;
		mux_msg->recv.is_bcast = is_bcast;
		mux_msg->recv.is_spx = false;
		mux_msg->recv.data_len = data_len;
		mux_msg->recv.tc = tc;

		/* add recv msg header to checksum */
		csum_diff = csum_add_ipxhdr(ipxh, csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
	}

	__u32 csum_ofs = ((void *) &(udph->check)) - data;
	/* insert the modified checksum */
	if (!csum_replace_with_zero_check(skb, csum_ofs, csum_diff)) {
		return TC_ACT_SHOT;
	}

	/* shorten the packet when direct reception is enabled */
	if (e->recv_direct) {
		if (bpf_skb_adjust_room(skb, -((__s32)sizeof(struct ipxhdr)),
					BPF_ADJ_ROOM_NET, 0) < 0) {
			return TC_ACT_SHOT;
		}
	}

	return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int ipx_wrap_mux(struct __sk_buff *skb)
{
	struct bpf_sock *client_sock = skb->sk;

	/* no source socket, do nothing */
	if (client_sock == NULL) {
		return TC_ACT_UNSPEC;
	}

	struct ipx_addr *bind_addr = NULL;

	bind_addr = bpf_sk_storage_get(&ipx_wrap_mux_bind_egress, client_sock,
			NULL, 0);

	/* not one of our client sockets, do nothing */
	if (bind_addr == NULL) {
		return TC_ACT_UNSPEC;
	}

	struct bpf_bind_entry *e = bpf_map_lookup_elem(
			&ipx_wrap_mux_bind_entries_uc, bind_addr);

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
	if (ip6h->nexthdr != IPPROTO_UDP) {
		return TC_ACT_SHOT;
	}

	struct udphdr *udph;
	if (parse_udphdr(&cur, data_end, &udph) < 0) {
		return TC_ACT_SHOT;
	}

	struct ipxw_mux_msg *mux_msg = cur.pos;
	__s64 csum_diff = 0;

	struct ipv6_eui64_addr *ip6_dummy_daddr = (struct ipv6_eui64_addr *)
		&(ip6h->daddr);
	bool is_direct = (bpf_ntohs(ip6_dummy_daddr->fffe) >> 8) ==
		IPX_DIRECT_MARK;
	if (is_direct) {
		/* no xmit message exists, reconstruct destination and packet
		 * type from IPv6 and UDP headers */

		/* make room for the ipx header */
		if (bpf_skb_adjust_room(skb, sizeof(struct ipxhdr),
					BPF_ADJ_ROOM_NET, 0) < 0) {
			return TC_ACT_SHOT;
		}
		bpf_skb_pull_data(skb, 0);

		/* adjust pointers and reverify */
		data_end = (void *)(long)skb->data_end;
		data = (void *)(long)skb->data;

		eth = data;
		ip6h = ((void *) eth) + sizeof(struct ethhdr);
		udph = ((void *) ip6h) + sizeof(struct ipv6hdr);
		mux_msg = ((void *) udph) + sizeof(struct udphdr);
		if (mux_msg + 1 > data_end) {
			return TC_ACT_SHOT;
		}
		ip6_dummy_daddr = (struct ipv6_eui64_addr *) &(ip6h->daddr);
		cur.pos = mux_msg;

		/* copy the UDP header after the IPv6 header */
		__builtin_memcpy(udph, ((void *) udph) + sizeof(struct ipxhdr),
				sizeof(struct udphdr));

		/* construct the mux msg */
		mux_msg->type = IPXW_MUX_XMIT;
		mux_msg->xmit.pkt_type = bpf_ntohs(ip6_dummy_daddr->fffe) &
			0xFF;
		mux_msg->xmit.data_len = bpf_ntohs(udph->len) - sizeof(struct
				udphdr);
		struct ipx_addr *ipx_daddr = &(mux_msg->xmit.daddr);
		ipx_daddr->net = ip6_dummy_daddr->ipx_net;
		__builtin_memcpy(ipx_daddr->node,
				ip6_dummy_daddr->ipx_node_fst,
				IPX_ADDR_NODE_BYTES / 2);
		__builtin_memcpy(&(ipx_daddr->node[3]),
				ip6_dummy_daddr->ipx_node_snd,
				IPX_ADDR_NODE_BYTES / 2);
		ipx_daddr->sock = udph->dest;

		/* adjust the IPv6 payload length */
		ip6h->payload_len = bpf_htons(bpf_ntohs(ip6h->payload_len) +
				sizeof(struct ipxhdr));

		/* adjust the UDP length and checksum */
		csum_diff = csum_del((__be32 *) &(udph->len),
				sizeof(udph->len), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
		udph->len = bpf_htons(bpf_ntohs(udph->len) + sizeof(struct
					ipxhdr));
		csum_diff = csum_add((__be32 *) &(udph->len),
				sizeof(udph->len), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
	}

	if (bpf_ntohs(udph->len) < sizeof(struct udphdr) + sizeof(struct
				ipxhdr)) {
		return TC_ACT_SHOT;
	}

	if (cur.pos + sizeof(struct ipxw_mux_msg) > data_end) {
		return TC_ACT_SHOT;
	}

	/* remove IPX message data from checksum */
	if (!is_direct) {
		csum_diff = csum_del_ipxhdr(&(mux_msg->ipxh), csum_diff);
		if (csum_diff < 0) {
			return TC_ACT_SHOT;
		}
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

	/* remove old IPv6 addrs from checksum */
	csum_diff = csum_del((__be32 *) &(ip6h->saddr), sizeof(struct
				ipv6_eui64_addr) * 2, csum_diff);
	if (csum_diff < 0) {
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

	/* add new IPv6 addrs to checksum */
	csum_diff = csum_add((__be32 *) &(ip6h->saddr), sizeof(struct
				ipv6_eui64_addr) * 2, csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}

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

	/* add IPX header data to checksum */
	csum_diff = csum_add_ipxhdr(ipx_msg, csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}

	/* update UDP source and destination port and fix checksum */
	csum_diff = csum_del((__be32 *) &(udph->source), sizeof(__be32),
			csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}
	udph->source = bpf_htons(IPX_IN_IPV6_PORT);
	udph->dest = bpf_htons(IPX_IN_IPV6_PORT);
	csum_diff = csum_add((__be32 *) &(udph->source), sizeof(__be32),
			csum_diff);
	if (csum_diff < 0) {
		return TC_ACT_SHOT;
	}

	/* update the UDP checksum */
	if (!csum_replace_with_zero_check(skb, ((void *) &(udph->check)) -
				data, csum_diff)) {
		return TC_ACT_SHOT;
	}

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
