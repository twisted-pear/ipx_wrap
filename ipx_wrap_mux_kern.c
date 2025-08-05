/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#define IPX_SOCKETS_MAX	32768

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, IFINDEX_MAX);
	//__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_sock_egress SEC(".maps");

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
} ipx_wrap_mux_bind_entries SEC(".maps");

#define CB_INFO(ctx) ((struct bpf_cb_info *) &(ctx->cb[0]))

SEC("tc/ingress")
int ipw_wrap_demux(struct __sk_buff *skb)
{
	if (CB_INFO(skb)->mark != IPX_TO_IPV6UDP_REINJECT_MARK) {
		return TC_ACT_UNSPEC;
	}

	struct bpf_sock *sock = skb->sk;
	if (sock == NULL) {
		bpf_printk("demux no socket");
		return TC_ACT_UNSPEC;
	}

	struct bpf_sock *fullsock = bpf_sk_fullsock(sock);
	if (fullsock == NULL) {
		bpf_printk("no fullsock");
		return TC_ACT_UNSPEC;
	}

	bpf_printk("proto: %d", fullsock->protocol);
	bpf_printk("dport: %d", fullsock->dst_port);
	bpf_printk("daddr: %08x", fullsock->dst_ip6[0]);
	bpf_printk("daddr: %08x", fullsock->dst_ip6[1]);
	bpf_printk("daddr: %08x", fullsock->dst_ip6[2]);
	bpf_printk("daddr: %08x", fullsock->dst_ip6[3]);
	bpf_printk("sport: %d", fullsock->src_port);
	bpf_printk("saddr: %08x", fullsock->src_ip6[0]);
	bpf_printk("saddr: %08x", fullsock->src_ip6[1]);
	bpf_printk("saddr: %08x", fullsock->src_ip6[2]);
	bpf_printk("saddr: %08x", fullsock->src_ip6[3]);
	bpf_printk("type: %d", skb->pkt_type);

	/* TODO: get IPX dst sock and retrieve bind entry */

	bpf_printk("demux unicast, len: %u", skb->len);
	return TC_ACT_OK;
}

SEC("sk_msg")
int ipx_wrap_mux(struct sk_msg_md *msg)
{
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
