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
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 1);
	//__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_sock_egress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, IPX_SOCKETS_MAX);
	//__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_sock_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__type(key, __u32);
	__type(value, struct ipx_addr);
	__uint(max_entries, 0);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipx_wrap_mux_bind_ingress_uc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__type(key, __u32);
	__type(value, struct ipx_addr);
	__uint(max_entries, 0);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipx_wrap_mux_bind_ingress_mc SEC(".maps");

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
		bpf_printk("demux unicast no socket");
		return TC_ACT_UNSPEC;
	}

	/* get the UDP socket */
	struct ipx_addr *ipx_addr =
		bpf_sk_storage_get(&ipx_wrap_mux_bind_ingress_uc, sock, NULL,
				0);
	if (ipx_addr == NULL) {
		ipx_addr = bpf_sk_storage_get(&ipx_wrap_mux_bind_ingress_mc,
				sock, NULL, 0);
	}

	if (ipx_addr == NULL) {
		bpf_printk("demux unicast failed");
		return TC_ACT_UNSPEC;
	}

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
