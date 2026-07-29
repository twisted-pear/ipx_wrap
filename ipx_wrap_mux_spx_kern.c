/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "ipx_wrap_common_kern.h"
#include "ipx_wrap_common_proto.h"

#define SPX_SOCKETS_MAX	32768

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct spx_conn_key);
	__type(value, __u64);
	__uint(max_entries, SPX_SOCKETS_MAX);
	//__uint(map_flags, BPF_F_RDONLY_PROG);
} ipx_wrap_mux_kspx_sock_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__type(key, __u32);
	__type(value, struct bpf_spx_state);
	__uint(max_entries, 0);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipx_wrap_mux_kspx_state SEC(".maps");

SEC("tc/ingress")
int ipx_wrap_spx_demux(struct __sk_buff *skb)
{
	return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int ipx_wrap_spx_mux(struct __sk_buff *skb)
{
	struct bpf_sock *client_sock = skb->sk;
	if (client_sock == NULL) {
		return TC_ACT_UNSPEC;
	}

	struct bpf_spx_state *spx_state =
		bpf_sk_storage_get(&ipx_wrap_mux_kspx_state, client_sock, NULL,
				0);
	if (spx_state == NULL) {
		return TC_ACT_UNSPEC;
	}

	bpf_printk("Got packet for kernel SPX conn %d",
			bpf_ntohs(spx_state->local_id));

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
