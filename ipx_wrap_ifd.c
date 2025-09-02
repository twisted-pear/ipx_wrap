#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <linux/limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"

#include "ipx_wrap_kern_nopin.skel.h"

#define IPX_WRAP_IF_CONFIG_MAP "ipx_wrap_if_config"

enum ifd_error_codes {
	IFD_ERR_OK = 0,
	IFD_ERR_USAGE,
	IFD_ERR_BPF,
	IFD_ERR_IFINDEX,
	IFD_ERR_SIG_HANDLER,
	IFD_ERR_MAX
};

static struct ipx_wrap_kern_nopin *bpf_kern = NULL;
static struct bpf_link *ingress_link = NULL;
static struct bpf_link *egress_link = NULL;

static bool keep_going = true;

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			keep_going = false;
			break;
		default:
			assert(0);
	}
}

static _Noreturn void cleanup_and_exit(int exit_code)
{
	if (ingress_link != NULL) {
		bpf_link__detach(ingress_link);
		bpf_link__destroy(ingress_link);
	}

	if (egress_link != NULL) {
		bpf_link__detach(egress_link);
		bpf_link__destroy(egress_link);
	}

	if (bpf_kern != NULL) {
		ipx_wrap_kern_nopin__destroy(bpf_kern);
	}

	exit(exit_code);
}

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_ifd <if> <if ipv6 addr>\n");
	exit(IFD_ERR_USAGE);
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		usage();
	}

	char *ifname = argv[1];
	char *addr_str = argv[2];

	struct ipv6_eui64_addr addr;
	struct if_config ifcfg;

	if (inet_pton(AF_INET6, addr_str, &addr) != 1) {
		usage();
	}

	ifcfg.prefix = addr.prefix;
	ifcfg.network = addr.ipx_net;

	__u32 ifidx = if_nametoindex(ifname);
	if (ifidx == 0) {
		perror("ifindex");
		cleanup_and_exit(IFD_ERR_IFINDEX);
	}

	bpf_kern = ipx_wrap_kern_nopin__open_and_load();
	if (bpf_kern == NULL) {
		perror("load BPF kernel objects");
		cleanup_and_exit(IFD_ERR_BPF);
	}

	ingress_link = bpf_program__attach_tcx(bpf_kern->progs.ipx_wrap_in,
			ifidx, NULL);
	egress_link = bpf_program__attach_tcx(bpf_kern->progs.ipx_wrap_out,
			ifidx, NULL);
	if (ingress_link == NULL || egress_link == NULL) {
		perror("attach BPF programs");
		cleanup_and_exit(IFD_ERR_BPF);
	}

	int err = bpf_map__update_elem(bpf_kern->maps.ipx_wrap_if_config,
			&ifidx, sizeof(__u32), &ifcfg, sizeof(struct
				if_config), BPF_ANY);
	if (err != 0) {
		errno = -err;
		perror("update IF config BPF map");
		cleanup_and_exit(IFD_ERR_BPF);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting signal handler");
		cleanup_and_exit(IFD_ERR_SIG_HANDLER);
	}

	while (keep_going) {
		sleep(1);
	}

	cleanup_and_exit(IFD_ERR_OK);
}
