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

static struct bpf_tc_hook *if_hook = NULL;

static volatile sig_atomic_t keep_going = true;

static struct bpf_tc_hook *create_tc_hook(__u32 ifidx)
{
	struct bpf_tc_hook *h = calloc(1, sizeof(struct bpf_tc_hook));
	if (h == NULL) {
		return NULL;
	}

	h->sz = sizeof(struct bpf_tc_hook);
	h->ifindex = ifidx;
	h->attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;

	int err = bpf_tc_hook_create(h);
	if (err != 0) {
		free(h);

		errno = -err;
		return NULL;
	}

	return h;
}

static bool attach_tc_prog(int fd, struct bpf_tc_hook *h, bool ingress)
{
	struct bpf_tc_opts o;
	memset(&o, 0, sizeof(struct bpf_tc_opts));

	o.sz = sizeof(struct bpf_tc_opts);
	o.prog_fd = fd;
	o.handle = h->parent;

	struct bpf_tc_hook tmph;
	memcpy(&tmph, h, sizeof(struct bpf_tc_hook));
	tmph.attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

	int err = bpf_tc_attach(&tmph, &o);
	if (err != 0) {
		errno = -err;
		return false;
	}

	return true;
}

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
	if (if_hook != NULL) {
		bpf_tc_hook_destroy(if_hook);
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

	if_hook = create_tc_hook(ifidx);
	if (if_hook == NULL) {
		perror("create TC hook");
		cleanup_and_exit(IFD_ERR_BPF);
	}

	int ingress_fd = bpf_program__fd(bpf_kern->progs.ipx_wrap_in);
	int egress_fd = bpf_program__fd(bpf_kern->progs.ipx_wrap_out);
	if (ingress_fd < 0 || egress_fd < 0) {
		fprintf(stderr, "Failed to obtain program FD\n");
		cleanup_and_exit(IFD_ERR_BPF);
	}

	if (!attach_tc_prog(ingress_fd, if_hook, true)) {
		perror("attach ingress BPF program");
		cleanup_and_exit(IFD_ERR_BPF);
	}
	if (!attach_tc_prog(egress_fd, if_hook, false)) {
		perror("attach egress BPF program");
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
