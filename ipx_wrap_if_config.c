#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>

#include "common.h"

#define PIN_BASE "/sys/fs/bpf"
#define PIN_SUB "tc/globals"
#define IPX_WRAP_IF_CONFIG_MAP "ipx_wrap_if_config"

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_if_config <if> <if ipv6 addr>\n");
	exit(1);
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
		exit(2);
	}

	char map_fn[PATH_MAX];
	int len = snprintf(map_fn, PATH_MAX, "%s/%s/%s", PIN_BASE, PIN_SUB,
			IPX_WRAP_IF_CONFIG_MAP);
	if (len < 0) {
		fprintf(stderr, "mk map path: failed to create path\n");
		exit(3);
	}

	int map_fd = bpf_obj_get(map_fn);
	if (map_fd < 0) {
		perror("get if config map fd");
		exit(4);
	}

	if (bpf_map_update_elem(map_fd, &ifidx, &ifcfg, 0) < 0) {
		perror("update if config map");
		exit(5);
	}

	return 0;
}
