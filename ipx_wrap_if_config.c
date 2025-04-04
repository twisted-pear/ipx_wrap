#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <net/if.h>
#include <netinet/in.h>

#include <bpf/bpf.h>

#define IPV6_PREFIX_LEN 4
#define PIN_BASE "/sys/fs/bpf"
#define PIN_SUB "tc/globals"
#define IPX_WRAP_IF_CONFIG_MAP "ipx_wrap_if_config"

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_if_config <if> <ipv6 /32 prefix>-<ipx net hex>\n");
	exit(1);
}

static int parse_cfg(char *str, unsigned char *prefix, __u32 *net)
{
	if (sscanf(str, "%02hhx%02hhx:%02hhx%02hhx-%x%*c", &prefix[0],
				&prefix[1], &prefix[2], &prefix[3], net) !=
			IPV6_PREFIX_LEN + 1) {
		return -1;
	}

	return 0;
}


int main(int argc, char **argv)
{
	if (argc != 3) {
		usage();
	}

	char *ifname = argv[1];
	char *prefix_str = argv[2];

	struct __attribute__((packed)) {
		unsigned char prefix[IPV6_PREFIX_LEN];
		__be32 net;
	} if_config;

	if (parse_cfg(prefix_str, if_config.prefix, &if_config.net) < 0) {
		usage();
	}
	if_config.net = htonl(if_config.net);

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

	if (bpf_map_update_elem(map_fd, &ifidx, &if_config, 0) < 0) {
		perror("update if config map");
		exit(5);
	}

	return 0;
}
