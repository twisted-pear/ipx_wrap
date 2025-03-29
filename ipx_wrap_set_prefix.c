#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <net/if.h>

#include <bpf/bpf.h>

#define IPV6_PREFIX_LEN 4
#define PIN_BASE "/sys/fs/bpf"
#define PIN_SUB "tc/globals"
#define IPX_WRAP_PREFIX_MAP "ipx_wrap_prefix"

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_set_prefix <ipv6 /32 prefix>\n");
	exit(1);
}

static int parse_ipv6_prefix(char *str, unsigned char *prefix)
{
	if (sscanf(str, "%02hhx%02hhx:%02hhx%02hhx%*c", &prefix[0], &prefix[1],
				&prefix[2], &prefix[3]) != IPV6_PREFIX_LEN) {
		return -1;
	}

	return 0;
}


int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
	}

	char *prefix_str = argv[1];
	unsigned char prefix[IPV6_PREFIX_LEN];

	if (parse_ipv6_prefix(prefix_str, prefix) < 0) {
		usage();
	}

	char map_fn[PATH_MAX];
	int len = snprintf(map_fn, PATH_MAX, "%s/%s/%s", PIN_BASE, PIN_SUB,
			IPX_WRAP_PREFIX_MAP);
	if (len < 0) {
		fprintf(stderr, "mk map path: failed to create path\n");
		exit(2);
	}

	int map_fd = bpf_obj_get(map_fn);
	if (map_fd < 0) {
		perror("get prefix map fd");
		exit(3);
	}

	__u32 key = 0;
	if (bpf_map_update_elem(map_fd, &key, prefix, 0) < 0) {
		perror("update prefix map for");
		exit(4);
	}

	return 0;
}
