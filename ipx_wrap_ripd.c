#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "common.h"

#define RTABLE_FILE "/proc/net/ipv6_route"
#define RIP_PKT_TYPE 0x01
#define RIP_SOCK 0x0453
#define RIP_INTERVAL_SECS 60
#define RIP_TYPE_RESPONSE 2
#define MAX_ROUTES 64

struct rip_entry {
	__be32 net;
	__be16 hops;
	__be16 ticks;
} __attribute__((packed));

static struct __attribute__((packed)) {
	struct ipxhdr ipxh;
	__be16 rip_type;
	struct rip_entry rip_entries[MAX_ROUTES];
} rip_pkt;

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_ripd <bind ipv6 addr>\n");
	exit(1);
}

static int get_next_rip_entry(FILE *rtable, struct rip_entry *re, __u32
		my_prefix, __u32 my_net)
{
	char *line = NULL;
	size_t len;

	ssize_t res = getline(&line, &len, rtable);
	if (res < 0) {
		free(line);
		if (errno != 0) {
			perror("read rtable");
		}
		return -1;
	}

	__u32 dst_prefix;
	__u32 dst_net;
	__u8 dst_mask;
	__u32 gw_prefix;
	__u32 gw_net;
	res = sscanf(line, "%08x%08x%*16x %02hhx 00000000000000000000000000000000 00 %08x%08x%*16x",
				&dst_prefix, &dst_net, &dst_mask, &gw_prefix,
				&gw_net);
	free(line);
	if (res != 5) {
		fprintf(stderr, "failed to parse rtable entry");
		return -1;
	}

	/* don't advertise strange subnets, we only support /64 */
	if (dst_mask != 64) {
		return 0;
	}

	/* only advertise within the prefix */
	if (dst_prefix != my_prefix) {
		return 0;
	}

	/* don't advertise a route to the net we are bound to */
	if (dst_net == my_net) {
		return 0;
	}

	/* don't advertise a route via the net we are bound to */
	if (gw_prefix == my_prefix && gw_net == my_net) {
		return 0;
	}

	/* directly connected network */
	int distance = 1;
	if (gw_prefix != 0 || gw_net != 0) {
		/* non-directly connected network */
		distance = 2;
	}

	re->net = htonl(dst_net);
	re->hops = htons(distance);
	re->ticks = htons(distance + 1);

	return 1;
}

static int mk_rip_pkt(FILE *rtable, __u32 my_prefix, __u32 my_net)
{
	int res = 0;
	int nentries;
	for (nentries = 0; nentries < MAX_ROUTES;) {
		res = get_next_rip_entry(rtable,
				&rip_pkt.rip_entries[nentries], my_prefix,
				my_net);
		if (res < 0) {
			break;
		}

		if (res == 1) {
			nentries++;
		}
	}

	rip_pkt.ipxh.pktlen = htons(sizeof(rip_pkt.ipxh) +
			sizeof(rip_pkt.rip_type) + nentries * sizeof(struct
				rip_entry));

	return nentries;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
	}

	char *bind_addr_str = argv[1];

	struct in6_addr bind_addr;
	if (inet_pton(AF_INET6, bind_addr_str, &bind_addr) != 1) {
		usage();
	}

	struct ipv6_eui64_addr *my_addr = (struct ipv6_eui64_addr *)
		&bind_addr;
	__u32 my_prefix = ntohl(my_addr->prefix);
	__u32 my_net = ntohl(my_addr->ipx_net);

	/* prepare the destination address */
	struct in6_addr send_addr;
	struct ipv6_eui64_addr *dst_addr = (struct ipv6_eui64_addr *)
		&send_addr;
	dst_addr->prefix = my_addr->prefix;
	dst_addr->ipx_net = my_addr->ipx_net;
	memset(dst_addr->ipx_node_fst, 0xFF, sizeof(dst_addr->ipx_node_fst));
	dst_addr->fffe = 0xFFFE;
	memset(dst_addr->ipx_node_snd, 0xFF, sizeof(dst_addr->ipx_node_snd));

	/* pre-fill IPX header */
	rip_pkt.ipxh.csum = 0xFFFF;
	rip_pkt.ipxh.pktlen = htons(sizeof(rip_pkt.ipxh) +
			sizeof(rip_pkt.rip_type));
	rip_pkt.ipxh.tc = 0;
	rip_pkt.ipxh.type = RIP_PKT_TYPE;
	rip_pkt.ipxh.daddr.net = my_addr->ipx_net;
	memset(rip_pkt.ipxh.daddr.node, 0xFF, sizeof(rip_pkt.ipxh.daddr.node));
	rip_pkt.ipxh.daddr.sock = htons(RIP_SOCK);
	rip_pkt.ipxh.saddr.net = my_addr->ipx_net;
	memcpy(rip_pkt.ipxh.saddr.node, my_addr->ipx_node_fst,
			sizeof(my_addr->ipx_node_fst));
	memcpy(rip_pkt.ipxh.saddr.node + sizeof(my_addr->ipx_node_fst),
			my_addr->ipx_node_snd, sizeof(my_addr->ipx_node_snd));
	rip_pkt.ipxh.saddr.sock = htons(RIP_SOCK);
	rip_pkt.rip_type = htons(RIP_TYPE_RESPONSE);

	/* prepare the UDP socket */
	int udpsock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (udpsock < 0) {
		perror("creating UDP socket");
		exit(2);
	}

	struct sockaddr_in6 source = {
		.sin6_family = AF_INET6,
		.sin6_addr = bind_addr,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	if (bind(udpsock, (struct sockaddr *) &source, sizeof(source)) < 0) {
		perror("binding UDP socket");
		close(udpsock);
		exit(3);
	}

	struct sockaddr_in6 destination = {
		.sin6_family = AF_INET6,
		.sin6_addr = send_addr,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	if (connect(udpsock, (struct sockaddr *) &destination,
				sizeof(destination)) < 0) {
		perror("setting UDP destination");
		close(udpsock);
		exit(3);
	}

	/* open the routing table */
	FILE *rtable = fopen(RTABLE_FILE, "r");
	if (rtable == NULL) {
		perror("open routing table");
		close(udpsock);
		exit(4);
	}

	for (;;) {
		int nentries = mk_rip_pkt(rtable, my_prefix, my_net);
		if (fseek(rtable, 0, SEEK_SET) < 0) {
			perror("seek routing table");
			fclose(rtable);
			close(udpsock);
			exit(5);
		}

		printf("Sending RIP response with %d routes\n", nentries);
		if (send(udpsock, &rip_pkt, ntohs(rip_pkt.ipxh.pktlen), 0) < 0)
		{
			perror("sending RIP packet");
			fclose(rtable);
			close(udpsock);
			exit(6);
		}

		sleep(RIP_INTERVAL_SECS);
	}

	fclose(rtable);
	close(udpsock);

	return 0;
}
