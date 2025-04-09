#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#include <bpf/bpf.h>

#include "common.h"

#define RTABLE_FILE "/proc/net/ipv6_route"

#define RIP_PKT_TYPE 0x01
#define RIP_SOCK 0x0453
#define RIP_TYPE_RESPONSE 2
#define RIP_MAX_HOPS 15

#define RIP_UPDATE_TIMER 60
#define RIP_INVALID_TIMER 180

#define RIP_METRIC_MULT 2048
#define RIP_INVALID_TIMER_MULT 100

#define MAX_ROUTES 64

struct rip_entry {
	__be32 net;
	__be16 hops;
	__be16 ticks;
} __attribute__((packed));

struct rip_pkt {
	struct ipxhdr ipxh;
	__be16 rip_type;
	struct rip_entry rip_entries[MAX_ROUTES];
} __attribute__((packed));

static struct rip_pkt rip_pkt_out;

static struct rip_pkt rip_pkt_in;

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_ripd <if> <if ipv6 addr>\n");
	exit(1);
}

static int get_next_rip_entry(FILE *rtable, struct rip_entry *re, __u32
		my_prefix, __u32 my_net)
{
	char *line = NULL;
	size_t len;

	errno = 0;
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
	__u32 metric;
	res = sscanf(line, "%08x%08x%*16x %02hhx 00000000000000000000000000000000 00 %08x%08x%*16x %08x",
				&dst_prefix, &dst_net, &dst_mask, &gw_prefix,
				&gw_net, &metric);
	free(line);
	if (res != 6) {
		fprintf(stderr, "failed to parse rtable entry\n");
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

	int distance = (metric / RIP_METRIC_MULT) + 1;
	if (distance == 1) {
		if (gw_prefix != 0 || gw_net != 0) {
			/* non-directly connected network, static route */
			distance++;
		} else {
			/* directly connected network */
		}
	}

	/* don't advertise routes with too many hops */
	if (distance > RIP_MAX_HOPS) {
		return 0;
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
				&rip_pkt_out.rip_entries[nentries], my_prefix,
				my_net);
		if (res < 0) {
			break;
		}

		if (res == 1) {
			nentries++;
		}
	}

	rip_pkt_out.ipxh.pktlen = htons(sizeof(rip_pkt_out.ipxh) +
			sizeof(rip_pkt_out.rip_type) + nentries * sizeof(struct
				rip_entry));

	return nentries;
}

static int send_rip_resp(int udpsock, FILE *rtable, struct ipv6_eui64_addr
		*my_addr, struct sockaddr_in6 *destination)
{
	__u32 my_prefix = ntohl(my_addr->prefix);
	__u32 my_net = ntohl(my_addr->ipx_net);

	int nentries = mk_rip_pkt(rtable, my_prefix, my_net);
	if (fseek(rtable, 0, SEEK_SET) < 0) {
		perror("seek routing table");
		return -1;
	}

	printf("Sending RIP response with %u routes.\n", nentries);
	if (sendto(udpsock, &rip_pkt_out, ntohs(rip_pkt_out.ipxh.pktlen), 0,
				(struct sockaddr *) destination,
				sizeof(*destination)) < 0)
	{
		perror("sending RIP packet");
		return -1;
	}

	return 0;
}

static ssize_t got_rip_pkt(int udpsock)
{
	struct ipxhdr ipxh;

	ssize_t len = recv(udpsock, &ipxh, sizeof(ipxh), MSG_PEEK);
	do {
		if (len < 0) {
			perror("receive IPX header");
			break;
		}
		if (len != sizeof(ipxh)) {
			fprintf(stderr, "received broken IPX packet\n");
			break;
		}

		if (ipxh.type != RIP_PKT_TYPE) {
			break;
		}
		if (ipxh.daddr.sock != htons(RIP_SOCK)) {
			break;
		}

		return ntohs(ipxh.pktlen);
	} while (0);

	/* clear out packet */
	recv(udpsock, &ipxh, 0, 0);

	return -1;
}

static bool add_route(__be32 net, struct ipx_addr *gw, __be32 hops, struct
		ipv6_eui64_addr *my_addr, __u32 ifidx)
{
	struct in6_rtmsg rt;
	memset(&rt, 0x00, sizeof(rt));

	/* set destination net */
	struct ipv6_eui64_addr *ip6 = (struct ipv6_eui64_addr *) &rt.rtmsg_dst;
	ip6->prefix = my_addr->prefix;
	ip6->ipx_net = net;

	/* set gateway */
	ip6 = (struct ipv6_eui64_addr *) &rt.rtmsg_gateway;
	ip6->prefix = my_addr->prefix;
	ip6->ipx_net = gw->net;
	memcpy(ip6->ipx_node_fst, gw->node, sizeof(gw->node) / 2);
	ip6->fffe = htons(0xfffe);
	memcpy(ip6->ipx_node_snd, gw->node + (sizeof(gw->node) / 2),
			sizeof(gw->node) / 2);

	/* set mask */
	rt.rtmsg_dst_len = 64;

	/* set metric from the hopcount */
	rt.rtmsg_metric = ntohs(hops) * RIP_METRIC_MULT;

	/* set interface */
	rt.rtmsg_ifindex = ifidx;

	/* we want to add the route, add flags */
	rt.rtmsg_flags = RTMSG_NEWROUTE | RTF_UP | RTF_GATEWAY | RTF_EXPIRES;
	rt.rtmsg_info = RIP_INVALID_TIMER * RIP_INVALID_TIMER_MULT;

	/* try to insert the route */
	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("opening routing table");
		return false;
	}
	if (ioctl(sock, SIOCADDRT, &rt) < 0) {
		if (errno != EEXIST) {
			perror("inserting route");
			close(sock);
			return false;
		}
	}

	close(sock);
	return true;
}

static void handle_rip_pkt(int udpsock, size_t len, struct ipv6_eui64_addr
		*my_addr, __u32 ifidx)
{
	len = recv(udpsock, &rip_pkt_in, (len > sizeof(rip_pkt_in) ?
				sizeof(rip_pkt_in) : len), 0);
	size_t hdr_len = sizeof(rip_pkt_in) - sizeof(rip_pkt_in.rip_entries);

	/* check if we even have a complete packet */
	if (len < hdr_len) {
		fprintf(stderr, "received RIP packet too short\n");
		return;
	}

	/* cannot handle other RIP packets right now */
	if (rip_pkt_in.rip_type != ntohs(RIP_TYPE_RESPONSE)) {
		return;
	}

	/* incomplete routes */
	if ((len - hdr_len) % sizeof(struct rip_entry) != 0) {
		fprintf(stderr, "received RIP packet is mangled\n");
		return;
	}

	struct ipx_addr *gw = &rip_pkt_in.ipxh.saddr;
	size_t nentries = (len - hdr_len) / sizeof(struct rip_entry);

	printf("Processing RIP response with %lu routes.\n", nentries);

	size_t i;
	for (i = 0; i < nentries; i++) {
		__be32 net = rip_pkt_in.rip_entries[i].net;
		__be16 hops = rip_pkt_in.rip_entries[i].hops;
		/* skip routes that have too many hops */
		if (ntohs(hops) > RIP_MAX_HOPS) {
			continue;
		}
		if (!add_route(net, gw, hops, my_addr, ifidx)) {
			fprintf(stderr, "failed to add route for net %08x\n",
					ntohl(net));
		}
	}
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		usage();
	}

	char *ifname = argv[1];
	char *if_addr_str = argv[2];

	struct in6_addr if_addr;
	if (inet_pton(AF_INET6, if_addr_str, &if_addr) != 1) {
		usage();
	}

	__u32 ifidx = if_nametoindex(ifname);
	if (ifidx == 0) {
		perror("ifindex");
		exit(2);
	}

	struct ipv6_eui64_addr *my_addr = (struct ipv6_eui64_addr *) &if_addr;

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
	rip_pkt_out.ipxh.csum = 0xFFFF;
	rip_pkt_out.ipxh.pktlen = htons(sizeof(rip_pkt_out.ipxh) +
			sizeof(rip_pkt_out.rip_type));
	rip_pkt_out.ipxh.tc = 0;
	rip_pkt_out.ipxh.type = RIP_PKT_TYPE;
	rip_pkt_out.ipxh.daddr.net = my_addr->ipx_net;
	memset(rip_pkt_out.ipxh.daddr.node, 0xFF,
			sizeof(rip_pkt_out.ipxh.daddr.node));
	rip_pkt_out.ipxh.daddr.sock = htons(RIP_SOCK);
	rip_pkt_out.ipxh.saddr.net = my_addr->ipx_net;
	memcpy(rip_pkt_out.ipxh.saddr.node, my_addr->ipx_node_fst,
			sizeof(my_addr->ipx_node_fst));
	memcpy(rip_pkt_out.ipxh.saddr.node + sizeof(my_addr->ipx_node_fst),
			my_addr->ipx_node_snd, sizeof(my_addr->ipx_node_snd));
	rip_pkt_out.ipxh.saddr.sock = htons(RIP_SOCK);
	rip_pkt_out.rip_type = htons(RIP_TYPE_RESPONSE);

	/* prepare the UDP socket */
	int udpsock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (udpsock < 0) {
		perror("creating UDP socket");
		exit(3);
	}

	/* allow other processes to bind to this address too, so we don't
	 * monopolize the port */
	int reuse = 1;
	if (setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, &reuse,
				sizeof(reuse)) < 0) {
		perror("set reuseaddr");
		close(udpsock);
		exit(4);
	}

	/* bind the socket to the interface */
	if (setsockopt(udpsock, SOL_SOCKET, SO_BINDTODEVICE, ifname,
				strlen(ifname)) < 0) {
		perror("bind to device");
		close(udpsock);
		exit(5);
	}

	/* join the all nodes multicast group */
	struct ipv6_mreq group;
	group.ipv6mr_interface = ifidx;
	memcpy(&group.ipv6mr_multiaddr, IPV6_MCAST_ALL_NODES,
			sizeof(group.ipv6mr_multiaddr));
	if (setsockopt(udpsock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group,
				sizeof(group)) < 0) {
		perror("join mcast group");
		close(udpsock);
		exit(6);
	}

	/* bind to the port (but not the interface IP) */
	struct sockaddr_in6 source = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};
	memset(&source.sin6_addr, 0x00, sizeof(source.sin6_addr));
	if (bind(udpsock, (struct sockaddr *) &source, sizeof(source)) < 0) {
		perror("binding UDP socket");
		close(udpsock);
		exit(7);
	}

	/* prepare destination for sending */
	struct sockaddr_in6 destination = {
		.sin6_family = AF_INET6,
		.sin6_addr = send_addr,
		.sin6_port = htons(IPX_IN_IPV6_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0
	};

	/* start a timer for sending periodic RIP responses */
	int tmr = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tmr < 0) {
		perror("creating timer");
		close(udpsock);
		exit(8);
	}
	struct itimerspec tmr_spec = {
		.it_interval = { .tv_sec = RIP_UPDATE_TIMER },
		.it_value = { .tv_sec = 1 }
	};
	if (timerfd_settime(tmr, 0, &tmr_spec, NULL) < 0) {
		perror("arming timer");
		close(udpsock);
		close(tmr);
		exit(9);
	}

	/* open the routing table */
	FILE *rtable = fopen(RTABLE_FILE, "r");
	if (rtable == NULL) {
		perror("open routing table");
		close(udpsock);
		close(tmr);
		exit(10);
	}

	struct pollfd fds[2] = {
		{
			.fd = udpsock,
			.events = POLLIN,
			.revents = 0
		},
		{
			.fd = tmr,
			.events = POLLIN,
			.revents = 0
		}
	};

	int ret = 0;
	for (;;) {
		int err = poll(fds, 2, -1);
		if (err < 0) {
			/* poll errored */
		        if (errno != EINTR) {
				perror("poll");
				ret = 11;
				break;
			}

			/* poll was interrupted, poll again */
			continue;
		}
		if (err == 0) {
			/* shouldn't happen */
			continue;
		}

		/* we can read from the socket */
		if (fds[0].revents & POLLIN) {
			ssize_t len = got_rip_pkt(udpsock);
			if (len >= 0) {
				handle_rip_pkt(udpsock, len, my_addr, ifidx);
			}
		} else if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			/* some other error */
			fprintf(stderr, "socket error\n");
			ret = 12;
			break;
		}

		/* the timer expired, send periodic RIP response */
		if (fds[1].revents & POLLIN) {
			if (send_rip_resp(udpsock, rtable, my_addr,
						&destination) < 0) {
				fprintf(stderr, "error sending packet\n");
			}
			/* consume all expirations */
			__u64 dummy;
			read(tmr, &dummy, sizeof(dummy));
		} else if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			/* some other error */
			fprintf(stderr, "timer error\n");
			ret = 13;
			break;
		}
	}

	fclose(rtable);
	close(udpsock);
	close(tmr);

	return ret;
}
