#include <assert.h>
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
#include <ifaddrs.h>

#include "ipx_wrap_mux_proto.h"

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
	union {
		struct {
			struct ipxw_mux_msg mux_msg;
			__be16 rip_type;
			struct rip_entry rip_entries[MAX_ROUTES];
		} __attribute__((packed));
		__u8 buf[IPXW_MUX_MSG_LEN];
	};
} __attribute__((packed));

_Static_assert(sizeof(struct rip_pkt) == IPXW_MUX_MSG_LEN);

static struct rip_pkt rip_pkt_out;

static struct rip_pkt rip_pkt_in;

static _Noreturn void usage() {
	printf("Usage: ipx_wrap_ripd <if ipv6 addr>\n");
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

	rip_pkt_out.mux_msg.xmit.data_len = sizeof(rip_pkt_out.rip_type) +
		(nentries * sizeof(struct rip_entry));

	return nentries;
}

static int send_rip_resp(int data_sock, FILE *rtable, struct ipv6_eui64_addr
		*my_addr)
{
	__u32 my_prefix = ntohl(my_addr->prefix);
	__u32 my_net = ntohl(my_addr->ipx_net);

	int nentries = mk_rip_pkt(rtable, my_prefix, my_net);
	if (fseek(rtable, 0, SEEK_SET) < 0) {
		perror("seek routing table");
		return -1;
	}

	printf("Sending RIP response with %u routes.\n", nentries);
	ssize_t len = ipxw_mux_xmit(data_sock, &rip_pkt_out.mux_msg);
	if (len < 0) {
		perror("send");
		return -1;
	}

	return 0;
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

static void handle_rip_pkt(int data_sock, struct ipv6_eui64_addr *my_addr,
		__u32 ifidx)
{
	ssize_t len = ipxw_mux_get_recvd(data_sock, &rip_pkt_in.mux_msg);
	if (len < 0) {
		perror("recv");
		return;
	}

	assert(len >= sizeof(struct ipxw_mux_msg));

	size_t data_len = rip_pkt_in.mux_msg.recv.data_len;

	/* check if we even have a complete RIP packet */
	if (data_len < sizeof(rip_pkt_in.rip_type)) {
		fprintf(stderr, "received RIP packet too short\n");
		return;
	}

	/* cannot handle other RIP packets right now */
	if (rip_pkt_in.rip_type != ntohs(RIP_TYPE_RESPONSE)) {
		return;
	}

	/* incomplete routes */
	if ((data_len - sizeof(rip_pkt_in.rip_type)) % sizeof(struct rip_entry) != 0) {
		fprintf(stderr, "received RIP packet is mangled\n");
		return;
	}

	struct ipx_addr *gw = &rip_pkt_in.mux_msg.recv.saddr;
	size_t nentries = (data_len - sizeof(rip_pkt_in.rip_type)) /
		sizeof(struct rip_entry);

	if (nentries > MAX_ROUTES) {
		fprintf(stderr, "received RIP packet is too big\n");
		return;
	}

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

static unsigned int get_ifindex_for_addr(struct in6_addr *if_addr)
{
	/* iterate over all addresses to find the interface to our IPv6 addr */
	struct ifaddrs *addrs;
	struct ifaddrs *iter;

	if (getifaddrs(&addrs) < 0) {
		return 0;
	}

	/* if the loop exits normally, we were unable to find the IPv6 addr */
	int ret = 0;
	errno = ENOENT;
	for (iter = addrs; iter != NULL; iter = iter->ifa_next) {
		if (iter->ifa_addr == NULL) {
			continue;
		}
		if (iter->ifa_addr->sa_family != AF_INET6) {
			continue;
		}
		struct sockaddr_in6 *iter_sa = (struct sockaddr_in6 *)
			iter->ifa_addr;
		if (memcmp(if_addr, &iter_sa->sin6_addr, sizeof(struct
						in6_addr)) != 0) {
			continue;
		}

		/* got address */

		/* determine ifindex or bail out */
		if (iter->ifa_name == NULL) {
			break;
		}

		ret = if_nametoindex(iter->ifa_name);
	}

	/* address not found */
	freeifaddrs(addrs);

	return ret;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
	}

	char *if_addr_str = argv[1];

	struct in6_addr if_addr;
	if (inet_pton(AF_INET6, if_addr_str, &if_addr) != 1) {
		usage();
	}

	unsigned int ifidx = get_ifindex_for_addr(&if_addr);
	if (ifidx == 0) {
		perror("determining interface");
		return 2;
	}

	struct ipv6_eui64_addr *my_addr = (struct ipv6_eui64_addr *) &if_addr;

	/* bind to the address and RIP socket */
	struct ipxw_mux_msg *bind_msg = &rip_pkt_out.mux_msg;
	memset(bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg->type = IPXW_MUX_BIND;
	bind_msg->bind.addr.net = my_addr->ipx_net;
	memcpy(bind_msg->bind.addr.node, my_addr->ipx_node_fst,
			sizeof(my_addr->ipx_node_fst));
	memcpy(bind_msg->bind.addr.node + sizeof(my_addr->ipx_node_fst),
			my_addr->ipx_node_snd,
			sizeof(my_addr->ipx_node_snd));
	bind_msg->bind.addr.sock = htons(RIP_SOCK);
	bind_msg->bind.pkt_type = RIP_PKT_TYPE;
	bind_msg->bind.pkt_type_any = 0;
	bind_msg->bind.recv_bcast = 1;

	int data_sock = ipxw_mux_bind(bind_msg);
	if (data_sock < 0) {
		perror("bind");
		return 3;
	}
	printf("bind successful\n");

	/* clear out bind msg */
	memset(&rip_pkt_out, 0, sizeof(struct ipxw_mux_msg));

	/* pre-fill xmit msg, this is the same for all sent pkts */
	rip_pkt_out.mux_msg.type = IPXW_MUX_XMIT;
	rip_pkt_out.mux_msg.xmit.pkt_type = RIP_PKT_TYPE;
	rip_pkt_out.mux_msg.xmit.daddr.net = my_addr->ipx_net;
	memcpy(&rip_pkt_out.mux_msg.xmit.daddr.node, IPX_BCAST_NODE,
			sizeof(rip_pkt_out.mux_msg.xmit.daddr.node));
	rip_pkt_out.mux_msg.xmit.daddr.sock = htons(RIP_SOCK);

	/* pre-fill RIP type */
	rip_pkt_out.rip_type = htons(RIP_TYPE_RESPONSE);

	/* start a timer for sending periodic RIP responses */
	int tmr = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tmr < 0) {
		perror("creating timer");
		ipxw_mux_unbind(data_sock);
		return 4;
	}
	struct itimerspec tmr_spec = {
		.it_interval = { .tv_sec = RIP_UPDATE_TIMER },
		.it_value = { .tv_sec = 1 }
	};
	if (timerfd_settime(tmr, 0, &tmr_spec, NULL) < 0) {
		perror("arming timer");
		ipxw_mux_unbind(data_sock);
		close(tmr);
		return 5;
	}

	/* open the routing table */
	FILE *rtable = fopen(RTABLE_FILE, "r");
	if (rtable == NULL) {
		perror("open routing table");
		ipxw_mux_unbind(data_sock);
		close(tmr);
		return 6;
	}

	struct pollfd fds[2] = {
		{
			.fd = data_sock,
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
				ret = 7;
				break;
			}

			/* poll was interrupted, poll again */
			continue;
		}
		if (err == 0) {
			/* shouldn't happen */
			continue;
		}

		/* socket */
		if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			/* some other error */
			fprintf(stderr, "socket error\n");
			ret = 8;
			break;
		}
		/* we can read from the socket */
		if (fds[0].revents & POLLIN) {
			handle_rip_pkt(data_sock, my_addr, ifidx);
		}

		/* timer */
		if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			/* some other error */
			fprintf(stderr, "timer error\n");
			ret = 9;
			break;
		}
		/* the timer expired, send periodic RIP response */
		if (fds[1].revents & POLLIN) {
			if (send_rip_resp(data_sock, rtable, my_addr) < 0) {
				fprintf(stderr, "error sending packet\n");
			}
			/* consume all expirations */
			__u64 dummy;
			read(tmr, &dummy, sizeof(dummy));
		}
	}

	fclose(rtable);
	ipxw_mux_unbind(data_sock);
	close(tmr);

	return ret;
}
