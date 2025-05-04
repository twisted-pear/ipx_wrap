#include <assert.h>
#include <linux/ipv6_route.h>
#include <linux/route.h>
#include <sys/ioctl.h>

#include "uthash.h"
#include "ipx_wrap_service_lib.h"

// TODO: send an initial request for all routes at interface startup?

#define MAINTENANCE_INTERVAL_SECS 10

#define RTABLE_FILE "/proc/net/ipv6_route"

#define RIP_SOCK 0x0453
#define RIP_PKT_TYPE 0x01
#define RIP_MAX_HOPS 15
#define RIP_UPDATE_TIMER 60
#define RIP_INVALID_TIMER 180
#define RIP_MAX_ROUTES_PER_PKT 50
#define RIP_METRIC_MULT 2048
#define RIP_INVALID_TIMER_MULT 100

#define RIP_PKT_TYPE_RESPONSE htons(2)

struct rip_service_context {
	__be32 prefix;
	time_t last_update_bcast;
};

struct rip_entry {
	__be32 net;
	__be16 hops;
	__be16 ticks;
} __attribute__((packed));

struct rip_rsp_pkt {
	__be16 rip_type;
	struct rip_entry rip_entries[0];
};

static bool add_route(__be32 net, struct ipx_addr *gw, __be32 hops, __be32
		prefix)
{
	struct in6_rtmsg rt;
	memset(&rt, 0x00, sizeof(rt));

	/* set destination net */
	struct ipv6_eui64_addr *ip6 = (struct ipv6_eui64_addr *) &rt.rtmsg_dst;
	ip6->prefix = prefix;
	ip6->ipx_net = net;

	/* set gateway */
	ip6 = (struct ipv6_eui64_addr *) &rt.rtmsg_gateway;
	ip6->prefix = prefix;
	ip6->ipx_net = gw->net;
	memcpy(ip6->ipx_node_fst, gw->node, sizeof(gw->node) / 2);
	ip6->fffe = htons(0xfffe);
	memcpy(ip6->ipx_node_snd, gw->node + (sizeof(gw->node) / 2),
			sizeof(gw->node) / 2);

	/* set mask */
	rt.rtmsg_dst_len = 64;

	/* set metric from the hopcount */
	rt.rtmsg_metric = ntohs(hops) * RIP_METRIC_MULT;

	/* we want to add the route, add flags */
	rt.rtmsg_flags = RTMSG_NEWROUTE | RTF_UP | RTF_GATEWAY | RTF_EXPIRES;
	rt.rtmsg_info = RIP_INVALID_TIMER * RIP_INVALID_TIMER_MULT;

	/* try to insert the route */
	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) {
		return false;
	}
	if (ioctl(sock, SIOCADDRT, &rt) < 0) {
		if (errno != EEXIST) {
			close(sock);
			return false;
		}
	}

	close(sock);
	return true;
}

static void handle_rip_msg(struct ipxw_mux_msg *msg, struct if_entry *in_if,
		__be32 prefix)
{
	fprintf(stderr, "Received RIP message from "
			"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx: ",
			ntohl(msg->recv.saddr.net), msg->recv.saddr.node[0],
			msg->recv.saddr.node[1], msg->recv.saddr.node[2],
			msg->recv.saddr.node[3], msg->recv.saddr.node[4],
			msg->recv.saddr.node[5], ntohs(msg->recv.saddr.sock));

	/* not a valid RIP message */
	if (msg->recv.data_len < sizeof(struct rip_rsp_pkt)) {
		fprintf(stderr, "invalid.\n");
		return;
	}

	struct rip_rsp_pkt *rip_rsp_pkt = (struct rip_rsp_pkt *) msg->data;
	do {
		if (rip_rsp_pkt->rip_type == RIP_PKT_TYPE_RESPONSE) {
			/* RIP response, fill routing table */
			if (msg->recv.data_len < sizeof(struct rip_rsp_pkt)) {
				/* too short */
				fprintf(stderr, "response too short");
				break;
			}

			if ((msg->recv.data_len - sizeof(struct rip_rsp_pkt)) %
					sizeof(struct rip_entry) != 0) {
				/* incomplete server entries */
				fprintf(stderr, "response malformed");
				break;
			}

			struct ipx_addr *gw = &msg->recv.saddr;
			size_t nentries = (msg->recv.data_len - sizeof(struct
						rip_rsp_pkt)) / sizeof(struct
						rip_entry);

			size_t ninserted = 0;
			size_t i;
			for (i = 0; i < nentries; i++) {
				__be32 net = rip_rsp_pkt->rip_entries[i].net;
				__be16 hops = rip_rsp_pkt->rip_entries[i].hops;
				/* skip routes that have too many hops */
				if (ntohs(hops) > RIP_MAX_HOPS) {
					continue;
				}
				if (!add_route(net, gw, hops, prefix)) {
					fprintf(stderr, "\nfailed to add route "
							"for net %08x\n",
							ntohl(net));
				} else {
					ninserted++;
				}
			}

			fprintf(stderr, "added %lu of %lu routes", ninserted,
					nentries);
			break;
		} else {
			// TODO
			fprintf(stderr, "type not supported");
			break;
		}
	} while(0);

	fprintf(stderr, ".\n");
}

static struct ipxw_mux_msg *mk_rip_update_pkt_for_iface(struct if_entry *iface)
{
	struct ipxw_mux_msg *bcast = calloc(1, sizeof(struct ipxw_mux_msg) +
			sizeof(struct rip_rsp_pkt) + (sizeof(struct rip_entry)
				* RIP_MAX_ROUTES_PER_PKT));
	if (bcast == NULL) {
		return false;
	}
	struct rip_rsp_pkt *rip = (struct rip_rsp_pkt *) bcast->data;

	bcast->type = IPXW_MUX_XMIT;
	bcast->xmit.daddr.net = iface->addr.net;
	memcpy(bcast->xmit.daddr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES);
	bcast->xmit.daddr.sock = htons(RIP_SOCK);
	bcast->xmit.pkt_type = RIP_PKT_TYPE;
	bcast->xmit.data_len = sizeof(struct rip_rsp_pkt);
	rip->rip_type = RIP_PKT_TYPE_RESPONSE;

	return bcast;
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
	res = sscanf(line, "%08x%08x%*16x %02hhx "
			"00000000000000000000000000000000 00 %08x%08x%*16x "
			"%08x",
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

static bool prepare_rip_update_for_iface(struct if_entry *iface, __be32 prefix,
		int epoll_fd)
{
	struct ipxw_mux_msg *bcast = NULL;
	int i = 0;

	/* open the routing table */
	FILE *rtable = NULL;
	do {
		rtable = fopen(RTABLE_FILE, "r");
	} while (rtable == NULL && errno == EINTR);
	if (rtable == NULL) {
		perror("open routing table");
		return false;
	}

	while (1) {
		/* start a new broadcast packet */
		if (bcast == NULL) {
			bcast = mk_rip_update_pkt_for_iface(iface);
			if (bcast == NULL) {
				fclose(rtable);
				return false;
			}

			i = 0;
		}
		assert(bcast != NULL);

		struct rip_rsp_pkt *rip = (struct rip_rsp_pkt *) bcast->data;

		int err = get_next_rip_entry(rtable, &rip->rip_entries[i],
				ntohl(prefix), ntohl(iface->addr.net));
		if (err < 0) {
			/* done or error */
			break;
		} else if (err == 0) {
			/* route not taken */
			continue;
		} else {
			/* route taken */
			bcast->xmit.data_len += sizeof(struct rip_entry);
			i++;
		}

		/* update packet is full, transmit */
		if (i >= RIP_MAX_ROUTES_PER_PKT) {
			if (!queue_msg_on_iface(iface, bcast, epoll_fd)) {
				free(bcast);
				fclose(rtable);
				return false;
			}

			bcast = NULL;
		}
	}

	fclose(rtable);

	/* no update packet left, all were transmitted */
	if (bcast == NULL) {
		return true;
	}

	/* transmit last update packet */
	if (!queue_msg_on_iface(iface, bcast, epoll_fd)) {
		free(bcast);
		return false;
	}

	return true;
}

struct per_iface_update_ctx {
	__be32 prefix;
	int epoll_fd;
};

static bool per_iface_rip_update(struct if_entry *iface, void *ctx)
{
	struct per_iface_update_ctx *per_if_ctx = ctx;

	if (!prepare_rip_update_for_iface(iface, per_if_ctx->prefix,
				per_if_ctx->epoll_fd)) {
		perror("sending RIP update");
	}

	return true;
}

static void prepare_rip_updates(__be32 prefix, int epoll_fd)
{
	printf("Sending RIP update.\n");

	struct per_iface_update_ctx ctx = {
		.prefix = prefix,
		.epoll_fd = epoll_fd
	};

	/* prepare broadcast for all interfaces */
	for_each_iface(per_iface_rip_update, &ctx);
}

void service_cleanup_and_exit(void *ctx)
{
	/* do nothing */
}

bool service_maintenance(void *ctx, time_t now_secs, int epoll_fd)
{
	assert(ctx != NULL);
	struct rip_service_context *service_ctx = ctx;

	/* check if we need to do the route broadcast */
	if (is_timeout_expired(now_secs, RIP_UPDATE_TIMER,
				service_ctx->last_update_bcast)) {
		/* send the RIP update on all interfaces */
		prepare_rip_updates(service_ctx->prefix, epoll_fd);
		service_ctx->last_update_bcast = now_secs;
	}

	return true;
}

bool service_handle_msg(struct ipxw_mux_msg *msg, struct if_entry *iface, void
		*ctx)
{
	struct rip_service_context *service_ctx = ctx;

	handle_rip_msg(msg, iface, service_ctx->prefix);

	return true;
}

bool service_reload(void *ctx)
{
	return true;
}

static _Noreturn void usage(void)
{
	printf("Usage: ipx_wrap_ripd <32-bit hex prefix>\n");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage();
	}

	__be32 prefix = htonl(strtoul(argv[1], NULL, 0));
	if (prefix == 0) {
		usage();
	}

	struct rip_service_context service_ctx = {
		.prefix = prefix,
		.last_update_bcast = 0
	};

	struct if_bind_config ifcfg = {
		.prefix = prefix,
		.sock = RIP_SOCK,
		.pkt_type = RIP_PKT_TYPE,
		.pkt_type_any = false,
		.recv_bcast = true
	};

	run_service(&service_ctx, &ifcfg, MAINTENANCE_INTERVAL_SECS);

	return 0;
}
