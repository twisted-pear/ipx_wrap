#include <assert.h>
#include <linux/ipv6_route.h>
#include <linux/route.h>
#include <sys/ioctl.h>

#include "uthash.h"
#include "ipx_wrap_service_lib.h"

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

#define RIP_PKT_TYPE_REQUEST htons(1)
#define RIP_PKT_TYPE_RESPONSE htons(2)
#define RIP_DEFAULT_ROUTE htonl(0xFFFFFFFE)
#define RIP_ALL_ROUTES htonl(0xFFFFFFFF)

#define RIP_REQ_HOPS htons(0xFFFF)
#define RIP_REQ_TICKS htons(0xFFFF)

_Static_assert(RIP_MAX_ROUTES_PER_PKT <= (sizeof(__u64) * 8),
		"too many routes per packet");

struct rip_service_context {
	__be32 prefix;
	time_t last_update_bcast;
};

struct rip_entry {
	__be32 net;
	__be16 hops;
	__be16 ticks;
} __attribute__((packed));

struct rip_req_pkt {
	__be16 rip_type;
	struct rip_entry rip_entry;
};

struct rip_rsp_pkt {
	__be16 rip_type;
	struct rip_entry rip_entries[0];
};

static int add_route(__be32 net, struct ipx_addr *gw, __be32 hops, __be32
		prefix)
{
	struct in6_rtmsg rt;
	memset(&rt, 0x00, sizeof(rt));

	/* set destination net */
	struct ipv6_eui64_addr *ip6 = (struct ipv6_eui64_addr *) &rt.rtmsg_dst;
	ip6->prefix = prefix;

	if (net == RIP_DEFAULT_ROUTE) {
		/* insert the default route for everything in the prefix */
		/* network part remains 0 */

		/* set mask */
		rt.rtmsg_dst_len = 32;

	} else {
		/* insert a regular route for a single network */
		ip6->ipx_net = net;

		/* set mask */
		rt.rtmsg_dst_len = 64;
	}

	/* set gateway */
	ipx_to_ipv6_addr(&(rt.rtmsg_gateway), gw, prefix);

	/* set metric from the hopcount */
	rt.rtmsg_metric = ntohs(hops) * RIP_METRIC_MULT;

	/* we want to add the route, add flags */
	rt.rtmsg_flags = RTMSG_NEWROUTE | RTF_UP | RTF_GATEWAY | RTF_EXPIRES;
	rt.rtmsg_info = RIP_INVALID_TIMER * RIP_INVALID_TIMER_MULT;

	/* try to insert the route */
	int sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) {
		return -1;
	}

	int ret = 0;
	if (ioctl(sock, SIOCADDRT, &rt) < 0) {
		if (errno != EEXIST) {
			close(sock);
			return -1;
		}

		ret = 1;
	}

	close(sock);
	return ret;
}

static struct ipxw_mux_msg *mk_rip_request_for_iface(struct if_entry *iface,
		__be32 req_net)
{
	struct ipxw_mux_msg *req = calloc(1, sizeof(struct ipxw_mux_msg) +
			sizeof(struct rip_req_pkt));
	if (req == NULL) {
		return NULL;
	}
	struct rip_req_pkt *rip = (struct rip_req_pkt *) req->data;

	req->type = IPXW_MUX_XMIT;
	req->xmit.daddr.net = iface->addr.net;
	memcpy(req->xmit.daddr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES);
	req->xmit.daddr.sock = htons(RIP_SOCK);
	req->xmit.pkt_type = RIP_PKT_TYPE;
	req->xmit.data_len = sizeof(struct rip_req_pkt);
	rip->rip_type = RIP_PKT_TYPE_REQUEST;
	rip->rip_entry.net = req_net;
	rip->rip_entry.hops = RIP_REQ_HOPS;
	rip->rip_entry.ticks = RIP_REQ_TICKS;

	return req;
}

static struct ipxw_mux_msg *mk_rip_response_to_addr(struct ipx_addr *addr)
{
	struct ipxw_mux_msg *rsp = calloc(1, sizeof(struct ipxw_mux_msg) +
			sizeof(struct rip_rsp_pkt) + (sizeof(struct rip_entry)
				* RIP_MAX_ROUTES_PER_PKT));
	if (rsp == NULL) {
		return NULL;
	}
	struct rip_rsp_pkt *rip = (struct rip_rsp_pkt *) rsp->data;

	rsp->type = IPXW_MUX_XMIT;
	rsp->xmit.daddr.net = addr->net;
	memcpy(rsp->xmit.daddr.node, addr->node, IPX_ADDR_NODE_BYTES);
	rsp->xmit.daddr.sock = addr->sock;
	rsp->xmit.pkt_type = RIP_PKT_TYPE;
	rsp->xmit.data_len = sizeof(struct rip_rsp_pkt);
	rip->rip_type = RIP_PKT_TYPE_RESPONSE;

	return rsp;
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

	/* only advertise within the prefix */
	if (dst_prefix != my_prefix) {
		return 0;
	}

	/* special case for the default route */
	if (dst_mask == 32 && dst_net == 0) {
		dst_net = ntohl(RIP_DEFAULT_ROUTE);
		dst_mask = 64;
	}

	/* don't advertise strange subnets, we only support /64 */
	if (dst_mask != 64) {
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
		struct ipx_addr *daddr, int epoll_fd)
{
	struct ipxw_mux_msg *bcast = NULL;
	int i = 0;

	/* open the routing table */
	FILE *rtable = NULL;
	do {
		rtable = fopen(RTABLE_FILE, "r");
	} while (rtable == NULL && errno == EINTR);
	if (rtable == NULL) {
		return false;
	}

	while (1) {
		/* start a new broadcast packet */
		if (bcast == NULL) {
			bcast = mk_rip_response_to_addr(daddr);
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

static bool prepare_rip_response_for_iface(struct if_entry *iface, __be32
		prefix, struct ipx_addr *daddr, __be32 network, int epoll_fd)
{
	struct ipxw_mux_msg *rsp = mk_rip_response_to_addr(daddr);
	if (rsp == NULL) {
		return false;
	}

	/* open the routing table */
	FILE *rtable = NULL;
	do {
		rtable = fopen(RTABLE_FILE, "r");
	} while (rtable == NULL && errno == EINTR);
	if (rtable == NULL) {
		free(rsp);
		return false;
	}

	while (1) {
		struct rip_rsp_pkt *rip = (struct rip_rsp_pkt *) rsp->data;

		int err = get_next_rip_entry(rtable, &rip->rip_entries[0],
				ntohl(prefix), ntohl(iface->addr.net));
		if (err < 0) {
			/* end of routing table or error */
			fclose(rtable);
			free(rsp);
			return false;
		} else if (err == 0) {
			/* route not taken */
			continue;
		} else {
			/* not the network we're looking for */
			if (rip->rip_entries[0].net != network) {
				continue;
			}

			/* route taken */
			rsp->xmit.data_len += sizeof(struct rip_entry);
			break;
		}
	}

	assert(rsp != NULL);

	fclose(rtable);

	/* transmit last update packet */
	if (!queue_msg_on_iface(iface, rsp, epoll_fd)) {
		free(rsp);
		return false;
	}

	return true;
}

static void prepare_rip_propagate(struct if_entry *in_if, struct ipxw_mux_msg
		*in_msg, __be32 prefix, size_t nentries, __u64 prop_route_bits,
		int epoll_fd);

static void handle_rip_msg(struct ipxw_mux_msg *msg, struct if_entry *in_if,
		__be32 prefix, int epoll_fd)
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
	struct rip_req_pkt *rip_req_pkt = (struct rip_req_pkt *) msg->data;
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

			__u64 prop_route_bits = 0;
			size_t ninserted = 0;
			size_t i;
			for (i = 0; i < nentries; i++) {
				__be32 net = rip_rsp_pkt->rip_entries[i].net;
				__be16 hops = rip_rsp_pkt->rip_entries[i].hops;
				/* skip routes that have too many hops */
				if (ntohs(hops) > RIP_MAX_HOPS) {
					continue;
				}
				int route_status = add_route(net, gw, hops, prefix);
				if (route_status < 0) {
					fprintf(stderr, "\nfailed to add route "
							"for net %08x\n",
							ntohl(net));
				} else {
					ninserted++;

					/* new, previously unknown route, mark
					 * for propagation */
					if (route_status == 0) {
						prop_route_bits |= (1 << i);
					}
				}
			}

			fprintf(stderr, "added %lu of %lu routes", ninserted,
					nentries);

			if (msg->recv.is_bcast) {
				prepare_rip_propagate(in_if, msg, prefix,
						nentries, prop_route_bits,
						epoll_fd);
			}

			break;
		} else if (rip_rsp_pkt->rip_type == RIP_PKT_TYPE_REQUEST) {
			if (msg->recv.data_len != sizeof(struct rip_req_pkt)) {
				/* wrong size */
				fprintf(stderr, "request has invalid size");
				break;
			}

			if (rip_req_pkt->rip_entry.net == IPX_NET_ALL_ROUTES) {
				if (!prepare_rip_update_for_iface(in_if,
							prefix,
							&msg->recv.saddr,
							epoll_fd)) {
					fprintf(stderr, "\n");
					perror("sending RIP response");
				} else {
					fprintf(stderr, "sending response");
				}
				break;
			}

			if (!prepare_rip_response_for_iface(in_if, prefix,
						&msg->recv.saddr,
						rip_req_pkt->rip_entry.net,
						epoll_fd)) {
				fprintf(stderr, "\n");
				perror("sending RIP response");
			} else {
				fprintf(stderr, "sending response");
			}
		} else {
			fprintf(stderr, "type not supported");
			break;
		}
	} while(0);

	fprintf(stderr, ".\n");
}

struct per_iface_propagate_ctx {
	struct if_entry *in_if;
	struct ipxw_mux_msg *in_msg;
	size_t in_nentries;
	__u64 in_prop_route_bits;
	__be32 prefix;
	int epoll_fd;
};

static bool per_iface_rip_propagate(struct if_entry *iface, void *ctx)
{
	struct per_iface_propagate_ctx *per_if_ctx = ctx;

	if (iface == per_if_ctx->in_if) {
		return true;
	}

	struct ipx_addr out_bcast_addr = {
		.net = iface->addr.net,
		.sock = htons(RIP_SOCK)
	};
	memcpy(out_bcast_addr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES);
	struct ipxw_mux_msg *out_msg =
		mk_rip_response_to_addr(&out_bcast_addr);
	if (out_msg == NULL) {
		return false;
	}

	struct rip_rsp_pkt *in_rsp = (struct rip_rsp_pkt *)
		per_if_ctx->in_msg->data;
	struct rip_rsp_pkt *out_rsp = (struct rip_rsp_pkt *) out_msg->data;

	/* copy all routes, except the one for the interface's network into
	 * output packet */
	size_t i_out = 0;
	size_t i;
	for (i = 0; i < per_if_ctx->in_nentries && i <
			RIP_MAX_ROUTES_PER_PKT; i++) {
		__be32 net = in_rsp->rip_entries[i].net;
		__be16 hops = htons(ntohs(in_rsp->rip_entries[i].hops) + 1);
		__be16 ticks = htons(ntohs(in_rsp->rip_entries[i].ticks) + 1);

		/* don't send routes to the interface's own network */
		if (net == iface->addr.net) {
			continue;
		}

		/* route is already known, don't propagate */
		if (((1 << i) & per_if_ctx->in_prop_route_bits) == 0) {
			continue;
		}

		out_rsp->rip_entries[i_out].net = net;
		out_rsp->rip_entries[i_out].hops = hops;
		out_rsp->rip_entries[i_out].ticks = ticks;
		i_out++;
	}

	/* adjust packet length */
	out_msg->xmit.data_len += sizeof(struct rip_entry) * i_out;

	/* no routes for this interface */
	if (i_out == 0) {
		free(out_msg);
		return true;
	}

	/* propagate the routes */
	if (!queue_msg_on_iface(iface, out_msg, per_if_ctx->epoll_fd)) {
		free(out_msg);
		return false;
	}

	return true;
}

static void prepare_rip_propagate(struct if_entry *in_if, struct ipxw_mux_msg
		*in_msg, __be32 prefix, size_t nentries, __u64 prop_route_bits,
		int epoll_fd)
{
	struct per_iface_propagate_ctx ctx = {
		.in_if = in_if,
		.in_msg = in_msg,
		.in_nentries = nentries,
		.in_prop_route_bits = prop_route_bits,
		.prefix = prefix,
		.epoll_fd = epoll_fd
	};

	/* propagate in_msg to all other interfaces */
	for_each_iface(per_iface_rip_propagate, &ctx);
}

struct per_iface_update_ctx {
	__be32 prefix;
	int epoll_fd;
};

static bool per_iface_rip_update(struct if_entry *iface, void *ctx)
{
	struct per_iface_update_ctx *per_if_ctx = ctx;

	struct ipx_addr daddr = {
		.net = iface->addr.net,
		.sock = htons(RIP_SOCK)
	};
	memcpy(daddr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES);

	if (!prepare_rip_update_for_iface(iface, per_if_ctx->prefix, &daddr,
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

void service_ifup(struct if_entry *iface, int epoll_fd, void *ctx)
{
	struct ipxw_mux_msg *msg = mk_rip_request_for_iface(iface,
			IPX_NET_ALL_ROUTES);
	if (msg == NULL) {
		return;
	}

	if (!queue_msg_on_iface(iface, msg, epoll_fd)) {
		free(msg);
	}
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

void service_handle_signal(int signal)
{
	/* do nothing */
}

bool service_handle_msg(struct ipxw_mux_msg *msg, struct if_entry *iface, int
		epoll_fd, void *ctx)
{
	struct rip_service_context *service_ctx = ctx;

	handle_rip_msg(msg, iface, service_ctx->prefix, epoll_fd);

	return true;
}

bool service_reload(void *ctx)
{
	return true;
}

static _Noreturn void usage(void)
{
	printf("Usage: ipx_wrap_ripd <32-bit hex prefix>\n");
	exit(SRVC_ERR_USAGE);
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
