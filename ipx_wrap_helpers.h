#ifndef __IPX_WRAP_HELPERS_H__
#define __IPX_WRAP_HELPERS_H__

#include <stdio.h>
#include <sys/queue.h>

#include "ipx_wrap_mux_proto.h"

struct ipx_if_addr {
	__be32 net;
	__u8 node[IPX_ADDR_NODE_BYTES];
} __attribute__((packed));

void print_ipx_if_addr(FILE *f, const struct ipx_if_addr *addr);
void print_ipxaddr(FILE *f, const struct ipx_addr *addr);

bool parse_ipx_node_addr(const char *str, __u8 addr[IPX_ADDR_NODE_BYTES]);
bool parse_ipxaddr(const char *str, struct ipx_addr *addr);

bool get_bound_ipx_addr(struct ipxw_mux_handle h, struct ipx_addr *addr);

STAILQ_HEAD(ipxw_msg_queue, ipxw_mux_msg);

struct counted_msg_queue {
	struct ipxw_msg_queue q;
	size_t n;
};

#define counted_msg_queue_init(qname) { .q = STAILQ_HEAD_INITIALIZER(qname.q), .n = 0 }

bool counted_msg_queue_empty(struct counted_msg_queue *q);
size_t counted_msg_queue_nitems(struct counted_msg_queue *q);

struct ipxw_mux_msg *counted_msg_queue_peek(struct counted_msg_queue *q);
struct ipxw_mux_msg *counted_msg_queue_pop(struct counted_msg_queue *q);
void counted_msg_queue_push(struct counted_msg_queue *q, struct ipxw_mux_msg
		*msg);

#endif /* __IPX_WRAP_HELPERS_H__ */
