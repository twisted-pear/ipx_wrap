#ifndef __IPX_WRAP_HELPERS_H__
#define __IPX_WRAP_HELPERS_H__

#include <stdio.h>

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

#endif /* __IPX_WRAP_HELPERS_H__ */
