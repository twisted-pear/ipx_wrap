#include <assert.h>

#include "ipx_wrap_helpers.h"

void print_ipx_if_addr(FILE *f, const struct ipx_if_addr *addr)
{
	fprintf(f, "%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
			ntohl(addr->net), addr->node[0], addr->node[1],
			addr->node[2], addr->node[3], addr->node[4],
			addr->node[5]);
}

void print_ipxaddr(FILE *f, const struct ipx_addr *addr)
{
	print_ipx_if_addr(f, (const struct ipx_if_addr *) addr);
	fprintf(f, ".%04hx", ntohs(addr->sock));
}

bool parse_ipx_node_addr(const char *str, __u8 addr[IPX_ADDR_NODE_BYTES])
{
	ssize_t res = sscanf(str, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
			&(addr[0]), &(addr[1]), &(addr[2]), &(addr[3]),
			&(addr[4]), &(addr[5]));
	if (res != 6) {
		return false;
	}

	return true;
}

bool parse_ipxaddr(const char *str, struct ipx_addr *addr)
{
	__u32 net;
	__u16 sock;
	ssize_t res = sscanf(str,
			"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx",
			&net, &(addr->node[0]), &(addr->node[1]),
			&(addr->node[2]), &(addr->node[3]), &(addr->node[4]),
			&(addr->node[5]), &sock);
	if (res != 8) {
		return false;
	}

	addr->net = htonl(net);
	addr->sock = htons(sock);

	return true;
}

bool get_bound_ipx_addr(struct ipxw_mux_handle h, struct ipx_addr *addr)
{
	/* prepare in message */
	struct ipxw_mux_msg in_msg;
	memset(&in_msg, 0, sizeof(in_msg));
	in_msg.type = IPXW_MUX_GETSOCKNAME;

	/* prepare out message */
	struct ipxw_mux_msg out_msg;
	memset(&out_msg, 0, sizeof(out_msg));
	out_msg.type = IPXW_MUX_CONF;

	ssize_t out_len = ipxw_mux_send_recv_conf_msg(h, &in_msg, &out_msg);
	if (out_len < 0) {
		return false;
	}

	/* verify output message */
	if (out_len != sizeof(out_msg)) {
		errno = EINVAL;
		return false;
	}
	if (out_msg.type != IPXW_MUX_GETSOCKNAME) {
		errno = EINVAL;
		return false;
	}

	*addr = out_msg.getsockname.addr;
	return true;
}

bool counted_msg_queue_empty(struct counted_msg_queue *q)
{
	bool ret = STAILQ_EMPTY(&(q->q));

	if (ret) {
		assert(q->n == 0);
	}

	return ret;
}

struct ipxw_mux_msg *counted_msg_queue_peek(struct counted_msg_queue *q)
{
	return STAILQ_FIRST(&(q->q));
}

struct ipxw_mux_msg *counted_msg_queue_pop(struct counted_msg_queue *q)
{
	struct ipxw_mux_msg *ret = STAILQ_FIRST(&(q->q));
	if (ret == NULL) {
		assert(q->n == 0);
		return NULL;
	}

	STAILQ_REMOVE_HEAD(&(q->q), q_entry);
	q->n--;

	return ret;
}

void counted_msg_queue_push(struct counted_msg_queue *q, struct ipxw_mux_msg
		*msg)
{
	STAILQ_INSERT_TAIL(&(q->q), msg, q_entry);
	q->n++;
}

size_t counted_msg_queue_nitems(struct counted_msg_queue *q)
{
	return q->n;
}
