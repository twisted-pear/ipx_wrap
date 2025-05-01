#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

#define MAINTENANCE_INTERVAL_SECS 10
#define INTERFACE_RESCAN_SECS 30
#define MAX_EPOLL_EVENTS 64

#define SAP_SOCK 0x0452
#define SAP_PKT_TYPE 0x04
#define SAP_SRV_SHUTDOWN_HOPS htons(0x0010)
#define SAP_SRV_EXPIRY_SECS (60*5)
#define SAP_MAX_SRV_NAME_LEN 47
#define SAP_MAX_SRVS_PER_PKT 7 /* max observed */
#define SAP_BCAST_INTERVAL_SECS 60

#define SAP_SRV_TYPE_WILD htons(0xFFFF)

#define SAP_PKT_TYPE_GENERAL_SQ htons(1)
#define SAP_PKT_TYPE_NEAREST_SQ htons(3)
#define SAP_RSP_TYPE_PERIODIC_BC htons(2)
#define SAP_RSP_TYPE_GENERAL_SQ htons(2)
#define SAP_RSP_TYPE_NEAREST_SQ htons(4)

STAILQ_HEAD(ipxw_msg_queue, ipxw_mux_msg);

struct srv_data {
	__be16 srv_type;
	char srv_name[SAP_MAX_SRV_NAME_LEN + 1];
	struct ipx_addr srv_addr;
	__be16 hops;
} __attribute__((packed));

struct srv_type_and_name_key {
	__be16 srv_type;
	char srv_name[SAP_MAX_SRV_NAME_LEN + 1];
} __attribute__((packed));

struct srv_entry {
	struct srv_data data;
	/* hash entry */
	UT_hash_handle hh; /* by IPX addr */
	UT_hash_handle h_srv_type_and_name; /* by server type and name */
	/* list entry */
	TAILQ_ENTRY(srv_entry) type_list_entry; /* list per server type */
	/* last time the server transmitted an advertisement */
	time_t last_seen;
	__be32 learned_from_net;
};

struct srv_id_pkt {
	__be16 rsp_type;
	struct srv_data data[0];
} __attribute__((packed));

struct srv_query {
	__be16 pkt_type;
	__be16 srv_type;
} __attribute__((packed));

TAILQ_HEAD(srv_entries, srv_entry);

struct srv_type_list {
	/* server type */
	__be16 srv_type;
	/* hash entry */
	UT_hash_handle hh; /* by server type */
	/* list of servers of that type */
	struct srv_entries entries;
};

static struct srv_entry *ht_ipx_addr_to_srv = NULL;
static struct srv_entry *ht_srv_type_and_name_to_srv = NULL;
static struct srv_type_list *ht_srv_type_to_srv_list = NULL;

struct if_entry {
	/* the handle for the binding */
	struct ipxw_mux_handle mux_handle;
	/* ipx address we are bound to */
	struct ipx_addr addr;
	/* hash entry */
	UT_hash_handle h_data_sock; /* by data socket */
	UT_hash_handle h_ipx_addr; /* by IPX addr */
	/* msgs to send */
	struct ipxw_msg_queue out_queue;
	/* whether to keep the interface after the if-scan */
	bool keep;
};

static struct if_entry *ht_sock_to_if = NULL;
static struct if_entry *ht_ipx_addr_to_if = NULL;

static bool reload_now = false;
static bool keep_going = true;

static struct srv_type_list *get_srv_type_list(__be16 srv_type)
{
	struct srv_type_list *l;
	HASH_FIND(hh, ht_srv_type_to_srv_list, &srv_type, sizeof(srv_type), l);

	/* create new list entry for the server type */
	if (l == NULL) {
		l = calloc(1, sizeof(struct srv_type_list));
		if (l == NULL) {
			return NULL;
		}

		l->srv_type = srv_type;
		TAILQ_INIT(&l->entries);

		HASH_ADD(hh, ht_srv_type_to_srv_list, srv_type,
				sizeof(srv_type), l);
	}

	assert(l != NULL);
	assert(l->srv_type == srv_type);

	return l;
}

static int sort_srv_entry_by_last_seen(struct srv_entry *a, struct srv_entry
		*b)
{
	return a->last_seen - b->last_seen;
}

static bool prepare_srv_type_and_name_key(__be16 srv_type, const char
		*srv_name, struct srv_type_and_name_key *key)
{
	key->srv_type = srv_type;

	size_t srv_name_len = strlen(srv_name);
	if (srv_name_len > SAP_MAX_SRV_NAME_LEN) {
		return false;
	}

	memcpy(key->srv_name, srv_name, srv_name_len);
	memset(key->srv_name + srv_name_len, '\0', SAP_MAX_SRV_NAME_LEN -
			srv_name_len + 1);

	return true;
}

static struct srv_entry *get_srv_entry_by_ipx_addr(const struct ipx_addr *addr)
{
	struct srv_entry *e = NULL;
	HASH_FIND(hh, ht_ipx_addr_to_srv, addr, sizeof(*addr), e);
	return e;
}

static struct srv_entry *get_srv_entry_by_srv_type_and_name(__be16 srv_type,
		const char *srv_name)
{
	struct srv_type_and_name_key key;

	/* prepare the search key */
	if (!prepare_srv_type_and_name_key(srv_type, srv_name, &key)) {
		return NULL;
	}

	struct srv_entry *e = NULL;
	HASH_FIND(h_srv_type_and_name, ht_srv_type_and_name_to_srv, &key,
			sizeof(key), e);
	return e;
}

static void delete_srv_entry(struct srv_entry *e)
{
	struct srv_type_list *l = get_srv_type_list(e->data.srv_type);
	/* server type list must already exist */
	assert(l != NULL);

	HASH_DELETE(hh, ht_ipx_addr_to_srv, e);
	HASH_DELETE(h_srv_type_and_name, ht_srv_type_and_name_to_srv, e);
	TAILQ_REMOVE(&l->entries, e, type_list_entry);
	free(e);
}

static bool insert_srv_entry(struct srv_entry *e)
{
	/* service must not exist already */

	struct srv_entry *found_addr = get_srv_entry_by_ipx_addr(&e->data.srv_addr);
	assert(found_addr == NULL);

	struct srv_entry *found_type_and_name =
		get_srv_entry_by_srv_type_and_name(e->data.srv_type,
				e->data.srv_name);
	assert(found_type_and_name == NULL);

	/* add new entry to all the data structures */

	/* the by IPX addr hash */
	HASH_ADD_KEYPTR_INORDER(hh, ht_ipx_addr_to_srv, &e->data.srv_addr,
			sizeof(struct ipx_addr), e,
			sort_srv_entry_by_last_seen);

	/* the by server type and name hash */
	/* make sure the server name is NULL-terminated */
	e->data.srv_name[SAP_MAX_SRV_NAME_LEN] = '\0';
	struct srv_type_and_name_key *key = (struct srv_type_and_name_key *)
		&e->data.srv_type;
	HASH_ADD_KEYPTR(h_srv_type_and_name, ht_srv_type_and_name_to_srv, key,
			sizeof(*key), e);

	/* the by server type ordered list */
	struct srv_type_list *l = get_srv_type_list(e->data.srv_type);
	if (l == NULL) {
		return false;
	}

	bool inserted = false;
	struct srv_entry *i;
	TAILQ_FOREACH(i, &l->entries, type_list_entry) {
		/* insert before the first entry with a higher hop
		 * count */
		if (ntohs(i->data.hops) > ntohs(e->data.hops)) {
			TAILQ_INSERT_BEFORE(i, e, type_list_entry);
			inserted = true;
			break;
		}
	}

	/* no entries with a higher hop count, insert at the end */
	if (!inserted) {
		TAILQ_INSERT_TAIL(&l->entries, e, type_list_entry);
	}

	return true;
}

static bool update_srv_entry(struct srv_entry *e)
{
	/* try to find an existing entry by IPX addr... */
	struct srv_entry *found_addr = get_srv_entry_by_ipx_addr(&e->data.srv_addr);
	/* ... and by server type and name */
	struct srv_entry *found_type_and_name =
		get_srv_entry_by_srv_type_and_name(e->data.srv_type,
				e->data.srv_name);

	struct srv_entry *found = NULL;
	if (found_addr == NULL && found_type_and_name == NULL) {
		/* server does not exist yet */
		found = NULL;
	} else if (found_addr == NULL && found_type_and_name != NULL) {
		/* existing server changed address */
		found = found_type_and_name;
	} else if (found_addr != NULL && found_type_and_name == NULL) {
		/* existing server changed name or type */
		found = found_addr;
	} else if (found_addr != NULL && found_type_and_name != NULL) {
		/* server exists, no change in addr, name or type, only hop
		 * count might have changed */
		assert(found_addr == found_type_and_name);
		found = found_addr;

		/* if we got a server shutdown packet from the same network we
		 * received the server from, remove the server */
		if (found->learned_from_net == e->learned_from_net &&
				e->data.hops == SAP_SRV_SHUTDOWN_HOPS) {
			delete_srv_entry(found);
			return false;
		}
	} else {
		assert(0);
	}

	if (found != NULL) {
		/* we always replace existing entries with an entry from the
		 * config */
		if (e->learned_from_net != htonl(0)) {
			/* never update an entry from the config file */
			if (found->learned_from_net == htonl(0)) {
				return false;
			}

			/* if the old entry has a better hop count, discard the new
			 * entry */
			if (ntohs(found->data.hops) < ntohs(e->data.hops)) {
				return false;
			}
		}

		/* replace the entry */
		delete_srv_entry(found);
	}

	return insert_srv_entry(e);
}

static bool queue_msg_on_iface(struct if_entry *iface, struct ipxw_mux_msg
		*msg, int epoll_fd)
{
	int data_sock = ipxw_mux_handle_data(iface->mux_handle);

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data.fd = data_sock
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, data_sock, &ev) < 0) {
		return false;
	}

	/* queue the message on the interface */
	STAILQ_INSERT_TAIL(&iface->out_queue, msg, q_entry);

	return true;
}

static struct ipxw_mux_msg *mk_sap_bcast_pkt_for_iface(struct if_entry *iface)
{
	struct ipxw_mux_msg *bcast = calloc(1, sizeof(struct ipxw_mux_msg) +
			sizeof(struct srv_id_pkt) + (sizeof(struct srv_data) *
				SAP_MAX_SRVS_PER_PKT));
	if (bcast == NULL) {
		return false;
	}
	struct srv_id_pkt *sap = (struct srv_id_pkt *) bcast->data;

	bcast->type = IPXW_MUX_XMIT;
	bcast->xmit.daddr.net = iface->addr.net;
	memcpy(bcast->xmit.daddr.node, IPX_BCAST_NODE, IPX_ADDR_NODE_BYTES);
	bcast->xmit.daddr.sock = htons(SAP_SOCK);
	bcast->xmit.pkt_type = SAP_PKT_TYPE;
	bcast->xmit.data_len = sizeof(struct srv_id_pkt);
	sap->rsp_type = SAP_RSP_TYPE_PERIODIC_BC;

	return bcast;
}

static bool prepare_sap_bcast_for_iface(struct if_entry *iface, int epoll_fd)
{
	struct ipxw_mux_msg *bcast = NULL;
	int i = 0;

	struct srv_entry *se;
	struct srv_entry *stmp;
	HASH_ITER(hh, ht_ipx_addr_to_srv, se, stmp) {
		/* do not broadcast back to the interface from where we got the
		 * server */
		if (se->learned_from_net == iface->addr.net) {
			continue;
		}

		/* start a new broadcast packet */
		if (bcast == NULL) {
			bcast = mk_sap_bcast_pkt_for_iface(iface);
			if (bcast == NULL) {
				return false;
			}

			i = 0;
		}
		assert(bcast != NULL);

		struct srv_id_pkt *sap = (struct srv_id_pkt *) bcast->data;

		/* fill in the data from the entry */
		memcpy(&sap->data[i], &se->data, sizeof(struct srv_data));
		/* increase hop counter */
		sap->data[i].hops = htons(ntohs(sap->data[i].hops) + 1);
		bcast->xmit.data_len += sizeof(struct srv_data);

		/* ready for next entry */
		i++;

		/* broadcast packet is full, transmit */
		if (i >= SAP_MAX_SRVS_PER_PKT) {
			if (!queue_msg_on_iface(iface, bcast, epoll_fd)) {
				free(bcast);
				return false;
			}

			bcast = NULL;
		}
	}

	/* no broadcast packet left, all were transmitted */
	if (bcast == NULL) {
		return true;
	}

	/* transmit last broadcast packet */
	if (!queue_msg_on_iface(iface, bcast, epoll_fd)) {
		free(bcast);
		return false;
	}

	return true;
}

static void prepare_sap_bcasts(int epoll_fd)
{
	printf("Sending SAP broadcast.\n");

	/* prepare broadcast for all interfaces */
	struct if_entry *e;
	struct if_entry *tmp;
	HASH_ITER(h_data_sock, ht_sock_to_if, e, tmp) {
		if (!prepare_sap_bcast_for_iface(e, epoll_fd)) {
			perror("sending SAP bcast");
		}
	}
}

static ssize_t send_queued_msgs(struct if_entry *iface, int epoll_fd)
{
	int data_sock = ipxw_mux_handle_data(iface->mux_handle);

	/* no msgs to send */
	if (STAILQ_EMPTY(&iface->out_queue)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = data_sock
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, data_sock, &ev);

		return 0;
	}

	struct ipxw_mux_msg *xmit_msg = STAILQ_FIRST(&iface->out_queue);
	ssize_t err = ipxw_mux_xmit(iface->mux_handle, xmit_msg, false);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return 0;
		}

		/* other error, make sure to get rid of the message */
	}

	STAILQ_REMOVE_HEAD(&iface->out_queue, q_entry);
	free(xmit_msg);

	return err;
}

static void cleanup_iface(struct if_entry *iface)
{
	/* unbind from the muxer */
	ipxw_mux_unbind(iface->mux_handle);

	/* remove all undelivered messages */
	while (!STAILQ_EMPTY(&iface->out_queue)) {
		struct ipxw_mux_msg *msg = STAILQ_FIRST(&iface->out_queue);
		STAILQ_REMOVE_HEAD(&iface->out_queue, q_entry);
		free(msg);
	}

	/* remove the interface from all hash tables */
	HASH_DELETE(h_data_sock, ht_sock_to_if, iface);
	HASH_DELETE(h_ipx_addr, ht_ipx_addr_to_if, iface);

	free(iface);
}

static void cleanup_srv_type_list(struct srv_type_list *l)
{
	while (!TAILQ_EMPTY(&l->entries)) {
		struct srv_entry *e = TAILQ_FIRST(&l->entries);
		delete_srv_entry(e);
	}

	HASH_DELETE(hh, ht_srv_type_to_srv_list, l);
	free(l);
}

static _Noreturn void cleanup_and_exit(int tmr_fd, int epoll_fd, int exit_code)
{
	/* remove all interfaces */
	struct if_entry *e;
	struct if_entry *tmp;
	HASH_ITER(h_data_sock, ht_sock_to_if, e, tmp) {
		cleanup_iface(e);
	}

	/* clean up the database */
	struct srv_type_list *le;
	struct srv_type_list *ltmp;
	HASH_ITER(hh, ht_srv_type_to_srv_list, le, ltmp) {
		cleanup_srv_type_list(le);
	}

	/* close the timer fd */
	if (tmr_fd >= 0) {
		close(tmr_fd);
	}

	/* close down epoll fd */
	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	exit(exit_code);
}

static struct if_entry *add_iface(struct ipv6_eui64_addr *ipv6_addr, int
		epoll_fd)
{
	struct if_entry *iface = calloc(1, sizeof(struct if_entry));
	if (iface == NULL) {
		return NULL;
	}

	iface->addr.net = ipv6_addr->ipx_net;
	memcpy(iface->addr.node, ipv6_addr->ipx_node_fst,
			sizeof(ipv6_addr->ipx_node_fst));
	memcpy(iface->addr.node + sizeof(ipv6_addr->ipx_node_fst),
			ipv6_addr->ipx_node_snd,
			sizeof(ipv6_addr->ipx_node_snd));
	iface->addr.sock = htons(SAP_SOCK);

	STAILQ_INIT(&iface->out_queue);

	struct if_entry *iface_found = NULL;
	HASH_FIND(h_ipx_addr, ht_ipx_addr_to_if, &iface->addr,
			sizeof(iface->addr), iface_found);
	if (iface_found != NULL) {
		/* interface already exists */
		free(iface);
		return iface_found;
	}

	struct ipxw_mux_msg bind_msg;
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = iface->addr;
	bind_msg.bind.pkt_type = SAP_PKT_TYPE;
	bind_msg.bind.pkt_type_any = false;
	bind_msg.bind.recv_bcast = true;

	do {
		iface->mux_handle = ipxw_mux_bind(&bind_msg);
		if (ipxw_mux_handle_is_error(iface->mux_handle)) {
			break;
		}

		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP,
			.data = {
				.fd = ipxw_mux_handle_data(iface->mux_handle)
			}
		};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
					ipxw_mux_handle_data(iface->mux_handle),
					&ev) < 0)
		{
			break;
		}

		/* add new interface entry */
		HASH_ADD(h_ipx_addr, ht_ipx_addr_to_if, addr,
				sizeof(iface->addr), iface);
		HASH_ADD_KEYPTR(h_data_sock, ht_sock_to_if,
				&iface->mux_handle.data_sock,
				sizeof(iface->mux_handle.data_sock), iface);

		printf("adding interface "
				"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx\n",
				ntohl(iface->addr.net), iface->addr.node[0],
				iface->addr.node[1], iface->addr.node[2],
				iface->addr.node[3], iface->addr.node[4],
				iface->addr.node[5], ntohs(iface->addr.sock));

		return iface;
	} while (0);

	ipxw_mux_handle_close(iface->mux_handle);
	free(iface);

	return NULL;
}


/* FIXME: we cannot handle an address migrating from one interface to another,
 * but this should not happen with IPX anyway */
static bool scan_interfaces(__be32 prefix, int epoll_fd)
{
	/* iterate over all addresses to find the interface to our IPv6 addr */
	struct ifaddrs *addrs;
	struct ifaddrs *iter;

	int err = -1;
	do {
		err = getifaddrs(&addrs);
	} while (err < 0 && errno == EINTR);
	if (err < 0) {
		return false;
	}

	/* if the loop exits normally, we were unable to find the IPv6 addr */
	for (iter = addrs; iter != NULL; iter = iter->ifa_next) {
		if (iter->ifa_addr == NULL) {
			continue;
		}
		if (iter->ifa_addr->sa_family != AF_INET6) {
			continue;
		}

		struct sockaddr_in6 *iter_sa = (struct sockaddr_in6 *)
			iter->ifa_addr;
		struct ipv6_eui64_addr *ipv6_addr = (struct ipv6_eui64_addr *)
			&iter_sa->sin6_addr;
		if (ipv6_addr->prefix != prefix) {
			continue;
		}

		/* get or create a new interface for this address */
		struct if_entry *iface = add_iface(ipv6_addr, epoll_fd);
		/* an error occurred during interface creation, abort */
		if (iface == NULL) {
			freeifaddrs(addrs);
			return false;
		}

		/* mark the returned interface, so that we keep it */
		iface->keep = true;
	}

	freeifaddrs(addrs);

	struct if_entry *e;
	struct if_entry *tmp;
	HASH_ITER(h_ipx_addr, ht_ipx_addr_to_if, e, tmp) {
		if (!e->keep) {
			cleanup_iface(e);
		} else {
			e->keep = false;
		}
	}

	return true;
}

static int parse_next_line_from_cfg(FILE *cfg, struct srv_entry *e)
{
	char *line = NULL;
	size_t len;

	errno = 0;
	ssize_t res = getline(&line, &len, cfg);
	if (res < 0) {
		free(line);
		if (errno != 0) {
			perror("read config");
		}
		return -1;
	}

	/* skip comments and empty lines */
	if (len == 0 || line[0] == '#') {
		free(line);
		return 0;
	}

	__u32 srv_net;
	char srv_node[IPX_ADDR_NODE_BYTES];
	__u16 srv_sock;
	__u16 srv_hops;
	__u16 srv_type;
	char srv_name[SAP_MAX_SRV_NAME_LEN + 1];
#define __STRINGIFY__(X) #X
#define __STRINGIFY(X) __STRINGIFY__(X)
	res = sscanf(line, "%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx "
			"%04hx %04hx %" __STRINGIFY(SAP_MAX_SRV_NAME_LEN) "s",
			&srv_net, &srv_node[0], &srv_node[1], &srv_node[2],
			&srv_node[3], &srv_node[4], &srv_node[5], &srv_sock,
			&srv_hops, &srv_type, srv_name);
	free(line);
	if (res != 11) {
		fprintf(stderr, "failed to parse config entry\n");
		errno = EINVAL;
		return -1;
	}

	/* don't allow equivalent of server shutdown packet in the config */
	if (htons(srv_hops) == SAP_SRV_SHUTDOWN_HOPS) {
		fprintf(stderr, "config entry has invalid hop count\n");
		errno = EINVAL;
		return -1;
	}

	/* fill in the entry */

	memset(e, 0, sizeof(*e));

	/* fill in the data section */
	e->data.srv_addr.net = htonl(srv_net);
	memcpy(e->data.srv_addr.node, srv_node, IPX_ADDR_NODE_BYTES);
	e->data.srv_addr.sock = htons(srv_sock);
	e->data.hops = htons(srv_hops);
	e->data.srv_type = htons(srv_type);
	strncpy(e->data.srv_name, srv_name, SAP_MAX_SRV_NAME_LEN);

	/* fill in the meta data */
	e->last_seen = 0;
	e->learned_from_net = htonl(0);

	return 1;
}

static bool read_cfg(const char *cfg_path)
{
	/* remove all configured entries from the database */
	struct srv_entry *se;
	struct srv_entry *stmp;
	HASH_ITER(hh, ht_ipx_addr_to_srv, se, stmp) {
		if (se->learned_from_net == htonl(0)) {
			delete_srv_entry(se);
		}
	}

	FILE *cfg = NULL;
	do {
		cfg = fopen(cfg_path, "r");
	} while (cfg == NULL && errno == EINTR);

	if (cfg == NULL) {
		perror("opening config file");
		return false;
	}

	bool ret = false;
	int res = 0;
	for (;;) {
		struct srv_entry *e = calloc(1, sizeof(struct srv_entry));
		if (e == NULL) {
			break;
		}

		res = parse_next_line_from_cfg(cfg, e);

		/* error or EOF */
		if (res < 0) {
			free(e);
			if (errno == 0) {
				/* EOF */
				ret = true;
				break;
			}

			/* error */
			break;
		}

		/* entry was successfully parsed, try to insert it */
		if (res == 1) {
			if (!update_srv_entry(e)) {
				free(e);
				break;
			}

			continue;
		}

		/* line was not parsed because it was empty or a comment */
		if (res == 0) {
			free(e);
			continue;
		}

		assert(0);
	}

	fclose(cfg);
	return ret;
}

static int setup_timer(int epoll_fd, time_t secs)
{
	int tmr = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tmr < 0) {
		return -1;
	}

	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data = {
			.fd = tmr
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tmr, &ev) < 0) {
		close(tmr);
		return -1;
	}

	struct itimerspec tmr_spec = {
		.it_interval = { .tv_sec = secs },
		.it_value = { .tv_sec = secs }
	};
	if (timerfd_settime(tmr, 0, &tmr_spec, NULL) < 0) {
		close(tmr);
		return -1;
	}

	return tmr;
}

static bool get_now_secs(time_t *now_secs)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
		return false;
	}

	*now_secs = now.tv_sec;
	return true;
}

static bool is_timeout_expired(time_t now_secs, time_t timeout_secs, time_t last)
{
	time_t diff;
	__builtin_sub_overflow(now_secs, last, &diff);
	if (diff > timeout_secs) {
		return true;
	}

	return false;
}

static void timeout_srv_entries(time_t now_secs)
{
	struct srv_entry *se;
	struct srv_entry *stmp;
	HASH_ITER(hh, ht_ipx_addr_to_srv, se, stmp) {
		/* never delete entries from the config */
		if (se->learned_from_net == htonl(0)) {
			continue;
		}

		if (is_timeout_expired(now_secs, SAP_SRV_EXPIRY_SECS,
					se->last_seen))
		{
			delete_srv_entry(se);
		} else {
			/* entries are ordered by last_seen */
			break;
		}
	}
}

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGHUP:
			reload_now = true;
			break;
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			keep_going = false;
			break;
		default:
			assert(0);
	}
}

static _Noreturn void usage()
{
	printf("Usage: ipx_wrap_sapd <32-bit hex prefix> <cfg file>\n");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		usage();
	}

	__be32 prefix = htonl(strtoul(argv[1], NULL, 0));
	if (prefix == 0) {
		usage();
	}

	int epoll_fd = -1;
	int tmr_fd = -1;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(tmr_fd, epoll_fd, 2);
	}

	tmr_fd = setup_timer(epoll_fd, MAINTENANCE_INTERVAL_SECS);
	if (tmr_fd < 0) {
		perror("creating interface rescan timer");
		cleanup_and_exit(tmr_fd, epoll_fd, 3);
	}

	/* scan all interfaces for addresses within the prefix, we manage those
	 * interfaces */
	if (!scan_interfaces(prefix, epoll_fd)) {
		perror("adding interfaces");
		cleanup_and_exit(tmr_fd, epoll_fd, 4);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGHUP, &sig_act, NULL) < 0
			|| sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting signal handler");
		cleanup_and_exit(tmr_fd, epoll_fd, 5);
	}

	char *cfg_path = argv[2];
	if (!read_cfg(cfg_path)) {
		fprintf(stderr, "failed to read config file\n");
		cleanup_and_exit(tmr_fd, epoll_fd, 6);
	}

	time_t last_interface_scan = 0;
	time_t last_service_bcast = 0;
	time_t now_secs = 0;
	ssize_t err;
	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		/* received SIGHUP, do interface rescan and reload config */
		if (reload_now) {
			if (!scan_interfaces(prefix, epoll_fd)) {
				perror("scanning interfaces");
				cleanup_and_exit(tmr_fd, epoll_fd, 7);
			}

			if (!read_cfg(cfg_path)) {
				fprintf(stderr, "failed to read config file\n");
				cleanup_and_exit(tmr_fd, epoll_fd, 8);
			}

			reload_now = false;
		}

		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(tmr_fd, epoll_fd, 9);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(tmr_fd, epoll_fd, 10);
				}

				if (!get_now_secs(&now_secs)) {
					perror("getting current time");
					cleanup_and_exit(tmr_fd, epoll_fd, 11);
				}

				/* check if inferfaces need to be rescanned */
				if (is_timeout_expired(now_secs,
							INTERFACE_RESCAN_SECS,
							last_interface_scan)) {
					/* rescan the interfaces */
					if (!scan_interfaces(prefix, epoll_fd))
					{
						perror("scanning interfaces");
						cleanup_and_exit(tmr_fd,
								epoll_fd, 12);
					}
					last_interface_scan = now_secs;
				}

				/* check if we need to do the SAP broadcast */
				if (is_timeout_expired(now_secs,
							SAP_BCAST_INTERVAL_SECS,
							last_service_bcast)) {
					/* send the SAP broadcast on all
					 * interfaces */
					prepare_sap_bcasts(epoll_fd);
					last_service_bcast = now_secs;
				}

				/* remove expired server entries */
				timeout_srv_entries(now_secs);

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* one of the interface sockets */

			struct if_entry *iface;
			int data_sock = evs[i].data.fd;
			HASH_FIND(h_data_sock, ht_sock_to_if, &data_sock,
					sizeof(data_sock), iface);
			/* interface already deleted */
			if (iface == NULL) {
				continue;
			}

			/* can receive */
			if (evs[i].events & EPOLLIN) {
				// TODO
			}

			/* send queued pkts */
			if (evs[i].events & EPOLLOUT) {
				err = send_queued_msgs(iface, epoll_fd);
				if (err < 0) {
					/* get rid of the client */
					perror("recving data");
					cleanup_iface(iface);
					continue;
				} else if (err == 0) {
					/* nothing happened */
				}
			}

			/* something went wrong, remove interface */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "interface lost\n");
				cleanup_iface(iface);
				continue;
			}
		}
	}

	cleanup_and_exit(tmr_fd, epoll_fd, 0);

	return 0;
}
