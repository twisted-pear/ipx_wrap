#include <assert.h>

#include "uthash.h"
#include "ipx_wrap_service_lib.h"

#define MAINTENANCE_INTERVAL_SECS 10

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

struct sap_service_context {
	char *cfg_path;
	time_t last_service_bcast;
};

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

	size_t srv_name_len = strnlen(srv_name, SAP_MAX_SRV_NAME_LEN + 1);
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

static bool per_iface_sap_bcast(struct if_entry *iface, void *ctx)
{
	int epoll_fd = *((int *) ctx);

	if (!prepare_sap_bcast_for_iface(iface, epoll_fd)) {
		perror("sending SAP bcast");
	}

	return true;
}

static void prepare_sap_bcasts(int epoll_fd)
{
	printf("Sending SAP broadcast.\n");

	/* prepare broadcast for all interfaces */
	for_each_iface(per_iface_sap_bcast, &epoll_fd);
}

static ssize_t insert_srv_entries_from_sap_rsp(struct srv_id_pkt *sap_rsp,
		size_t nentries, __be32 in_net)
{
	time_t now_secs;
	if (!get_now_secs(&now_secs)) {
		return -1;
	}

	if (nentries > SAP_MAX_SRVS_PER_PKT) {
		return -1;
	}

	size_t ninserted = 0;

	size_t i;
	for (i = 0; i < nentries; i++) {
		struct srv_entry *e = calloc(1, sizeof(struct srv_entry));
		if (e == NULL) {
			continue;
		}

		memcpy(&e->data, &sap_rsp->data[i], sizeof(struct srv_data));
		e->learned_from_net = in_net;
		e->last_seen = now_secs;

		if (!update_srv_entry(e)) {
			free(e);
			continue;
		}

		ninserted++;
	}

	return ninserted;
}

static void handle_sap_msg(struct ipxw_mux_msg *msg, struct if_entry *in_if)
{
	fprintf(stderr, "Received SAP message from "
			"%08x.%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx.%04hx: ",
			ntohl(msg->recv.saddr.net), msg->recv.saddr.node[0],
			msg->recv.saddr.node[1], msg->recv.saddr.node[2],
			msg->recv.saddr.node[3], msg->recv.saddr.node[4],
			msg->recv.saddr.node[5], ntohs(msg->recv.saddr.sock));

	/* not a valid SAP message */
	if (msg->recv.data_len < sizeof(struct srv_id_pkt) &&
			msg->recv.data_len < sizeof(struct srv_query)) {
		fprintf(stderr, "invalid.\n");
		return;
	}

	struct srv_id_pkt *sap_rsp_pkt = (struct srv_id_pkt *) msg->data;
	struct srv_query *sap_query_pkt = (struct srv_query *) msg->data;
	do {
		if (sap_rsp_pkt->rsp_type == SAP_PKT_TYPE_GENERAL_SQ) {
			/* reply with all servers of the correct type */
			// TODO
			fprintf(stderr, "type not supported");
			break;
		} else if (sap_rsp_pkt->rsp_type == SAP_PKT_TYPE_NEAREST_SQ) {
			/* reply with the nearest server of the correct type */
			// TODO
			fprintf(stderr, "type not supported");
			break;
		} else if (sap_rsp_pkt->rsp_type == SAP_RSP_TYPE_NEAREST_SQ ||
			sap_rsp_pkt->rsp_type == SAP_RSP_TYPE_PERIODIC_BC ||
			sap_rsp_pkt->rsp_type == SAP_RSP_TYPE_GENERAL_SQ) {
			/* try to enter all services into the DB */

			if (msg->recv.data_len < sizeof(struct srv_id_pkt)) {
				/* too short */
				fprintf(stderr, "response too short");
				break;
			}

			if ((msg->recv.data_len - sizeof(struct srv_id_pkt)) %
					sizeof(struct srv_data) != 0) {
				/* incomplete server entries */
				fprintf(stderr, "response malformed");
				break;
			}

			size_t nentries = (msg->recv.data_len - sizeof(struct
						srv_id_pkt)) / sizeof(struct
						srv_data);

			size_t ninserted = insert_srv_entries_from_sap_rsp(
					sap_rsp_pkt, nentries,
					in_if->addr.net);

			if (ninserted < 0) {
				fprintf(stderr, "response malformed");
				break;
			}

			fprintf(stderr, "added %lu of %lu servers", ninserted,
					nentries);
			break;
		} else {
			/* invalid SAP message type */
			fprintf(stderr, "invalid type");
			break;
		}
	} while(0);

	fprintf(stderr, ".\n");
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

void service_cleanup_and_exit(void *ctx)
{
	/* clean up the database */
	struct srv_type_list *le;
	struct srv_type_list *ltmp;
	HASH_ITER(hh, ht_srv_type_to_srv_list, le, ltmp) {
		cleanup_srv_type_list(le);
	}
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
					se->last_seen)) {
			delete_srv_entry(se);
		}
	}
}

bool service_maintenance(void *ctx, time_t now_secs, int epoll_fd)
{
	assert(ctx != NULL);
	struct sap_service_context *service_ctx = ctx;

	/* check if we need to do the SAP broadcast */
	if (is_timeout_expired(now_secs, SAP_BCAST_INTERVAL_SECS,
				service_ctx->last_service_bcast)) {
		/* send the SAP broadcast on all
		 * interfaces */
		prepare_sap_bcasts(epoll_fd);
		service_ctx->last_service_bcast = now_secs;
	}

	/* remove expired server entries */
	timeout_srv_entries(now_secs);

	return true;
}

bool service_handle_msg(struct ipxw_mux_msg *msg, struct if_entry *iface, void
		*ctx)
{
	handle_sap_msg(msg, iface);

	return true;
}

bool service_reload(void *ctx)
{
	assert(ctx != NULL);
	struct sap_service_context *service_ctx = ctx;

	return read_cfg(service_ctx->cfg_path);
}

static _Noreturn void usage(void)
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

	struct sap_service_context service_ctx = {
		.cfg_path = argv[2],
		.last_service_bcast = 0
	};

	struct if_bind_config ifcfg = {
		.prefix = prefix,
		.sock = SAP_SOCK,
		.pkt_type = SAP_PKT_TYPE,
		.pkt_type_any = false,
		.recv_bcast = true
	};

	char *cfg_path = argv[2];
	if (!read_cfg(cfg_path)) {
		fprintf(stderr, "failed to read config file\n");
		cleanup_and_exit(-1, -1, &service_ctx, 6);
	}

	run_service(&service_ctx, &ifcfg, MAINTENANCE_INTERVAL_SECS);

	return 0;
}
