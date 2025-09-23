#include <assert.h>
#include <float.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "uthash.h"
#include "ipx_wrap_ping.h"
#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define DEFAULT_DATA_LEN 12
#define MIN_PING_INTERVAL 0.002

enum ipxping_error_codes {
	IPXPING_ERR_OK = 0,
	IPXPING_ERR_USAGE,
	IPXPING_ERR_EPOLL_FD,
	IPXPING_ERR_TMR_FD,
	IPXPING_ERR_GETRANDOM,
	IPXPING_ERR_CONF_FD,
	IPXPING_ERR_IPX_FD,
	IPXPING_ERR_SIG_HANDLER,
	IPXPING_ERR_BIND,
	IPXPING_ERR_RX_TX_TSTAMPS,
	IPXPING_ERR_GETSOCKNAME,
	IPXPING_ERR_GET_OIF_DATA_LEN,
	IPXPING_ERR_OIF_DATA_LEN_ZERO,
	IPXPING_ERR_GETTIME,
	IPXPING_ERR_EPOLL_WAIT,
	IPXPING_ERR_TMR_FAILURE,
	IPXPING_ERR_CONF_FAILURE,
	IPXPING_ERR_IPX_FAILURE,
	IPXPING_ERR_INTERVAL_TOO_SMALL,
	IPXPING_ERR_MAX
};

struct ping_wait {
	/* ID field of the Ping/Pong message */
	__u16 id;
	/* hash entry */
	UT_hash_handle hh; /* by Ping ID */
	/* whether we already have the TX timestamp */
	bool have_tx_ts;
	/* TX timestamp of the Ping message */
	struct __kernel_timespec tx_ts;
	/* whether we have already seen a reply to this Ping */
	bool have_reply;
	/* data length of the Ping message */
	__u16 data_len;
};

struct ping_wait *ht_id_to_ping_wait = NULL;

#define MAX_EPOLL_EVENTS 64

#define CTRL_DATA_LEN 1024

struct ipxping_stats {
	struct timespec time_start;
	struct timespec time_end;
	double rtt_min;
	double rtt_max;
	double rtt_sum;
	double rtt_sq_sum;
	__u32 n_pings;
	__u32 n_pongs;
	__u32 n_pings_with_replies;
};

struct ipxping_cfg {
	bool verbose;
	bool rx_pkt_type_any;
	__u8 tx_pkt_type;
	double interval;
	__u16 data_len;
	__u32 max_pings;
	struct ipx_addr local_addr;
	struct ipx_addr remote_addr;
	__u16 proc_id;
	__u16 cur_msg_id;
	__u32 n_pings;
};

static bool keep_going = true;

static struct ipxw_mux_handle ipxh = ipxw_mux_handle_init;

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			keep_going = false;
			break;
		default:
			assert(0);
	}
}

static int setup_timer(int epoll_fd, struct timespec *interval)
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
		.it_interval = *interval,
		.it_value = { .tv_sec = 0, .tv_nsec = 1 }
	};
	if (timerfd_settime(tmr, 0, &tmr_spec, NULL) < 0) {
		close(tmr);
		return -1;
	}

	return tmr;
}

static _Noreturn void cleanup_and_exit(int epoll_fd, int tmr_fd, struct
		ipxping_cfg *cfg, enum ipxping_error_codes code)
{
	if (tmr_fd >= 0) {
		close(tmr_fd);
	}

	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	/* remove all pings we are still waiting for */
	struct ping_wait *pe;
	struct ping_wait *ptmp;
	HASH_ITER(hh, ht_id_to_ping_wait, pe, ptmp) {
		HASH_DELETE(hh, ht_id_to_ping_wait, pe);
		free(pe);
	}

	ipxw_mux_unbind(ipxh);

	exit(code);
}

static bool send_ping(struct ipxping_cfg *cfg, struct ipxping_stats *stats)
{
	struct ping_wait *ping_wait = NULL;
	HASH_FIND(hh, ht_id_to_ping_wait, &(cfg->cur_msg_id), sizeof(__u16),
			ping_wait);
	/* delete previous wait entry with this ID, thus expiring it */
	if (ping_wait != NULL) {
		HASH_DELETE(hh, ht_id_to_ping_wait, ping_wait);
		free(ping_wait);
		ping_wait = NULL;
	}

	struct ipxw_mux_msg *ping_msg = calloc(1, sizeof(struct ipxw_mux_msg) +
			sizeof(struct ping_pkt) + cfg->data_len);
	if (ping_msg == NULL) {
		return false;
	}

	/* build the ping packet */

	ping_msg->type = IPXW_MUX_XMIT;
	ping_msg->xmit.daddr = cfg->remote_addr;
	ping_msg->xmit.pkt_type = cfg->tx_pkt_type;
	ping_msg->xmit.data_len = sizeof(struct ping_pkt) + cfg->data_len;

	struct ping_pkt *ping_pkt = (struct ping_pkt *) ping_msg->data;
	memcpy(ping_pkt->ping, PING_STR, PING_STR_LEN);
	ping_pkt->version = PING_VERSION;
	ping_pkt->type = PING_TYPE_QUERY;
	ping_pkt->id = htons(cfg->cur_msg_id);
	ping_pkt->result = PING_RESULT_QUERY;

	do {
		/* allocate the data structure to record the ping */
		ping_wait = calloc(1, sizeof(struct ping_wait));
		if (ping_wait == NULL) {
			break;
		}

		/* set timestamp ID, this will be used to retrieve the TX timestamp */
		__u32 ts_id = (cfg->proc_id << 16) | cfg->cur_msg_id;

		__u8 ctrl_data[CTRL_DATA_LEN];
		ssize_t ctrl_data_len = ipxw_mux_set_tx_timestamp_id(ctrl_data,
				CTRL_DATA_LEN, ts_id);
		if (ctrl_data_len < 0) {
			break;
		}

		/* send the ping */
		ssize_t sent_len = ipxw_mux_xmit_with_ctrl(ipxh, ping_msg, false,
				ctrl_data, ctrl_data_len);
		if (sent_len < 0) {
			break;
		}

		/* record the sent ping, so that we can receive the TX
		 * timestamp and replies */
		ping_wait->id = cfg->cur_msg_id;
		ping_wait->have_tx_ts = false;
		ping_wait->data_len = cfg->data_len;
		HASH_ADD(hh, ht_id_to_ping_wait, id, sizeof(__u16), ping_wait);

		/* increase ID for next packet */
		cfg->cur_msg_id++;

		/* increase the number of sent Pings */
		cfg->n_pings++;

		/* update stats */
		stats->n_pings++;

		free(ping_msg);
		return true;
	} while (0);

	free(ping_msg);
	if (ping_wait != NULL) {
		free(ping_wait);
	}

	return false;
}

static bool recv_ping_tx_ts(struct ipxping_cfg *cfg)
{
	struct __kernel_timespec tx_ts;
	__u32 tx_ts_id;

	if (!ipxw_mux_get_tx_timestamp(ipxh, &tx_ts, &tx_ts_id, false)) {
		return false;
	}

	__u16 proc_id = tx_ts_id >> 16;
	__u16 ping_id = tx_ts_id & 0xFFFF;

	/* timestamp is for different process */
	if (proc_id != cfg->proc_id) {
		if (cfg->verbose) {
			fprintf(stderr, "timestamp process ID mismatch\n");
		}
		errno = EINVAL;
		return false;
	}

	struct ping_wait *ping_wait;
	HASH_FIND(hh, ht_id_to_ping_wait, &ping_id, sizeof(ping_id),
			ping_wait);
	/* timestamp is for ping which does not exist */
	if (ping_wait == NULL) {
		if (cfg->verbose) {
			fprintf(stderr, "got TX timestamp for nonexistent "
					"ping %hu\n", ping_id);
		}
		errno = EINVAL;
		return false;
	}

	/* timestamp is for ping which already has a TX timestamp */
	if (ping_wait->have_tx_ts) {
		if (cfg->verbose) {
			fprintf(stderr, "got duplicate TX timestamp for ping "
					" %hu\n", ping_id);
		}
		errno = EINVAL;
		return false;
	}

	/* record TX timestamp */
	ping_wait->have_tx_ts = true;
	ping_wait->tx_ts = tx_ts;

	return true;
}

static bool recv_pong(struct ipxping_cfg *cfg, struct ipxping_stats *stats)
{
	ssize_t expected_msg_len = ipxw_mux_peek_recvd_len(ipxh, false);
	if (expected_msg_len < 0) {
		if (errno == EINTR) {
			return true;
		}

		return false;
	}

	struct ipxw_mux_msg *msg = calloc(1, expected_msg_len + 1);
	if (msg == NULL) {
		return false;
	}

	__u8 cmsg_data[CTRL_DATA_LEN];
	msg->type = IPXW_MUX_RECV;
	msg->recv.data_len = expected_msg_len - sizeof(struct ipxw_mux_msg);
	ssize_t rcvd_len = ipxw_mux_get_recvd_with_ctrl(ipxh, msg, false,
			cmsg_data, CTRL_DATA_LEN);
	if (rcvd_len < 0) {
		free(msg);
		if (errno == EINTR) {
			return true;
		}

		return false;
	}

	/* need at least a full Ping msg */
	size_t data_len = msg->recv.data_len;
	if (data_len < sizeof(struct ping_pkt)) {
		if (cfg->verbose) {
			fprintf(stderr, "received truncated Pong from ");
			print_ipxaddr(stderr, &(msg->recv.saddr));
			fprintf(stderr, "\n");
		}

		free(msg);
		return true;
	}

	/* save out relevant data to the Pong */
	struct ipx_addr pong_saddr = msg->recv.saddr;
	__u8 pong_tc = msg->recv.tc;

	struct ping_pkt *pong_pkt = (struct ping_pkt *) msg->data;
	__u8 pong_type = pong_pkt->type;
	__u16 pong_id = ntohs(pong_pkt->id);
	size_t pong_data_len = msg->recv.data_len - sizeof(struct ping_pkt);
	free(msg);

	if (pong_type != PING_TYPE_REPLY) {
		if (cfg->verbose) {
			fprintf(stderr, "received malformed Pong from ");
			print_ipxaddr(stderr, &pong_saddr);
			fprintf(stderr, "\n");
		}

		return true;
	}

	struct __kernel_timespec pong_rx_ts;
	if (!ipxw_mux_get_rx_timestamp(cmsg_data, CTRL_DATA_LEN, &pong_rx_ts))
	{
		if (cfg->verbose) {
			fprintf(stderr, "failed to get RX timestamp for Pong from ");
			print_ipxaddr(stderr, &pong_saddr);
			fprintf(stderr, "\n");
		}

		return true;
	}

	struct ping_wait *ping_wait;
	HASH_FIND(hh, ht_id_to_ping_wait, &pong_id, sizeof(pong_id),
			ping_wait);
	if (ping_wait == NULL) {
		if (cfg->verbose) {
			fprintf(stderr, "received unexpected Pong from ");
			print_ipxaddr(stderr, &pong_saddr);
			fprintf(stderr, "\n");
		}

		return true;
	}

	/* update stats */
	if (!ping_wait->have_reply) {
		ping_wait->have_reply = true;
		stats->n_pings_with_replies++;
	}

	printf("%lu bytes from ", pong_data_len + sizeof(struct ping_pkt));
	print_ipxaddr(stdout, &pong_saddr);
	printf(": id=%hu tc=%hhu time=", pong_id, pong_tc);
	if (!ping_wait->have_tx_ts) {
		printf("unknown\n");
	} else {
		double rtt = (pong_rx_ts.tv_sec - ping_wait->tx_ts.tv_sec) +
			1.0e-9 * (pong_rx_ts.tv_nsec -
					ping_wait->tx_ts.tv_nsec);

		/* update stats */
		stats->n_pongs++;
		stats->rtt_sum += rtt;
		stats->rtt_sq_sum += rtt * rtt;
		if (rtt < stats->rtt_min) {
			stats->rtt_min = rtt;
		}
		if (rtt > stats->rtt_max) {
			stats->rtt_max = rtt;
		}

		printf("%.3f ms\n", rtt * 1000);
	}

	return true;
}

static void print_stats(struct ipxping_stats *stats, struct ipx_addr
		*remote_addr)
{
	printf("\n--- ");
	print_ipxaddr(stdout, remote_addr);
	printf(" ping statistics ---\n");

	double loss = 0.0;
	if (stats->n_pings > 0) {
		loss = ((stats->n_pings - stats->n_pings_with_replies) /
				stats->n_pings) * 100;
	}

	double runtime_s = (stats->time_end.tv_sec - stats->time_start.tv_sec)
		+ 1.0e-9 * (stats->time_end.tv_nsec -
				stats->time_start.tv_nsec);

	double avg = 0.0;
	double mdev = 0.0;
	if (stats->n_pongs > 0) {
		avg = stats->rtt_sum / stats->n_pongs;
		mdev = sqrtl((stats->rtt_sq_sum / stats->n_pongs) - (avg *
					avg));
	}

	printf("%u packets transmitted, %u received, %.0f%% packet loss, time "
			"%.0fms\n", stats->n_pings, stats->n_pongs, loss,
			runtime_s * 1000);
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
			stats->rtt_min * 1000, avg * 1000, stats->rtt_max *
			1000, mdev * 1000);
}

static _Noreturn void do_ipxping(struct ipxping_cfg *cfg, int epoll_fd, int
		tmr_fd)
{
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = cfg->tx_pkt_type;
	bind_msg.bind.pkt_type_any = cfg->rx_pkt_type_any;
	bind_msg.bind.recv_bcast = false;

	ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXPING_ERR_BIND);
	}

	if (!ipxw_mux_enable_timestamps(ipxh, true, true)) {
		perror("timestamps");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg,
				IPXPING_ERR_RX_TX_TSTAMPS);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->local_addr))) {
			perror("IPX get bound address");
			cleanup_and_exit(epoll_fd, tmr_fd, cfg,
					IPXPING_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "bound to ");
		print_ipxaddr(stderr, &(cfg->local_addr));
		fprintf(stderr, "\n");
	}

	int max_oif_data_len = ipxw_get_outif_max_ipx_data_len_for_dst(ipxh,
			&(cfg->remote_addr));
	if (max_oif_data_len < 0) {
		perror("getting output interface max data length");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg,
				IPXPING_ERR_GET_OIF_DATA_LEN);
	}
	if (max_oif_data_len < sizeof(struct ping_pkt)) {
		fprintf(stderr, "output interface MTU too small\n");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg,
				IPXPING_ERR_OIF_DATA_LEN_ZERO);
	}

	size_t max_oif_ping_data_len = max_oif_data_len - sizeof(struct
			ping_pkt);
	if (cfg->data_len > max_oif_ping_data_len) {
		if (cfg->verbose) {
			fprintf(stderr, "output interface MTU too "
					"small for %hu bytes of data, "
					"reducing to %lu\n",
					cfg->data_len, max_oif_ping_data_len);
		}
		cfg->data_len = max_oif_ping_data_len;
	}

	struct epoll_event ev = {
		.events = EPOLLERR | EPOLLHUP,
		.data = {
			.fd = ipxw_mux_handle_conf(ipxh)
		}
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_conf(ipxh), &ev)
			< 0) {
		perror("registering config socket for event polling");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXPING_ERR_CONF_FD);
	}

	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = ipxw_mux_handle_data(ipxh);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_data(ipxh), &ev)
			< 0) {
		perror("registering IPX socket for event polling");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXPING_ERR_IPX_FD);
	}

	struct ipxping_stats stats = {
		.rtt_min = DBL_MAX,
		.rtt_max = 0,
		.rtt_sum = 0,
		.rtt_sq_sum = 0,
		.n_pings = 0,
		.n_pongs = 0,
		.n_pings_with_replies = 0
	};

	if (clock_gettime(CLOCK_MONOTONIC, &(stats.time_start)) != 0) {
		perror("getting start time");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXPING_ERR_GETTIME);
	}

	printf("PING ");
	print_ipxaddr(stdout, &(cfg->remote_addr));
	printf(" %hu data bytes\n", cfg->data_len);

	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno == EINTR) {
				continue;
			}

			perror("event polling");
			cleanup_and_exit(epoll_fd, tmr_fd, cfg,
					IPXPING_ERR_EPOLL_WAIT);
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* timer fd */
			if (evs[i].data.fd == tmr_fd) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "timer fd error\n");
					cleanup_and_exit(epoll_fd, tmr_fd, cfg,
							IPXPING_ERR_TMR_FAILURE);
				}

				/* if the maximum number of Pings was reached,
				 * exit */
				if (cfg->max_pings != 0) {
					if (cfg->n_pings >= cfg->max_pings) {
						keep_going = false;
					}
				}

				/* send a ping */
				if (!send_ping(cfg, &stats)) {
					perror("sending Ping");
				}

				/* consume all expirations */
				__u64 dummy;
				read(tmr_fd, &dummy, sizeof(dummy));

				continue;
			}

			/* config socket */
			if (evs[i].data.fd == ipxw_mux_handle_conf(ipxh)) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "config socket error\n");
					cleanup_and_exit(epoll_fd, tmr_fd, cfg,
							IPXPING_ERR_CONF_FAILURE);
				}

				continue;
			}

			/* IPX socket */

			/* something went wrong */
			if (evs[i].events & EPOLLHUP) {
				fprintf(stderr, "IPX socket error\n");
				cleanup_and_exit(epoll_fd, tmr_fd, cfg,
						IPXPING_ERR_IPX_FAILURE);
			}

			/* try to get a TX timestamp */
			if (evs[i].events & EPOLLERR) {
				/* receive TX timestamp */
				if (!recv_ping_tx_ts(cfg)) {
					if (cfg->verbose) {
						perror("receiving TX timestamp");
					}
				}

				continue;
			}

			/* nothing to read from IPX socket */
			if ((evs[i].events & EPOLLIN) == 0) {
				continue;
			}

			/* receive and match incoming pongs to pings */
			if (!recv_pong(cfg, &stats)) {
				perror("receiving Pong");
			}

			continue;
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &(stats.time_end)) != 0) {
		perror("getting end time");
		cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXPING_ERR_GETTIME);
	}

	print_stats(&stats, &(cfg->remote_addr));

	cleanup_and_exit(epoll_fd, tmr_fd, cfg, IPXPING_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: ipxping [-v] [-i <interval seconds>] [-c <count>] [-d <maximum data bytes>] [-t <packet type>] [-a] <local IPX address> <remote IPX address>\n");
	exit(IPXPING_ERR_USAGE);
}

static bool verify_cfg(struct ipxping_cfg *cfg)
{
	if (cfg->data_len > IPX_MAX_DATA_LEN - sizeof(struct ping_pkt)) {
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	struct ipxping_cfg cfg = {
		.verbose = false,
		.rx_pkt_type_any = false,
		.tx_pkt_type = PING_PKT_TYPE,
		.interval = 1.0,
		.data_len = DEFAULT_DATA_LEN,
		.max_pings = 0,
		.proc_id = 0,
		.cur_msg_id = 0,
		.n_pings = 0
	};

	/* parse and verify command-line arguments */

	int opt;
	while ((opt = getopt(argc, argv, "ac:d:i:t:v")) != -1) {
		switch (opt) {
			case 'a':
				cfg.rx_pkt_type_any = true;
				break;
			case 'c':
				cfg.max_pings = strtoul(optarg, NULL, 0);
				break;
			case 'd':
				cfg.data_len = strtoul(optarg, NULL, 0);
				break;
			case 'i':
				cfg.interval = strtod(optarg, NULL);
				break;
			case 't':
				cfg.tx_pkt_type = strtoul(optarg, NULL, 0);
				break;
			case 'v':
				cfg.verbose = true;
				break;
			default:
				usage();
		}
	}

	if (optind + 2 != argc) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind], &(cfg.local_addr))) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind + 1], &(cfg.remote_addr))) {
		usage();
	}

	if (!verify_cfg(&cfg)) {
		usage();
	}

	if (cfg.interval < MIN_PING_INTERVAL) {
		fprintf(stderr, "Ping interval too small\n");
		cleanup_and_exit(-1, -1, &cfg, IPXPING_ERR_INTERVAL_TOO_SMALL);
	}

	/* initial setup */

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, -1, &cfg, IPXPING_ERR_EPOLL_FD);
	}

	struct timespec interval;
	interval.tv_sec = (time_t) cfg.interval;
	interval.tv_nsec = (cfg.interval - interval.tv_sec) * 1000000000L;
	int tmr_fd = setup_timer(epoll_fd, &interval);
	if (tmr_fd < 0) {
		perror("creating ping timer");
		cleanup_and_exit(epoll_fd, tmr_fd, &cfg, IPXPING_ERR_TMR_FD);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, tmr_fd, &cfg,
				IPXPING_ERR_SIG_HANDLER);
	}

	if (getrandom(&(cfg.proc_id), sizeof(__u16), 0) != sizeof(__u16)) {
		perror("creating process id");
		cleanup_and_exit(epoll_fd, tmr_fd, &cfg,
				IPXPING_ERR_GETRANDOM);
	}

	do_ipxping(&cfg, epoll_fd, tmr_fd);
}
