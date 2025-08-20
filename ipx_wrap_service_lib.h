#ifndef __IPX_WRAP_SERVICE_LIB_H__
#define __IPX_WRAP_SERVICE_LIB_H__

#define INTERFACE_RESCAN_SECS 30
#define MAX_EPOLL_EVENTS 64

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "uthash.h"
#include "ipx_wrap_mux_proto.h"

enum service_general_error_codes {
	SRVC_ERR_OK = 0,
	SRVC_ERR_USAGE,
	SRVC_ERR_EPOLL_FD,
	SRVC_ERR_TMR_FD,
	SRVC_ERR_IFACE_SCAN,
	SRVC_ERR_SIG_HANDLER,
	SRVC_ERR_RELOAD,
	SRVC_ERR_EPOLL_WAIT,
	SRVC_ERR_TMR_FAILURE,
	SRVC_ERR_GET_TIME,
	SRVC_ERR_MAX
};

STAILQ_HEAD(ipxw_msg_queue, ipxw_mux_msg);

struct if_bind_config {
	__be32 prefix;
	__u16 sock;
	__u8 pkt_type;
	__u8 pkt_type_any:1,
	     recv_bcast:1,
	     reserved:6;
};

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

bool get_now_secs(time_t *now_secs);
bool queue_msg_on_iface(struct if_entry *iface, struct ipxw_mux_msg *msg, int
		epoll_fd);
_Noreturn void cleanup_and_exit(int tmr_fd, int epoll_fd, void *service_ctx,
		int exit_code);
bool is_timeout_expired(time_t now_secs, time_t timeout_secs, time_t last);
bool for_each_iface(bool (*per_iface_cb)(struct if_entry *iface, void *ctx),
		void *ctx);
_Noreturn void run_service(void *service_ctx, const struct if_bind_config
		*ifcfg, int maintenance_interval_secs);

extern void service_cleanup_and_exit(void *ctx);
extern void service_ifup(struct if_entry *iface, int epoll_fd, void *ctx);
extern bool service_reload(void *ctx);
extern bool service_maintenance(void *ctx, time_t now_secs, int epoll_fd);
extern void service_handle_signal(int signal);
extern bool service_handle_msg(struct ipxw_mux_msg *msg, struct if_entry
		*iface, int epoll_fd, void *ctx);

#endif /* __IPX_WRAP_SERVICE_LIB_H__ */
