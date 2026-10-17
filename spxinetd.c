#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ipx_wrap_mux_proto.h"
#include "ipx_wrap_helpers.h"

#define DEFAULT_TX_QUEUE_PAUSE_THRESHOLD (64)
#define DEFAULT_RX_QUEUE_PAUSE_THRESHOLD (64)

enum spxinetd_error_codes {
	SPXINETD_ERR_OK = 0,
	SPXINETD_ERR_USAGE,
	SPXINETD_ERR_EPOLL_FD,
	SPXINETD_ERR_CONF_FD,
	SPXINETD_ERR_IPX_FD,
	SPXINETD_ERR_SPX_FD,
	SPXINETD_ERR_EXEC_FD,
	SPXINETD_ERR_EXEC_IN_FAILURE,
	SPXINETD_ERR_SIG_HANDLER,
	SPXINETD_ERR_BIND,
	SPXINETD_ERR_GETSOCKNAME,
	SPXINETD_ERR_EPOLL_WAIT,
	SPXINETD_ERR_CONF_FAILURE,
	SPXINETD_ERR_IPX_FAILURE,
	SPXINETD_ERR_SPX_FAILURE,
	SPXINETD_ERR_MSG_ALLOC,
	SPXINETD_ERR_MSG_QUEUE,
	SPXINETD_ERR_DUP,
	SPXINETD_ERR_EXEC,
	SPXINETD_ERR_PROG_EXEC,
	SPXINETD_ERR_MAX
};

#define MAX_EPOLL_EVENTS 64

struct spxinetd_cfg {
	bool verbose;
	bool redir_stderr;
	__u16 max_spx_data_len;
	size_t tx_queue_pause_threshold;
	size_t rx_queue_pause_threshold;
	struct ipx_addr local_addr;
	char **sub_argv;
};

static volatile sig_atomic_t keep_going = true;
static volatile sig_atomic_t reap_children = false;

static struct counted_ipx_msg_queue out_queue =
	counted_msg_queue_init(out_queue);
static struct counted_ipx_msg_queue in_queue =
	counted_msg_queue_init(in_queue);

static struct ipxw_mux_handle ipxh = ipxw_mux_handle_init;

static FILE *fd_exec_in = NULL;
static FILE *fd_exec_out = NULL;
static pid_t pid_exec_child = -1;

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGCHLD:
			reap_children = true;
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

static void print_child_status(pid_t child_pid, int wstatus)
{
	if (WIFEXITED(wstatus)) {
		fprintf(stderr, "%d exited, status=%d\n",
				child_pid,
				WEXITSTATUS(wstatus));
	} else if (WIFSIGNALED(wstatus)) {
		fprintf(stderr, "%d killed by signal %d\n",
				child_pid, WTERMSIG(wstatus));
	} else if (WIFSTOPPED(wstatus)) {
		fprintf(stderr, "%d stopped by signal %d\n",
				child_pid, WSTOPSIG(wstatus));
	}
}

static bool write_to_exec_proc(int epoll_fd, struct spxinetd_cfg *cfg);

static _Noreturn void cleanup_and_exit(int epoll_fd, struct ipxw_mux_spx_handle
		*spxh, struct spxinetd_cfg *cfg, enum spxinetd_error_codes
		code)
{
	/* close epoll FD */
	if (epoll_fd >= 0) {
		close(epoll_fd);
	}

	/* remove all undelivered messages */
	while (!counted_ipx_msg_queue_empty(&in_queue)) {
		struct queued_ipx_msg *msg =
			counted_ipx_msg_queue_pop(&in_queue);
		free(msg);
	}
	while (!counted_ipx_msg_queue_empty(&out_queue)) {
		struct queued_ipx_msg *msg =
			counted_ipx_msg_queue_pop(&out_queue);
		free(msg);
	}

	if (spxh != NULL) {
		/* sub-process */
		ipxw_mux_spx_conn_close(spxh);
	} else {
		/* main process */
		ipxw_mux_unbind(ipxh);
	}

	/* close FDs to the execed process (if any) */
	if (fd_exec_in != NULL) {
		fclose(fd_exec_in);
	}
	if (fd_exec_out != NULL) {
		fclose(fd_exec_out);
	}

	/* kill and collect the exec-child process */
	if (pid_exec_child != -1) {
		/* sub-process */
		kill(pid_exec_child, SIGTERM);

		int err = -1;
		int wstatus;
		do {
			err = waitpid(pid_exec_child, &wstatus, 0);
		} while (err < 0 && errno == EINTR);
		if (cfg->verbose) {
			print_child_status(pid_exec_child, wstatus);
		}
	}

	exit(code);
}

static bool send_out_spx_msg(int epoll_fd, struct ipxw_mux_spx_handle h)
{
	/* no msgs to send */
	if (counted_ipx_msg_queue_empty(&out_queue)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLIN | EPOLLERR | EPOLLHUP,
			.data.fd = ipxw_mux_spx_handle_sock(h)
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ipxw_mux_spx_handle_sock(h),
				&ev);

		return true;
	}

	struct queued_ipx_msg *msg = counted_ipx_msg_queue_peek(&out_queue);
	ssize_t err = ipxw_mux_kspx_send(h, msg->data, msg->data_len,
			MSG_DONTWAIT, msg->datastream_type, msg->spx_flags);
	if (err < 0) {
		/* recoverable errors, don't dequeue the message but try again
		 * later */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return true;
		}

		/* other error, make sure to get rid of the message */
	}

	counted_ipx_msg_queue_pop(&out_queue);
	free(msg);

	return (err >= 0);
}

static bool queue_in_msg(int epoll_fd, struct queued_ipx_msg *msg)
{
	/* re-register for ready-to-write events on the exec-process, now that
	 * messages are available */
	struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLERR | EPOLLHUP,
		.data.fd = fileno(fd_exec_in)
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fileno(fd_exec_in), &ev) < 0) {
		return false;
	}

	/* queue the input message */
	counted_ipx_msg_queue_push(&in_queue, msg);

	return true;
}

static void spx_recv_loop(int epoll_fd, struct ipxw_mux_spx_handle spxh, struct
		spxinetd_cfg *cfg)
{
	while (true) {
		/* SPX message received */
		__u8 dummy_buf;
		__u8 dummy_ds_type;
		__u8 dummy_spx_flags;
		ssize_t expected_data_len = ipxw_mux_kspx_recv(spxh,
				&dummy_buf, 1, MSG_DONTWAIT | MSG_PEEK |
				MSG_TRUNC, &dummy_ds_type, &dummy_spx_flags);
		if (expected_data_len < 0) {
			if (errno == EINTR) {
				continue;
			}

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}

			perror("SPX receive peek");
			cleanup_and_exit(epoll_fd, &spxh, cfg,
					SPXINETD_ERR_SPX_FAILURE);
		}

		// FIXME: this can cause a busy loop when the queue is full
		if (counted_ipx_msg_queue_nitems(&in_queue) >
				cfg->rx_queue_pause_threshold) {
			return;
		}

		struct queued_ipx_msg *msg = calloc(1, sizeof(struct
					queued_ipx_msg) + expected_data_len +
				1);
		if (msg == NULL) {
			perror("allocating message");
			cleanup_and_exit(epoll_fd, &spxh, cfg,
					SPXINETD_ERR_MSG_ALLOC);
		}

		ssize_t rcvd_len = ipxw_mux_kspx_recv(spxh, msg->data,
				expected_data_len, MSG_DONTWAIT,
				&(msg->datastream_type), &(msg->spx_flags));
		if (rcvd_len < 0) {
			free(msg);
			if (errno == EINTR) {
				continue;
			}

			perror("SPX receive");
			cleanup_and_exit(epoll_fd, &spxh, cfg,
					SPXINETD_ERR_SPX_FAILURE);
		}

		/* connection closed */
		if (rcvd_len == 0) {
			free(msg);
			keep_going = false;
			return;
		}

		/* queue received message */
		msg->data[rcvd_len] = '\0';
		msg->data_len = rcvd_len;
		msg->is_spx = true;
		if (!queue_in_msg(epoll_fd, msg)) {
			free(msg);
			perror("queueing message");
			cleanup_and_exit(epoll_fd, &spxh, cfg,
					SPXINETD_ERR_MSG_QUEUE);
		}
	}
}

static bool do_exec(int epoll_fd, struct ipxw_mux_spx_handle spxh, struct
		spxinetd_cfg *cfg)
{
	int in_pipe[2] = { -1, -1 };
	int out_pipe[2] = { -1, -1 };

	do {
		if (pipe(in_pipe) != 0) {
			break;
		}

		if (pipe(out_pipe) != 0) {
			break;
		}

		FILE *exec_in = fdopen(in_pipe[1], "w");
		if (exec_in == NULL) {
			break;
		}
		if (setvbuf(exec_in, NULL, _IOLBF, 0) != 0) {
			break;
		}
		FILE *exec_out = fdopen(out_pipe[0], "r");
		if (exec_out == NULL) {
			break;
		}
		if (setvbuf(exec_out, NULL, _IONBF, 0) != 0) {
			break;
		}

		/* fork off a new process to exec the target process */
		pid_t child_pid = fork();
		if (child_pid < 0) {
			break;
		}

		if (child_pid == 0) {
			/* child */

			/* close unused pipe ends */
			close(in_pipe[1]);
			close(out_pipe[0]);

			/* close the SPX handle */
			ipxw_mux_spx_handle_close(&spxh);

			/* close old epoll fd */
			close(epoll_fd);

			if (dup2(in_pipe[0], STDIN_FILENO) == -1) {
				exit(SPXINETD_ERR_DUP);
			}
			if (dup2(out_pipe[1], STDOUT_FILENO) == -1) {
				exit(SPXINETD_ERR_DUP);
			}
			if (cfg->redir_stderr) {
				if (dup2(out_pipe[1], STDERR_FILENO) == -1) {
					exit(SPXINETD_ERR_DUP);
				}
			}

			/* close remaining pipe ends */
			close(in_pipe[0]);
			close(out_pipe[1]);

			/* exec the program */
			execve(cfg->sub_argv[0], cfg->sub_argv, NULL);
			exit(SPXINETD_ERR_EXEC);
		}

		/* parent */

		/* close unused pipe ends */
		close(in_pipe[0]);
		close(out_pipe[1]);

		/* set the parameter for communicating with the exec-process */
		fd_exec_in = exec_in;
		fd_exec_out = exec_out;
		pid_exec_child = child_pid;

		return true;
	} while (0);

	if (in_pipe[0] != -1) {
		close(in_pipe[0]);
	}
	if (in_pipe[1] != -1) {
		close(in_pipe[1]);
	}
	if (out_pipe[0] != -1) {
		close(out_pipe[0]);
	}
	if (out_pipe[1] != -1) {
		close(out_pipe[1]);
	}

	return false;
}

static bool write_to_exec_proc(int epoll_fd, struct spxinetd_cfg *cfg)
{
	/* no msgs to write */
	if (counted_ipx_msg_queue_empty(&in_queue)) {
		/* unregister from ready-to-write events to avoid busy polling
		 */
		struct epoll_event ev = {
			.events = EPOLLERR | EPOLLHUP,
			.data.fd = fileno(fd_exec_in)
		};
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fileno(fd_exec_in), &ev);

		return false;
	}

	struct queued_ipx_msg *msg = counted_ipx_msg_queue_peek(&in_queue);

	if (fwrite(msg->data, msg->data_len, 1, fd_exec_in) != 1) {
		/* could not write out message, retry later */
		return true;
	}

	fflush(fd_exec_in);

	/* could write the message, get rid of it */
	counted_ipx_msg_queue_pop(&in_queue);
	free(msg);

	return true;
}

static bool read_from_exec_proc(int epoll_fd, struct ipxw_mux_spx_handle spxh,
		struct spxinetd_cfg *cfg)
{
	/* queue is full, try again later */
	// FIXME: this can cause a busy loop when the queue is full
	if (counted_ipx_msg_queue_nitems(&out_queue) >
			cfg->tx_queue_pause_threshold) {
		return true;
	}

	int max_data_len = cfg->max_spx_data_len;
	struct queued_ipx_msg *msg = calloc(1, sizeof(struct queued_ipx_msg) +
			max_data_len);
	if (msg == NULL) {
		return false;
	}

	msg->is_spx = true;
	msg->datastream_type = SPX_DS_NONE;
	msg->spx_flags = 0;

	ssize_t data_len = read(fileno(fd_exec_out), msg->data, max_data_len);
	if (data_len < 0) {
		free(msg);
		return false;
	}
	if (data_len == 0) {
		/* nothing to send */
		free(msg);
		return true;
	}

	/* record the message data length */
	msg->data_len = data_len;

	/* re-register for ready-to-send events */
	struct epoll_event ev = {
		.events = EPOLLOUT | EPOLLIN | EPOLLERR | EPOLLHUP,
		.data.fd = ipxw_mux_spx_handle_sock(spxh)
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ipxw_mux_spx_handle_sock(spxh),
				&ev) < 0) {
		free(msg);
		return false;
	}

	counted_ipx_msg_queue_push(&out_queue, msg);

	return true;
}

static _Noreturn void do_sub(struct spxinetd_cfg *cfg, struct
		ipxw_mux_spx_handle spxh)
{
	/* initial setup */

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, &spxh, cfg, SPXINETD_ERR_EPOLL_FD);
	}

	/* register signal handlers */
	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0
			|| sigaction(SIGCHLD, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, &spxh, cfg,
				SPXINETD_ERR_SIG_HANDLER);
	}

	/* start the process with the actual exec target */
	if (!do_exec(epoll_fd, spxh, cfg)) {
		perror("executing program");
		cleanup_and_exit(epoll_fd, &spxh, cfg, SPXINETD_ERR_PROG_EXEC);
	}

	/* register SPX socket for reception */
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLERR | EPOLLHUP,
		.data.fd = ipxw_mux_spx_handle_sock(spxh)
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_spx_handle_sock(spxh),
				&ev) < 0) {
		perror("registering SPX socket for event polling");
		cleanup_and_exit(epoll_fd, &spxh, cfg, SPXINETD_ERR_SPX_FD);
	}

	/* register the exec-process' output for reading */
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = fileno(fd_exec_out);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fileno(fd_exec_out), &ev) < 0) {
		perror("registering exec-process for event polling");
		cleanup_and_exit(epoll_fd, &spxh, cfg, SPXINETD_ERR_EXEC_FD);
	}

	/* register the exec-process* input, once messages arrive we will
	 * register it for writing events */
	ev.events = EPOLLERR | EPOLLHUP;
	ev.data.fd = fileno(fd_exec_in);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fileno(fd_exec_in), &ev) < 0) {
		perror("registering exec-process for event polling");
		cleanup_and_exit(epoll_fd, &spxh, cfg, SPXINETD_ERR_EXEC_FD);
	}

	struct epoll_event evs[MAX_EPOLL_EVENTS];
	/* keep going as long as there are queued messages */
	while (keep_going || !counted_ipx_msg_queue_empty(&in_queue) ||
			!counted_ipx_msg_queue_empty(&out_queue)) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno != EINTR) {
				perror("event polling");
				cleanup_and_exit(epoll_fd, &spxh, cfg,
						SPXINETD_ERR_EPOLL_WAIT);
			}
		}

		/* exit if our child (the exec-process) terminated */
		if (reap_children) {
			keep_going = false;
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* exec-process input */
			if (evs[i].data.fd == fileno(fd_exec_in)) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "exec input error\n");
					cleanup_and_exit(epoll_fd, &spxh, cfg,
							SPXINETD_ERR_EXEC_IN_FAILURE);
				}

				/* can't write to exec-process */
				if ((evs[i].events & EPOLLOUT) == 0) {
					continue;
				}

				/* write to exec process */
				write_to_exec_proc(epoll_fd, cfg);

				continue;
			}

			/* exec-process output */
			if (evs[i].data.fd == fileno(fd_exec_out)) {
				/* can't read from exec-process */
				if ((evs[i].events & EPOLLIN) == 0) {
					continue;
				}

				/* read from exec process */
				if (!read_from_exec_proc(epoll_fd, spxh, cfg)) {
					perror("queueing message");
					cleanup_and_exit(epoll_fd, &spxh, cfg,
							SPXINETD_ERR_MSG_QUEUE);
				}

				continue;
			}

			/* SPX socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "SPX socket error\n");
				cleanup_and_exit(epoll_fd, &spxh, cfg,
						SPXINETD_ERR_SPX_FAILURE);
			}

			/* can write to SPX socket */
			if (evs[i].events & EPOLLOUT) {
				if (!send_out_spx_msg(epoll_fd, spxh)) {
					perror("SPX send");
					cleanup_and_exit(epoll_fd, &spxh, cfg,
							SPXINETD_ERR_SPX_FAILURE);
				}
			}

			/* nothing to read from SPX socket */
			if ((evs[i].events & EPOLLIN) == 0) {
				continue;
			}

			/* receive SPX messages until there are no more
			 * or the queue is full */
			spx_recv_loop(epoll_fd, spxh, cfg);

			continue;
		}
	}

	cleanup_and_exit(epoll_fd, &spxh, cfg, SPXINETD_ERR_OK);
}

static void spx_accept_and_fork(int epoll_fd, struct spxinetd_cfg *cfg)
{
	/* IPX message received */
	__u8 dummy;
	ssize_t expected_data_len = ipxw_mux_recvfrom(ipxh, &dummy, 1,
			MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC, NULL, NULL);
	if (expected_data_len < 0) {
		if (errno == EINTR) {
			return;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}

		perror("IPX receive peek");
		return;
	}

	struct queued_ipx_msg *msg = calloc(1, sizeof(struct queued_ipx_msg) +
			expected_data_len + 1);
	if (msg == NULL) {
		perror("allocating message");
		return;
	}

	do {
		socklen_t addr_len = sizeof(msg->addr);
		ssize_t rcvd_len = ipxw_mux_recvfrom(ipxh, msg->data,
				expected_data_len, MSG_DONTWAIT, (struct
					sockaddr *) &(msg->addr), &addr_len);
		if (rcvd_len < 0) {
			if (errno == EINTR) {
				break;
			}

			free(msg);
			perror("IPX receive");
			cleanup_and_exit(epoll_fd, NULL, cfg,
					SPXINETD_ERR_IPX_FAILURE);
		}

		struct ipx_addr peer_addr;
		sockaddr_ipx_to_ipx_addr(&peer_addr, &(msg->addr));

		__be16 remote_conn_id = ipxw_mux_kspx_check_for_conn_req(
				msg->data, rcvd_len, &(msg->addr));

		/* not an SPX connection request */
		if (remote_conn_id == SPX_CONN_ID_UNKNOWN) {
			if (cfg->verbose) {
				fprintf(stderr, "received invalid connection "
						"request from ");
				print_ipxaddr(stderr, &peer_addr);
				fprintf(stderr, "\n");
			}

			break;
		}

		struct ipxw_mux_spx_handle spxh = ipxw_mux_kspx_accept(ipxh,
				&(msg->addr), remote_conn_id);
		if (ipxw_mux_spx_handle_is_error(spxh)) {
			perror("SPX accept");
			break;
		}

		/* fork off a new process to handle the connection */
		pid_t child_pid = fork();
		if (child_pid < 0) {
			perror("forking child");
		}

		if (child_pid == 0) {
			/* child */
			free(msg);

			/* get rid of IPX handle */
			ipxw_mux_handle_close(ipxh);

			/* close old epoll fd */
			close(epoll_fd);

			/* set up and run our per connection process */
			do_sub(cfg, spxh);
		}

		/* parent */
		ipxw_mux_spx_handle_close(&spxh);

		if (cfg->verbose) {
			printf("accepted connection from ");
			print_ipxaddr(stdout, &peer_addr);
			printf("\n");
		}
	} while (0);

	free(msg);
	return;
}

static void do_reap_children(struct spxinetd_cfg *cfg)
{
	int wstatus;
	pid_t child_pid;
	while ((child_pid  = waitpid(-1, &wstatus, WNOHANG)) > 0) {
		if (cfg->verbose) {
			print_child_status(child_pid, wstatus);
		}
	}
}

static _Noreturn void do_main(struct spxinetd_cfg *cfg, int epoll_fd)
{
	struct ipxw_mux_msg bind_msg;
	memset(&bind_msg, 0, sizeof(struct ipxw_mux_msg));
	bind_msg.type = IPXW_MUX_BIND;
	bind_msg.bind.addr = cfg->local_addr;
	bind_msg.bind.pkt_type = SPX_PKT_TYPE;
	bind_msg.bind.pkt_type_any = false;
	bind_msg.bind.recv_bcast = false;
	bind_msg.bind.recv_direct = true;

	ipxh = ipxw_mux_bind(&bind_msg);
	if (ipxw_mux_handle_is_error(ipxh)) {
		perror("IPX bind");
		cleanup_and_exit(epoll_fd, NULL, cfg, SPXINETD_ERR_BIND);
	}

	if (cfg->verbose) {
		if (!get_bound_ipx_addr(ipxh, &(cfg->local_addr))) {
			perror("IPX get bound address");
			cleanup_and_exit(epoll_fd, NULL, cfg,
					SPXINETD_ERR_GETSOCKNAME);
		}

		fprintf(stderr, "bound to ");
		print_ipxaddr(stderr, &(cfg->local_addr));
		fprintf(stderr, "\n");
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
		cleanup_and_exit(epoll_fd, NULL, cfg, SPXINETD_ERR_CONF_FD);
	}

	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = ipxw_mux_handle_data(ipxh);
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipxw_mux_handle_data(ipxh), &ev)
			< 0) {
		perror("registering IPX socket for event polling");
		cleanup_and_exit(epoll_fd, NULL, cfg, SPXINETD_ERR_IPX_FD);
	}

	struct epoll_event evs[MAX_EPOLL_EVENTS];
	while (keep_going) {
		int n_fds = epoll_wait(epoll_fd, evs, MAX_EPOLL_EVENTS, -1);
		if (n_fds < 0) {
			if (errno != EINTR) {
				perror("event polling");
				cleanup_and_exit(epoll_fd, NULL, cfg,
						SPXINETD_ERR_EPOLL_WAIT);
			}
		}

		if (reap_children) {
			do_reap_children(cfg);
			reap_children = false;
		}

		int i;
		for (i = 0; i < n_fds; i++) {
			/* config socket */
			if (evs[i].data.fd == ipxw_mux_handle_conf(ipxh)) {
				/* something went wrong */
				if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
					fprintf(stderr, "config socket error\n");
					cleanup_and_exit(epoll_fd, NULL, cfg,
							SPXINETD_ERR_CONF_FAILURE);
				}

				continue;
			}

			/* IPX socket */

			/* something went wrong */
			if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
				fprintf(stderr, "IPX socket error\n");
				cleanup_and_exit(epoll_fd, NULL, cfg,
						SPXINETD_ERR_IPX_FAILURE);
			}

			/* nothing to read from IPX socket */
			if ((evs[i].events & EPOLLIN) == 0) {
				continue;
			}

			/* accept an SPX connection */
			spx_accept_and_fork(epoll_fd, cfg);

			continue;
		}
	}

	cleanup_and_exit(epoll_fd, NULL, cfg, SPXINETD_ERR_OK);
}

static _Noreturn void usage(void)
{
	printf("Usage: spxinetd [-v] [-d <maximum data bytes>] [-e] <local IPX address> -- <command>\n");
	exit(SPXINETD_ERR_USAGE);
}

static bool verify_cfg(struct spxinetd_cfg *cfg)
{
	if (cfg->max_spx_data_len < 1) {
		return false;
	}

	if (cfg->max_spx_data_len > SPX_MAX_DATA_LEN_WO_SIZNG) {
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	struct spxinetd_cfg cfg = {
		.verbose = false,
		.redir_stderr = false,
		.tx_queue_pause_threshold = DEFAULT_TX_QUEUE_PAUSE_THRESHOLD,
		.rx_queue_pause_threshold = DEFAULT_RX_QUEUE_PAUSE_THRESHOLD,
		.max_spx_data_len = SPX_MAX_DATA_LEN_WO_SIZNG
	};

	/* parse and verify command-line arguments */

	int opt;
	while ((opt = getopt(argc, argv, "d:ev")) != -1) {
		switch (opt) {
			case 'd':
				__u16 max_data_len = strtoul(optarg, NULL, 0);
				cfg.max_spx_data_len = max_data_len;
				break;
			case 'e':
				cfg.redir_stderr = true;
				break;
			case 'v':
				cfg.verbose = true;
				break;
			default:
				usage();
		}
	}

	if (optind + 1 >= argc) {
		usage();
	}

	if (!parse_ipxaddr(argv[optind], &(cfg.local_addr))) {
		usage();
	}
	optind++;

	if (strcmp(argv[optind], "--") == 0) {
		optind++;
	}

	if (optind >= argc) {
		usage();
	}

	cfg.sub_argv = &(argv[optind]);

	if (!verify_cfg(&cfg)) {
		usage();
	}

	/* initial setup */

	int epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		perror("create epoll fd");
		cleanup_and_exit(epoll_fd, NULL, &cfg, SPXINETD_ERR_EPOLL_FD);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0
			|| sigaction(SIGCHLD, &sig_act, NULL) < 0) {
		perror("setting up signal handler");
		cleanup_and_exit(epoll_fd, NULL, &cfg,
				SPXINETD_ERR_SIG_HANDLER);
	}

	do_main(&cfg, epoll_fd);
}
