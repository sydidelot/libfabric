/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2017 DataDirect Networks, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <poll.h>
#include <limits.h>

#include "sock.h"
#include "sock_util.h"
#include "fi_file.h"

#define SOCK_LOG_DBG(...) _SOCK_LOG_DBG(FI_LOG_EP_CTRL, __VA_ARGS__)
#define SOCK_LOG_ERROR(...) _SOCK_LOG_ERROR(FI_LOG_EP_CTRL, __VA_ARGS__)

ssize_t sock_conn_send_src_addr(struct sock_ep_attr *ep_attr, struct sock_tx_ctx *tx_ctx,
				struct sock_conn *conn)
{
	int ret;
	uint64_t total_len;
	struct sock_op tx_op = { 0 };

	tx_op.op = SOCK_OP_CONN_MSG;
	SOCK_LOG_DBG("New conn msg on TX: %p using conn: %p\n", tx_ctx, conn);

	total_len = 0;
	tx_op.src_iov_len = sizeof(struct sockaddr_in);
	total_len = tx_op.src_iov_len + sizeof(struct sock_op_send);

	sock_tx_ctx_start(tx_ctx);
	if (ofi_rbavail(&tx_ctx->rb) < total_len) {
		ret = -FI_EAGAIN;
		goto err;
	}

	sock_tx_ctx_write_op_send(tx_ctx, &tx_op, 0, (uintptr_t) NULL, 0, 0,
				   ep_attr, conn);
	sock_tx_ctx_write(tx_ctx, ep_attr->src_addr, sizeof(struct sockaddr_in));
	sock_tx_ctx_commit(tx_ctx);
	conn->address_published = 1;
	return 0;

err:
	sock_tx_ctx_abort(tx_ctx);
	return ret;
}

int sock_conn_map_init(struct sock_ep *ep, int init_size)
{
	struct sock_conn_map *map = &ep->attr->cmap;
	map->table = calloc(init_size, sizeof(*map->table));
	if (!map->table)
		return -FI_ENOMEM;

	if (fi_epoll_create(&map->epoll_set) < 0) {
		SOCK_LOG_ERROR("failed to create epoll set\n");
		free(map->table);
		return -FI_ENOMEM;
	}

	fastlock_init(&map->lock);
	map->used = 0;
	map->size = init_size;
	return 0;
}

static int sock_conn_map_increase(struct sock_conn_map *map, int new_size)
{
	void *_table;

	_table = realloc(map->table, new_size * sizeof(*map->table));
	if (!_table) {
		SOCK_LOG_ERROR("*** realloc failed, use FI_SOCKETS_DEF_CONN_MAP_SZ for"
			"specifying conn-map-size\n");
		return -FI_ENOMEM;
	}

	map->size = new_size;
	map->table = _table;
	return 0;
}

void sock_conn_map_destroy(struct sock_ep_attr *ep_attr)
{
	int i;
	struct sock_conn_map *cmap = &ep_attr->cmap;
	for (i = 0; i < cmap->used; i++) {
		if (cmap->table[i].sock_fd != -1) {
			sock_pe_poll_del(ep_attr->domain->pe, cmap->table[i].sock_fd);
			sock_conn_release_entry(cmap, &cmap->table[i]);
		}
	}
	free(cmap->table);
	cmap->table = NULL;
	cmap->used = cmap->size = 0;
	fi_epoll_close(cmap->epoll_set);
	fastlock_destroy(&cmap->lock);
}

void sock_conn_release_entry(struct sock_conn_map *map, struct sock_conn *conn)
{
	fi_epoll_del(map->epoll_set, conn->sock_fd);
	ofi_close_socket(conn->sock_fd);

	conn->address_published = 0;
        conn->connected = 0;
        conn->sock_fd = -1;
}

static int sock_conn_get_next_index(struct sock_conn_map *map)
{
	int i;
	for (i = 0; i < map->size; i++) {
		if (map->table[i].sock_fd == -1)
			return i;
	}
	return -1;
}

static struct sock_conn *sock_conn_map_insert(struct sock_ep_attr *ep_attr,
				struct sockaddr_in *addr, int conn_fd,
				int addr_published)
{
	int index;
	struct sock_conn_map *map = &ep_attr->cmap;

	if (map->size == map->used) {
		index = sock_conn_get_next_index(map);
		if (index < 0) {
			if (sock_conn_map_increase(map, map->size * 2))
				return NULL;
			index = map->used;
			map->used++;
		}
	} else {
		index = map->used;
		map->used++;
	}

	map->table[index].av_index = FI_ADDR_NOTAVAIL;
	map->table[index].connected = 1;
	map->table[index].addr = *addr;
	map->table[index].sock_fd = conn_fd;
	map->table[index].ep_attr = ep_attr;
	sock_set_sockopts(conn_fd);

	if (fi_epoll_add(map->epoll_set, conn_fd, &map->table[index]))
		SOCK_LOG_ERROR("failed to add to epoll set: %d\n", conn_fd);

	map->table[index].address_published = addr_published;
	sock_pe_poll_add(ep_attr->domain->pe, conn_fd);
	return &map->table[index];
}

int fd_set_nonblock(int fd)
{
	int ret;

	ret = fi_fd_nonblock(fd);
	if (ret) {
		SOCK_LOG_ERROR("fi_fd_nonblock failed\n");
	}

	return ret;
}

void sock_set_sockopt_reuseaddr(int sock)
{
	int optval;
	optval = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
		SOCK_LOG_ERROR("setsockopt reuseaddr failed\n");
}

void sock_set_sockopts_conn(int sock)
{
	int optval;
	optval = 1;
	sock_set_sockopt_reuseaddr(sock);
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)))
		SOCK_LOG_ERROR("setsockopt nodelay failed\n");
}

void sock_set_sockopts(int sock)
{
	int optval;
	optval = 1;

	sock_set_sockopt_reuseaddr(sock);
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)))
		SOCK_LOG_ERROR("setsockopt nodelay failed\n");

	fd_set_nonblock(sock);
}

int sock_conn_stop_listener_thread(struct sock_conn_listener *conn_listener)
{
	conn_listener->do_listen = 0;

	fastlock_acquire(&conn_listener->signal_lock);
	fd_signal_set(&conn_listener->signal);
	fastlock_release(&conn_listener->signal_lock);

	if (conn_listener->listener_thread &&
	    pthread_join(conn_listener->listener_thread, NULL)) {
		SOCK_LOG_DBG("pthread join failed\n");
	}

	fd_signal_free(&conn_listener->signal);
	fi_epoll_close(conn_listener->emap);
	fastlock_destroy(&conn_listener->signal_lock);

	return 0;
}

static void *sock_conn_listener_thread(void *arg)
{
	int num_fds, i;
	struct sock_conn_handle *conn_handle;
	struct sock_conn_listener *conn_listener = arg;
	void *ep_contexts[SOCK_EPOLL_WAIT_EVENTS];

	while (conn_listener->do_listen) {
		num_fds = fi_epoll_wait(conn_listener->emap, ep_contexts,
		                        SOCK_EPOLL_WAIT_EVENTS, -1);
		if (num_fds < 0) {
			SOCK_LOG_ERROR("poll failed : %s\n", strerror(errno));
			continue;
		}

		fastlock_acquire(&conn_listener->signal_lock);
		for (i = 0; i < num_fds; i++) {
			conn_handle = ep_contexts[i];

			if (conn_handle == NULL) { /* signal event */
				fd_signal_reset(&conn_listener->signal);
				continue;
			}

			struct sock_ep_attr *ep_attr = conn_handle->ep_attr;
			struct sock_conn_map *map = &ep_attr->cmap;
			int conn_fd;

			socklen_t addr_size;
			struct sockaddr_in remote;

			addr_size = sizeof(remote);
			conn_fd = accept(conn_handle->sock, (struct sockaddr *) &remote,
			                 &addr_size);
			SOCK_LOG_DBG("CONN: accepted conn-req: %d\n", conn_fd);
			if (conn_fd < 0) {
				SOCK_LOG_ERROR("failed to accept: %s\n", strerror(errno));
				continue;
			}

			SOCK_LOG_DBG("ACCEPT: %s, %d\n", inet_ntoa(remote.sin_addr),
				ntohs(remote.sin_port));

			fastlock_acquire(&map->lock);
			sock_conn_map_insert(ep_attr, &remote, conn_fd, 1);
			fastlock_release(&map->lock);
			sock_pe_signal(ep_attr->domain->pe);
		}
		fastlock_release(&conn_listener->signal_lock);
	}

	return NULL;
}

int sock_conn_start_listener_thread(struct sock_conn_listener *conn_listener)
{
	int ret;

	fastlock_init(&conn_listener->signal_lock);

	ret = fi_epoll_create(&conn_listener->emap);
	if (ret < 0) {
		SOCK_LOG_ERROR("failed to create epoll set\n");
		goto err1;
	}

	ret = fd_signal_init(&conn_listener->signal);
	if (ret < 0) {
		SOCK_LOG_ERROR("failed to init signal\n");
		goto err2;
	}

	ret = fi_epoll_add(conn_listener->emap,
	                   conn_listener->signal.fd[FI_READ_FD], NULL);
	if (ret != 0){
		SOCK_LOG_ERROR("failed to add signal fd to epoll\n");
		goto err3;
	}

	conn_listener->do_listen = 1;
	ret = pthread_create(&conn_listener->listener_thread, NULL,
	                     sock_conn_listener_thread, conn_listener);
	if (ret < 0) {
		SOCK_LOG_ERROR("failed to create conn listener thread\n");
		goto err3;
	}
	return 0;

err3:
	conn_listener->do_listen = 0;
	fd_signal_free(&conn_listener->signal);
err2:
	fi_epoll_close(conn_listener->emap);
err1:
	fastlock_destroy(&conn_listener->signal_lock);
	return ret;
}

int sock_conn_listen(struct sock_ep_attr *ep_attr)
{
	struct addrinfo *s_res = NULL, *p;
	struct addrinfo hints = { 0 };
	int listen_fd = 0, ret;
	socklen_t addr_size;
	struct sockaddr_in addr;
	struct sock_conn_handle *conn_handle = &ep_attr->conn_handle;
	char service[NI_MAXSERV] = {0};
	char *port;
	char ipaddr[24];

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	memcpy(&addr, ep_attr->src_addr, sizeof(addr));
	if (getnameinfo((void *)ep_attr->src_addr, sizeof(*ep_attr->src_addr),
			NULL, 0, conn_handle->service,
			sizeof(conn_handle->service), NI_NUMERICSERV)) {
		SOCK_LOG_ERROR("could not resolve src_addr\n");
		return -FI_EINVAL;
	}

	if (ep_attr->ep_type == FI_EP_MSG) {
		memset(conn_handle->service, 0, NI_MAXSERV);
		port = NULL;
		addr.sin_port = 0;
	} else
		port = conn_handle->service;

	inet_ntop(addr.sin_family, &addr.sin_addr, ipaddr, sizeof(ipaddr));
	ret = getaddrinfo(ipaddr, port, &hints, &s_res);
	if (ret) {
		SOCK_LOG_ERROR("no available AF_INET address, service %s, %s\n",
			       conn_handle->service, gai_strerror(ret));
		return -FI_EINVAL;
	}

	SOCK_LOG_DBG("Binding listener thread to port: %s\n", conn_handle->service);
	for (p = s_res; p; p = p->ai_next) {
		listen_fd = ofi_socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (listen_fd >= 0) {
			sock_set_sockopts(listen_fd);

			if (!bind(listen_fd, s_res->ai_addr, s_res->ai_addrlen))
				break;
			ofi_close_socket(listen_fd);
			listen_fd = -1;
		}
	}
	freeaddrinfo(s_res);

	if (listen_fd < 0) {
		SOCK_LOG_ERROR("failed to listen to port: %s\n",
			       conn_handle->service);
		goto err;
	}

	if (atoi(conn_handle->service) == 0) {
		addr_size = sizeof(addr);
		if (getsockname(listen_fd, (struct sockaddr *) &addr, &addr_size))
			goto err;
		snprintf(conn_handle->service, sizeof(conn_handle->service), "%d",
			 ntohs(addr.sin_port));
		SOCK_LOG_DBG("Bound to port: %s - %d\n", conn_handle->service, getpid());
		ep_attr->msg_src_port = ntohs(addr.sin_port);
	}

	if (ep_attr->src_addr->sin_addr.s_addr == 0) {
		snprintf(service, sizeof service, "%s", conn_handle->service);
		ret = sock_get_src_addr_from_hostname(ep_attr->src_addr, service);
		if (ret)
			goto err;
	}

	if (listen(listen_fd, sock_cm_def_map_sz)) {
		SOCK_LOG_ERROR("failed to listen socket: %s\n", strerror(errno));
		goto err;
	}

	if (((struct sockaddr_in *) (ep_attr->src_addr))->sin_port == 0) {
		((struct sockaddr_in *) (ep_attr->src_addr))->sin_port =
			htons(atoi(conn_handle->service));
	}

	conn_handle->sock = listen_fd;
	conn_handle->ep_attr = ep_attr;
	conn_handle->do_listen = 1;

	fastlock_acquire(&ep_attr->domain->conn_listener.signal_lock);
	ret = fi_epoll_add(ep_attr->domain->conn_listener.emap,
	                   conn_handle->sock, conn_handle);
	fastlock_release(&ep_attr->domain->conn_listener.signal_lock);
	if (ret)
	{
		SOCK_LOG_ERROR("failed to add fd to pollset: %d\n", ret);
		goto err;
	}

	return 0;
err:
	if (listen_fd >= 0)
		ofi_close_socket(listen_fd);

	return -FI_EINVAL;
}

struct sock_conn *sock_ep_connect(struct sock_ep_attr *ep_attr, fi_addr_t index)
{
	int conn_fd = -1, ret;
	int do_retry = sock_conn_retry;
	struct sock_conn *conn, *new_conn;
	struct sockaddr_in addr;
	socklen_t lon;
	int valopt = 0;
	struct pollfd poll_fd;

	if (ep_attr->ep_type == FI_EP_MSG) {
		/* Need to check that destination address has been
		   passed to endpoint */
		assert(ep_attr->dest_addr);
		addr = *ep_attr->dest_addr;
		addr.sin_port = htons(ep_attr->msg_dest_port);
	} else {
		addr = *((struct sockaddr_in *)&ep_attr->av->table[index].addr);
	}

do_connect:
	fastlock_acquire(&ep_attr->cmap.lock);
	conn = sock_ep_lookup_conn(ep_attr, index, &addr);
	fastlock_release(&ep_attr->cmap.lock);

	if (conn != SOCK_CM_CONN_IN_PROGRESS)
		return conn;

	conn_fd = ofi_socket(AF_INET, SOCK_STREAM, 0);
	if (conn_fd == -1) {
		SOCK_LOG_ERROR("failed to create conn_fd, errno: %d\n", errno);
		errno = FI_EOTHER;
		return NULL;
	}

	ret = fd_set_nonblock(conn_fd);
	if (ret) {
		SOCK_LOG_ERROR("failed to set conn_fd nonblocking, errno: %d\n", errno);
		errno = FI_EOTHER;
		ofi_close_socket(conn_fd);
		return NULL;
	}

	SOCK_LOG_DBG("Connecting to: %s:%d\n", inet_ntoa(addr.sin_addr),
			ntohs(addr.sin_port));
	SOCK_LOG_DBG("Connecting using address:%s\n",
			inet_ntoa(ep_attr->src_addr->sin_addr));

	ret = connect(conn_fd, (struct sockaddr *) &addr, sizeof addr);
	if (ret < 0) {
		if (ofi_sockerr() == EINPROGRESS) {
			poll_fd.fd = conn_fd;
			poll_fd.events = POLLOUT;

			ret = poll(&poll_fd, 1, 15 * 1000);
			if (ret < 0) {
				SOCK_LOG_DBG("poll failed\n");
				goto retry;
			}

			lon = sizeof(int);
			ret = getsockopt(conn_fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
			if (ret < 0) {
				SOCK_LOG_DBG("getsockopt failed: %d, %d\n", ret, conn_fd);
				goto retry;
			}

			if (valopt) {
				SOCK_LOG_DBG("Error in connection() %d - %s - %d\n", valopt, strerror(valopt), conn_fd);
				SOCK_LOG_DBG("Connecting to: %s:%d\n", inet_ntoa(addr.sin_addr),
						ntohs(addr.sin_port));
				SOCK_LOG_DBG("Connecting using address:%s\n",
				inet_ntoa(ep_attr->src_addr->sin_addr));
				goto retry;
			}
			goto out;
		} else {
			SOCK_LOG_DBG("Timeout or error() - %s: %d\n", strerror(errno), conn_fd);
			SOCK_LOG_DBG("Connecting to: %s:%d\n", inet_ntoa(addr.sin_addr),
					ntohs(addr.sin_port));
			SOCK_LOG_DBG("Connecting using address:%s\n",
					inet_ntoa(ep_attr->src_addr->sin_addr));
			goto retry;
		}
	} else {
		goto out;
	}

retry:
	do_retry--;
	sleep(10);
	if (!do_retry)
		goto err;

	if (conn_fd != -1) {
		ofi_close_socket(conn_fd);
		conn_fd = -1;
	}

	SOCK_LOG_ERROR("Connect error, retrying - %s - %d\n", strerror(errno), conn_fd);
	SOCK_LOG_DBG("Connecting to: %s:%d\n", inet_ntoa(addr.sin_addr),
			ntohs(addr.sin_port));
	SOCK_LOG_DBG("Connecting using address:%s\n",
			inet_ntoa(ep_attr->src_addr->sin_addr));
        goto do_connect;

out:
	fastlock_acquire(&ep_attr->cmap.lock);
	new_conn = sock_conn_map_insert(ep_attr, &addr, conn_fd, 0);
	if (!new_conn) {
		fastlock_release(&ep_attr->cmap.lock);
		goto err;
	}
	new_conn->av_index = (ep_attr->ep_type == FI_EP_MSG) ? FI_ADDR_NOTAVAIL : index;
	conn = ofi_idm_lookup(&ep_attr->av_idm, index);
	if (conn == SOCK_CM_CONN_IN_PROGRESS) {
		if (ofi_idm_set(&ep_attr->av_idm, index, new_conn) < 0)
			SOCK_LOG_ERROR("ofi_idm_set failed\n");
		conn = new_conn;
	}
	fastlock_release(&ep_attr->cmap.lock);
	return conn;

err:
	ofi_close_socket(conn_fd);
	return NULL;
}

