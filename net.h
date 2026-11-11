/* net.h — UDP and TCP socket helpers.
 * TCP helpers added for cc2obp (ipsc2hbpc's net.c was UDP-only — IPSC/HBP are
 * both UDP; CC-CC's control channel is TCP, §3). All TCP helpers are
 * non-blocking: connect/accept never stall the single-threaded event loop
 * (cc2obp Project Plan §5). */
#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/* Bind a UDP socket to ip:port (ip may be "0.0.0.0").  Returns fd, or -1 with errno set. */
int udp_bind(const char *ip, int port);

/* Create an unbound UDP socket suitable for sendto/recvfrom to a remote. -1 on err. */
int udp_socket(void);

/* Create a UDP socket connected to host:port (host may be a name or IPv4
 * literal; resolved via getaddrinfo).  Use send()/recv() afterward. -1 on err. */
int udp_connect(const char *host, int port);

/* Send to ip:port from fd. Returns bytes sent or -1. */
int udp_sendto(int fd, const void *buf, size_t len, const char *ip, int port);

/* Receive a datagram; fills src_ip (>=16 bytes) and *src_port. Returns len or -1. */
int udp_recvfrom(int fd, void *buf, size_t cap, char *src_ip, int *src_port);

/* Bind+listen a non-blocking TCP socket on ip:port (ip may be "0.0.0.0").
 * Returns fd or -1. */
int tcp_listen(const char *ip, int port);

/* Non-blocking accept.  On success returns fd (itself set non-blocking) and
 * fills src_ip (>=16 bytes) and *src_port.  Returns -1 if nothing pending
 * (errno == EAGAIN/EWOULDBLOCK) or on error. */
int tcp_accept(int listen_fd, char *src_ip, int *src_port);

/* Begin a non-blocking TCP connect to ip:port (ip must be a literal IPv4
 * address).  Returns the socket fd immediately; connection completion must
 * be detected via ev_add_fd_write + tcp_connect_finish.  Returns -1 on a
 * synchronous setup error (socket()/bind() failure — not a refused/timed-out
 * connect, which surfaces later via tcp_connect_finish). */
int tcp_connect_start(const char *ip, int port);

/* Call once the fd registered via ev_add_fd_write becomes writable.  Returns
 * 0 if the connection succeeded, -1 if it failed (errno-equivalent left in
 * *sockerr if non-NULL). */
int tcp_connect_finish(int fd, int *sockerr);

#endif
