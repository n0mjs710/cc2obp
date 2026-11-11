/* obp_link.h — one UDP socket per enabled [[openbridge]] peer (§6.1, §12).
 * Stateless protocol (no login/handshake); owns only the socket, HMAC
 * framing, and slot-1/HMAC validation on receive. */
#ifndef OBP_LINK_H
#define OBP_LINK_H

#include <stdint.h>
#include "../config.h"
#include "../eventloop.h"

typedef struct obp_mux obp_mux;
struct translator;

obp_mux *obp_mux_new(Config *cfg, struct translator *tr, ev_loop *loop);
int  obp_mux_start(obp_mux *mx);   /* binds a UDP socket per enabled peer (§5) */
void obp_mux_stop(obp_mux *mx);
void obp_mux_free(obp_mux *mx);

/* SIGHUP reload (§6.3), in two steps around the swap to the new config:
 * obp_mux_retire_peer() closes one peer's socket while *cfg still holds its
 * old values (a peer being rebuilt or removed); after the swap,
 * obp_mux_reconcile() binds every enabled peer that has no socket and closes
 * newly-disabled ones.  Other peers' sockets are never touched. */
void obp_mux_retire_peer(obp_mux *mx, int peer_idx);
void obp_mux_reconcile(obp_mux *mx);

/* A peer whose bind fails (at startup or on reload) stays down while every
 * other peer and every link carries on: the failure is logged at ERROR with
 * the links it cuts off, the bind is retried every 10 s from obp_mux_tick(),
 * a still-failing peer is re-logged at ERROR every 5 minutes, and recovery is
 * logged at WARNING.  Call obp_mux_tick() once a second. */
void obp_mux_tick(obp_mux *mx);

int obp_peer_is_enabled(const obp_mux *mx, int peer_idx);

/* Why peer_idx is not usable: "disabled", "down (cannot bind udp/N: <reason>)",
 * or "up".  Writes into buf and returns it. */
const char *obp_peer_down_reason(const obp_mux *mx, int peer_idx, char *buf, size_t cap);

/* Enabled peers whose bind is failing: returns the count and lists them in buf
 * as "'name' (udp/N: <reason>)", comma-separated. */
int obp_mux_failed_peers(const obp_mux *mx, char *buf, size_t cap);

/* Send a DMRD frame to peer_idx.  body must be exactly OBP_DMRD_BODY_LEN (53)
 * bytes; bytes OBP_NETID_OFF..+4 are overwritten with that peer's own
 * network_id before HMAC signing and transmission (§12).  No-op (logged at
 * DEBUG) if the peer is disabled/has no socket. */
void obp_send_dmrd(obp_mux *mx, int peer_idx, uint8_t body[53]);

#endif /* OBP_LINK_H */
