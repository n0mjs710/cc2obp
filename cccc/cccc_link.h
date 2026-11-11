/* cccc_link.h — CC-CC side: one shared UDP 42422 (voice+keepalive) socket,
 * one shared UDP 42420 (trial-echo) socket, one shared TCP 42421 listener,
 * for every configured [[link]] regardless of remote c-Bridge (§5, §7.1).
 * Owns per-link handshake/keepalive/trial-echo/B-on-B-off mechanics; does
 * NOT own call state (translate.c does, §4/§7.2). */
#ifndef CCCC_LINK_H
#define CCCC_LINK_H

#include <stdint.h>
#include "../config.h"
#include "../eventloop.h"

typedef struct cccc_mux cccc_mux;
struct translator;

cccc_mux *cccc_mux_new(Config *cfg, struct translator *tr, ev_loop *loop);
int  cccc_mux_start(cccc_mux *mx);   /* binds shared sockets, dials enabled outbound links */
void cccc_mux_stop(cccc_mux *mx);
void cccc_mux_free(cccc_mux *mx);

/* SIGHUP reload (§6.3), in two steps around the swap to the new config:
 * cccc_mux_retire_link() stops one link (connection, reconnect timer) while
 * *cfg still holds its old values (a link being rebuilt or removed); after
 * the swap, cccc_mux_reconcile() starts every enabled link that is not
 * running and tears down newly-disabled ones.  The shared sockets and every
 * other link's connection are never touched. */
void cccc_mux_retire_link(cccc_mux *mx, int link_idx);
void cccc_mux_reconcile(cccc_mux *mx);

int cccc_link_is_up(const cccc_mux *mx, int link_idx);

/* Outbound application-level sends, by index into Config.link[].  No-ops
 * (logged at DEBUG) if the link is not currently up. */
void cccc_send_bon(cccc_mux *mx, int link_idx, uint32_t radio_id, uint32_t peer_id,
                   int src_lid, int tgid, char call_type);
void cccc_send_boff(cccc_mux *mx, int link_idx, int lost, int total, double rssi);
void cccc_send_voice(cccc_mux *mx, int link_idx, uint16_t seq, uint32_t timestamp,
                     int marker, const uint8_t ambe21[21]);

#endif /* CCCC_LINK_H */
