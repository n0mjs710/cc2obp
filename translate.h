/* translate.h — wires cccc_link <-> obp_link; owns the link table and
 * per-call state (§7.2, §10).  Port pattern follows ipsc2hbpc's
 * translate.h/translator, generalized from a single IPSC<->HBP pair to a
 * table of N independent [[link]] <-> [[openbridge]] conduits (§1). */
#ifndef TRANSLATE_H
#define TRANSLATE_H

#include <stdint.h>
#include "config.h"
#include "eventloop.h"

typedef struct translator translator;
struct cccc_mux;
struct obp_mux;

translator *translator_new(Config *cfg, ev_loop *loop);
void translator_set_protocols(translator *tr, struct cccc_mux *cc, struct obp_mux *ob);
void translator_free(translator *tr);

/* Periodic housekeeping (call-idle timeouts not otherwise covered by an
 * explicit teardown signal). */
void translator_tick(translator *tr);

/* ---- CC-CC side callbacks (called by cccc_link.c), by index into Config.link[] ---- */
void translator_cccc_link_up(translator *tr, int link_idx);
void translator_cccc_link_down(translator *tr, int link_idx);
void translator_cccc_bon(translator *tr, int link_idx, uint32_t radio_id, uint32_t peer_id,
                         int src_lid, int tgid, char call_type);
void translator_cccc_boff(translator *tr, int link_idx, int lost, int total);
void translator_cccc_voice(translator *tr, int link_idx, uint16_t seq, uint32_t timestamp,
                           int marker, const uint8_t ambe21[21]);

/* SIGHUP reload (§6.3): forget any call state on a link that is being
 * rebuilt or removed (its slot may come back as a different link). */
void translator_link_reset(translator *tr, int link_idx);

/* ---- OpenBridge side callback (called by obp_link.c), by index into Config.openbridge[] ---- */
void translator_obp_dmrd_received(translator *tr, int peer_idx, const uint8_t body53[53]);

#endif /* TRANSLATE_H */
