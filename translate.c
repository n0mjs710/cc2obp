/* translate.c — wires cccc_link <-> obp_link; the link table; per-call state;
 * the two directional flows (§7, §10).  DMR burst assembly/decode ported
 * directly from ipsc2hbpc's translate.c (build_embed/build_gv/
 * extract_ambe_from_dmrd equivalents; §11) — same primitives, same byte
 * layout, generalized from IPSC's GROUP_VOICE framing to OpenBridge's DMRD
 * framing and from IPSC's fixed TS1/TS2 pair to an arbitrary link table.
 *
 * OpenBridge -> CC-CC ingest does NOT decode the VOICE_HEAD's BPTC-encoded
 * Full LC (an earlier revision did, plus a dmr_csum5 call on the result —
 * both removed). rf_src, TGID/dst_id, and the stream identifier are all
 * plain DMRD header fields at fixed offsets (OBP_SRC_OFF/OBP_DST_OFF/
 * OBP_STREAM_OFF, obp_const.h) — confirmed against hblink3's own
 * dmrd_received parsing — so decoding the LC to reach them was pure
 * overhead. It also bought nothing security-wise: the whole 53-byte DMRD
 * body those header fields live in is already HMAC-SHA1-signed end to end
 * (obp_link.c), a far stronger check than the LC's own embedded checksum
 * (which, per dmr_utils3's crc.py/bptc.py, doesn't even apply to a Full LC —
 * see the prior git history for that dead end). The LC *encode* path is
 * unaffected: CC-CC -> OpenBridge egress still builds a fresh Full LC per
 * call from the B-on's plain-text fields (translator_cccc_bon,
 * build_head_term_payload) to embed in outgoing VOICE_HEAD/TERM frames. */
#include "translate.h"
#include "cccc/cccc_link.h"
#include "cccc/cccc_ambe.h"
#include "cccc/cccc_const.h"
#include "openbridge/obp_link.h"
#include "openbridge/obp_const.h"
#include "dmr/dmr.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define LOGN "translate"

#define CALL_IDLE_TIMEOUT_S 5.0

typedef enum { CALL_ORIGIN_NONE = 0, CALL_ORIGIN_CC, CALL_ORIGIN_OBP } call_origin_t;

typedef struct {
    call_origin_t origin;
    uint32_t rf_src;
    uint32_t peer_id;          /* OBP-origin only: sender's received network_id (§10.1) */
    uint32_t cc_peer_id;       /* CC-origin only: source-peer from the B-on, forwarded into
                                * the outgoing DMRD Repeater-ID field when the peer's
                                * preserve_source_peer is set (else network_id overwrites it) */
    uint8_t  stream_id[4];
    uint8_t  lc[9];            /* opt(3) + dst_group/tgid(3) + src_sub/rf_src(3) */
    uint8_t  emb[4][4];        /* embedded LC fragments B..E, from dmr_encode_emblc */
    double   call_start_time;
    double   last_activity;
    int      cc_sent_first;    /* CC-CC RTP marker-bit tracking (obp-origin) */
    int      cc_seq;           /* most recent wall-clock slot index (§10.4, obp-origin) */
    int      obp_seq_pos;      /* outgoing OpenBridge burst-position counter 0..5 (cc-origin) */
    int      obp_seq;          /* outgoing OpenBridge DMRD sequence, 0 at VOICE_HEAD, wraps at 256 (cc-origin) */
} call_state;

typedef struct {
    int         has_call;
    call_state  call;
    int         cx_drop_logged; /* §6.3: log a cross-connect-inactive drop once per attempt */
} link_runtime;

struct translator {
    Config     *cfg;
    ev_loop    *loop;
    struct cccc_mux *cc;
    struct obp_mux   *ob;
    link_runtime link[CFG_MAX_LINKS];
};

/* ---------------- small helpers ---------------- */

static uint32_t rd24(const uint8_t *p) { return ((uint32_t)p[0]<<16)|((uint32_t)p[1]<<8)|p[2]; }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void wr24(uint8_t *p, uint32_t v) { p[0]=(uint8_t)(v>>16); p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }

static void rand4(uint8_t out[4])
{
    if (getrandom(out, 4, 0) != 4) { out[0]=(uint8_t)rand(); out[1]=(uint8_t)rand(); out[2]=(uint8_t)rand(); out[3]=(uint8_t)rand(); }
}

static int obp_gate_open(translator *tr, int link_idx, const char *dir_label)
{
    const LinkConfig *lcfg = &tr->cfg->link[link_idx];
    link_runtime *lr = &tr->link[link_idx];
    int peer_ok = lcfg->openbridge_idx >= 0 && obp_peer_is_enabled(tr->ob, lcfg->openbridge_idx);

    if (lcfg->cross_connect_active && peer_ok) return 1;

    if (!lr->cx_drop_logged) {
        if (!peer_ok) {
            char why[192];
            LOGW(LOGN, "link '%s': cross-connect inactive, openbridge system '%s' is %s — dropping %s",
                 lcfg->name, lcfg->openbridge_system,
                 obp_peer_down_reason(tr->ob, lcfg->openbridge_idx, why, sizeof why), dir_label);
        }
        else
            LOGW(LOGN, "link '%s': cross-connect inactive — dropping %s", lcfg->name, dir_label);
        lr->cx_drop_logged = 1;
    }
    return 0;
}

/* ---------------- DMR burst assembly (ported from ipsc2hbpc translate.c) ---------------- */

/* Full LC (VOICE_HEAD/TERM) -> 33-byte DMR burst payload. */
static void build_head_term_payload(const uint8_t lc[9], int is_term, uint8_t out33[33])
{
    dmr_bit full_lc[196]; dmr_bptc_encode_lc(lc, is_term, full_lc);
    dmr_bit fb[264]; int at = 0;
    const dmr_bit *slot_type = is_term ? DMR_SLOT_TYPE_VTERM : DMR_SLOT_TYPE_VHEAD;
    memcpy(fb+at, full_lc, 98); at += 98;
    memcpy(fb+at, slot_type, 10); at += 10;
    memcpy(fb+at, DMR_BS_DATA_SYNC, 48); at += 48;
    memcpy(fb+at, slot_type + 10, 10); at += 10;
    memcpy(fb+at, full_lc + 98, 98); at += 98;
    dmr_bits_to_bytes(fb, 264, out33);
}

/* Voice burst position -> 48-bit EMBED field (sync for pos 0, EMB header +
 * embedded-LC fragment for pos 1-4, null embedded LC for pos 5). */
static void build_embed(const call_state *call, int pos, dmr_bit embed[48])
{
    if (pos == 0) { memcpy(embed, DMR_BS_VOICE_SYNC, 48); return; }
    int eidx = pos - 1;
    memcpy(embed, DMR_EMB[eidx], 8);
    if (pos <= 4) dmr_bytes_to_bits(call->emb[pos - 1], 4, embed + 8);
    else memset(embed + 8, 0, 32);
    memcpy(embed + 40, DMR_EMB[eidx] + 8, 8);
}

/* 33-byte DMR burst -> 3x49-bit AMBE (inverse of the voice-burst assembly). */
static void extract_ambe(const uint8_t payload33[33], dmr_bit ambe49[3][49])
{
    dmr_bit burst[264]; dmr_bytes_to_bits(payload33, 33, burst);
    dmr_bit a1_72[72], a2_72[72], a3_72[72];
    memcpy(a1_72, burst + 0, 72);
    memcpy(a2_72, burst + 72, 36);
    memcpy(a2_72 + 36, burst + 156, 36);
    memcpy(a3_72, burst + 192, 72);
    dmr_ambe_72_to_49(a1_72, ambe49[0]);
    dmr_ambe_72_to_49(a2_72, ambe49[1]);
    dmr_ambe_72_to_49(a3_72, ambe49[2]);
}

/* ---------------- OpenBridge DMRD frame send (§10.2) ---------------- */

static void send_dmrd(translator *tr, int link_idx, uint8_t flags, const uint8_t payload33[33])
{
    const LinkConfig *lcfg = &tr->cfg->link[link_idx];
    link_runtime *lr = &tr->link[link_idx];
    int peer_idx = lcfg->openbridge_idx;
    if (peer_idx < 0) return;

    uint8_t body[53];
    memcpy(body, "DMRD", 4);
    /* Per call, not per peer as Project Plan §16 had it: receivers check loss
     * per stream (FreeDMR, ADN), so a counter shared by every call on the peer
     * reads as missed packets on both calls whenever two of them overlap.
     * MMDVMHost and the CC-CC side (§6.1) also number from 0 per call. */
    body[4] = (uint8_t)(lr->call.obp_seq++ & 0xFF);
    wr24(body + 5, lr->call.rf_src);
    wr24(body + 8, (uint32_t)lcfg->tgid);
    /* Repeater-ID field: seed with the CC-origin source-peer. obp_send_dmrd
     * overwrites it with our network_id unless preserve_source_peer is set (§12). */
    wr32(body + 11, lr->call.cc_peer_id);
    body[15] = flags;
    memcpy(body + 16, lr->call.stream_id, 4);
    memcpy(body + 20, payload33, 33);

    obp_send_dmrd(tr->ob, peer_idx, body);
}

static void send_obp_voice_head(translator *tr, int link_idx)
{
    uint8_t payload33[33];
    build_head_term_payload(tr->link[link_idx].call.lc, 0, payload33);
    send_dmrd(tr, link_idx, OBPF_FRAMETYPE_DATASYNC | OBPF_SLT_VHEAD, payload33);
}

static void send_obp_voice_term(translator *tr, int link_idx)
{
    uint8_t payload33[33];
    build_head_term_payload(tr->link[link_idx].call.lc, 1, payload33);
    send_dmrd(tr, link_idx, OBPF_FRAMETYPE_DATASYNC | OBPF_SLT_VTERM, payload33);
}

/* ---------------- call lifecycle helpers ---------------- */

static void end_obp_origin_call(translator *tr, int link_idx, const char *reason)
{
    link_runtime *lr = &tr->link[link_idx];
    if (!lr->has_call || lr->call.origin != CALL_ORIGIN_OBP) return;
    int total = lr->call.cc_sent_first ? (lr->call.cc_seq + 1) : 0;
    cccc_send_boff(tr->cc, link_idx, 0, total, 0);
    LOGI(LOGN, "link '%s': obp-origin call end (%s) — src=%u total=%d",
         tr->cfg->link[link_idx].name, reason, lr->call.rf_src, total);
    lr->has_call = 0;
}

static void end_cc_origin_call(translator *tr, int link_idx, const char *reason)
{
    link_runtime *lr = &tr->link[link_idx];
    if (!lr->has_call || lr->call.origin != CALL_ORIGIN_CC) return;
    send_obp_voice_term(tr, link_idx);
    LOGI(LOGN, "link '%s': cc-origin call end (%s) — src=%u",
         tr->cfg->link[link_idx].name, reason, lr->call.rf_src);
    lr->has_call = 0;
}

/* ---------------- OpenBridge -> CC-CC (§10.1) ---------------- */

static void handle_obp_voice_head(translator *tr, int link_idx, uint32_t peer_id, uint32_t rf_src,
                                  const uint8_t stream[4])
{
    const LinkConfig *lcfg = &tr->cfg->link[link_idx];
    link_runtime *lr = &tr->link[link_idx];

    /* rf_src/tgid/stream are already the caller's, straight from the DMRD
     * header (fixed offsets, HMAC-covered) — no LC decode needed to reach
     * them (see file header comment). */

    if (lr->has_call && lr->call.origin == CALL_ORIGIN_OBP) {
        if (memcmp(stream, lr->call.stream_id, 4) == 0) {
            LOGD(LOGN, "link '%s': duplicate VOICE_HEAD — stream unchanged", lcfg->name);
            return;
        }
        LOGW(LOGN, "link '%s': orphaned obp-origin call (VOICE_HEAD with new stream, no prior VOICE_TERM)",
             lcfg->name);
        end_obp_origin_call(tr, link_idx, "orphaned by new VOICE_HEAD");
        /* fall through: start the new call below */
    } else if (lr->has_call && lr->call.origin == CALL_ORIGIN_CC) {
        LOGW(LOGN, "link '%s': path contention — dropping obp-origin VOICE_HEAD, cc-origin call in progress (§10.3)",
             lcfg->name);
        return;
    }

    memset(&lr->call, 0, sizeof lr->call);
    lr->call.origin = CALL_ORIGIN_OBP;
    lr->call.rf_src = rf_src;
    lr->call.peer_id = peer_id;
    memcpy(lr->call.stream_id, stream, 4);
    /* lr->call.lc is intentionally left zeroed here: it's only ever read
     * back for CALL_ORIGIN_CC calls (translator_cccc_bon populates it fresh
     * from the B-on's fields for the CC-CC->OpenBridge egress LC encode);
     * an obp-origin call has no use for it. */
    lr->call.call_start_time = ev_now(tr->loop);
    lr->call.last_activity = lr->call.call_start_time;
    lr->has_call = 1;

    LOGI(LOGN, "link '%s': obp-origin call start — src=%u peer=%u tgid=%d",
         lcfg->name, rf_src, peer_id, lcfg->tgid);
    cccc_send_bon(tr->cc, link_idx, rf_src, peer_id, lcfg->cc_lid, lcfg->tgid, CCCC_CALL_TYPE_GROUP);
}

static void handle_obp_voice_burst(translator *tr, int link_idx, const uint8_t *payload33, const uint8_t stream[4])
{
    link_runtime *lr = &tr->link[link_idx];
    if (!lr->has_call || lr->call.origin != CALL_ORIGIN_OBP) {
        LOGD(LOGN, "link '%s': voice burst with no active obp-origin call — dropped", tr->cfg->link[link_idx].name);
        return;
    }
    if (memcmp(stream, lr->call.stream_id, 4) != 0) {
        LOGD(LOGN, "link '%s': voice burst stream mismatch — dropped (stray/superseded stream)",
             tr->cfg->link[link_idx].name);
        return;
    }

    lr->call.last_activity = ev_now(tr->loop);

    dmr_bit ambe49[3][49];
    extract_ambe(payload33, ambe49);
    uint8_t payload21[21];
    cccc_ambe_pack21(ambe49, payload21);

    /* §10.4: sequence and timestamp both derived from the same wall-clock
     * slot index — a real gap in delivery produces a real, consistent gap in
     * both fields, matching what a receiver's de-jitter logic expects. */
    double now = ev_now(tr->loop);
    int slot_index = (int)((now - lr->call.call_start_time) / CCCC_SLOT_MS + 0.5);
    uint16_t seq = (uint16_t)slot_index;
    uint32_t timestamp = (uint32_t)((uint32_t)CCCC_RTP_TS_STEP * (uint32_t)slot_index);
    int marker = !lr->call.cc_sent_first;
    lr->call.cc_sent_first = 1;
    lr->call.cc_seq = slot_index;

    cccc_send_voice(tr->cc, link_idx, seq, timestamp, marker, payload21);
}

static void handle_obp_voice_term(translator *tr, int link_idx, const uint8_t stream[4])
{
    link_runtime *lr = &tr->link[link_idx];
    if (!lr->has_call || lr->call.origin != CALL_ORIGIN_OBP) {
        LOGD(LOGN, "link '%s': VOICE_TERM with no active obp-origin call — dropped", tr->cfg->link[link_idx].name);
        return;
    }
    if (memcmp(stream, lr->call.stream_id, 4) != 0) {
        /* §10.1 step3: must NOT end a different, still-active call. */
        LOGD(LOGN, "link '%s': VOICE_TERM stream mismatch — dropped, active call unaffected",
             tr->cfg->link[link_idx].name);
        return;
    }
    end_obp_origin_call(tr, link_idx, "VOICE_TERM");
}

void translator_obp_dmrd_received(translator *tr, int peer_idx, const uint8_t body[53])
{
    uint32_t peer_id = rd32(body + OBP_NETID_OFF);
    uint32_t rf_src  = rd24(body + OBP_SRC_OFF);
    uint32_t dst_id  = rd24(body + OBP_DST_OFF);
    uint8_t  flags   = body[OBP_FLAGS_OFF];
    const uint8_t *stream    = body + OBP_STREAM_OFF;
    const uint8_t *payload33 = body + OBP_PAYLOAD_OFF;

    if (flags & OBPF_CALL_UNIT) { LOGD(LOGN, "obp: unit call dropped (out of scope, §1)"); return; }
    if ((flags & OBPF_VCSBK_MASK) == OBPF_VCSBK_MASK) { LOGD(LOGN, "obp: csbk/data frame dropped"); return; }

    int link_idx = -1;
    for (int i = 0; i < tr->cfg->n_link; i++) {
        if (!tr->cfg->link[i].vacant && tr->cfg->link[i].openbridge_idx == peer_idx &&
            (uint32_t)tr->cfg->link[i].tgid == dst_id) {
            link_idx = i;
            break;
        }
    }
    if (link_idx < 0) {
        LOGW(LOGN, "obp: no configured [[link]] for (openbridge_system='%s', tgid=%u) — dropped",
             tr->cfg->openbridge[peer_idx].name, dst_id);
        return;
    }

    const LinkConfig *lcfg = &tr->cfg->link[link_idx];
    if (!lcfg->enabled) { LOGD(LOGN, "link '%s': disabled — dropping obp-origin traffic", lcfg->name); return; }

    int frame_type = flags & OBPF_FRAMETYPE_MASK;
    int dtype = flags & OBPF_DTYPE_MASK;
    int is_head = (frame_type == OBPF_FRAMETYPE_DATASYNC && dtype == OBPF_SLT_VHEAD);
    int is_term = (frame_type == OBPF_FRAMETYPE_DATASYNC && dtype == OBPF_SLT_VTERM);

    if (is_head) tr->link[link_idx].cx_drop_logged = 0;   /* new attempt boundary (§6.3) */
    if (!obp_gate_open(tr, link_idx, "obp-origin traffic")) return;

    if (is_head) handle_obp_voice_head(tr, link_idx, peer_id, rf_src, stream);
    else if (is_term) handle_obp_voice_term(tr, link_idx, stream);
    else handle_obp_voice_burst(tr, link_idx, payload33, stream);
}

/* ---------------- CC-CC -> OpenBridge (§10.2) ---------------- */

void translator_cccc_bon(translator *tr, int link_idx, uint32_t radio_id, uint32_t peer_id,
                         int src_lid, int tgid, char call_type)
{
    (void)src_lid; (void)tgid; (void)call_type;
    /* §5 of the formal spec: TGID/call-type in the incoming B-on reflect the
     * ORIGINATING side and MUST NOT be used for delivery routing — this
     * link's own configured tgid is used instead (already used below). */
    const LinkConfig *lcfg = &tr->cfg->link[link_idx];
    link_runtime *lr = &tr->link[link_idx];

    if (!lcfg->enabled) { LOGD(LOGN, "link '%s': disabled — dropping cc-origin B-on", lcfg->name); return; }

    tr->link[link_idx].cx_drop_logged = 0;   /* new attempt boundary (§6.3) */
    if (!obp_gate_open(tr, link_idx, "cc-origin call attempt")) return;

    if (lr->has_call && lr->call.origin == CALL_ORIGIN_CC) {
        LOGD(LOGN, "link '%s': duplicate B-on for in-progress cc-origin call — ignored", lcfg->name);
        return;
    }
    if (lr->has_call && lr->call.origin == CALL_ORIGIN_OBP) {
        LOGW(LOGN, "link '%s': path contention — dropping cc-origin B-on, obp-origin call in progress (§10.3)",
             lcfg->name);
        return;
    }

    memset(&lr->call, 0, sizeof lr->call);
    lr->call.origin = CALL_ORIGIN_CC;
    lr->call.rf_src = radio_id;
    lr->call.cc_peer_id = peer_id;   /* B-on source-peer; forwarded outbound if preserve_source_peer set */
    rand4(lr->call.stream_id);
    lr->call.call_start_time = ev_now(tr->loop);
    lr->call.last_activity = lr->call.call_start_time;
    lr->call.obp_seq_pos = 0;
    lr->call.obp_seq = 0;

    lr->call.lc[0] = DMR_LC_OPT[0]; lr->call.lc[1] = DMR_LC_OPT[1]; lr->call.lc[2] = DMR_LC_OPT[2];
    wr24(lr->call.lc + 3, (uint32_t)lcfg->tgid);
    wr24(lr->call.lc + 6, radio_id);
    dmr_encode_emblc(lr->call.lc, lr->call.emb);
    lr->has_call = 1;

    LOGI(LOGN, "link '%s': cc-origin call start — src=%u tgid=%d", lcfg->name, radio_id, lcfg->tgid);
    send_obp_voice_head(tr, link_idx);
}

void translator_cccc_voice(translator *tr, int link_idx, uint16_t seq, uint32_t timestamp,
                           int marker, const uint8_t ambe21[21])
{
    (void)seq; (void)timestamp; (void)marker;   /* relay as-is; no re-pacing/jitter buffer (§1, §10.4) */
    link_runtime *lr = &tr->link[link_idx];
    const LinkConfig *lcfg = &tr->cfg->link[link_idx];
    if (!lr->has_call || lr->call.origin != CALL_ORIGIN_CC) {
        LOGD(LOGN, "link '%s': voice with no active cc-origin call — dropped", lcfg->name);
        return;
    }
    if (!lcfg->cross_connect_active) return;   /* already logged once at B-on time */

    lr->call.last_activity = ev_now(tr->loop);

    dmr_bit ambe49[3][49];
    cccc_ambe_unpack21(ambe21, ambe49);
    dmr_bit a1_72[72], a2_72[72], a3_72[72];
    dmr_ambe_49_to_72(ambe49[0], a1_72);
    dmr_ambe_49_to_72(ambe49[1], a2_72);
    dmr_ambe_49_to_72(ambe49[2], a3_72);

    int pos = lr->call.obp_seq_pos % 6;
    dmr_bit embed[48];
    build_embed(&lr->call, pos, embed);

    dmr_bit fb[264]; int at = 0;
    memcpy(fb+at, a1_72, 72); at += 72;
    memcpy(fb+at, a2_72, 36); at += 36;
    memcpy(fb+at, embed, 48); at += 48;
    memcpy(fb+at, a2_72 + 36, 36); at += 36;
    memcpy(fb+at, a3_72, 72); at += 72;
    uint8_t payload33[33]; dmr_bits_to_bytes(fb, 264, payload33);

    uint8_t flags = (pos == 0) ? OBPF_FRAMETYPE_VOICESYNC : (uint8_t)(OBPF_FRAMETYPE_VOICE | pos);
    send_dmrd(tr, link_idx, flags, payload33);
    lr->call.obp_seq_pos++;
}

void translator_cccc_boff(translator *tr, int link_idx, int lost, int total)
{
    (void)lost; (void)total;   /* not forwarded — OpenBridge has no B-off analog beyond VOICE_TERM */
    end_cc_origin_call(tr, link_idx, "B-off");
}

void translator_cccc_link_up(translator *tr, int link_idx)
{
    tr->link[link_idx].cx_drop_logged = 0;
    LOGI(LOGN, "link '%s': CC-CC up", tr->cfg->link[link_idx].name);
}

void translator_cccc_link_down(translator *tr, int link_idx)
{
    link_runtime *lr = &tr->link[link_idx];
    if (lr->has_call && lr->call.origin == CALL_ORIGIN_CC) {
        /* §10.2 step4: best-effort VOICE_TERM so the OpenBridge peer is not left waiting. */
        send_obp_voice_term(tr, link_idx);
        LOGW(LOGN, "link '%s': CC-CC dropped mid-call — best-effort VOICE_TERM sent to OpenBridge",
             tr->cfg->link[link_idx].name);
    }
    lr->has_call = 0;
    lr->cx_drop_logged = 0;
}

void translator_link_reset(translator *tr, int link_idx)
{
    memset(&tr->link[link_idx], 0, sizeof tr->link[link_idx]);
}

/* ---------------- lifecycle / housekeeping ---------------- */

translator *translator_new(Config *cfg, ev_loop *loop)
{
    translator *tr = calloc(1, sizeof *tr);
    tr->cfg = cfg;
    tr->loop = loop;
    return tr;
}

void translator_set_protocols(translator *tr, struct cccc_mux *cc, struct obp_mux *ob)
{
    tr->cc = cc;
    tr->ob = ob;
}

void translator_free(translator *tr)
{
    free(tr);
}

void translator_tick(translator *tr)
{
    double now = ev_now(tr->loop);
    for (int i = 0; i < tr->cfg->n_link; i++) {
        link_runtime *lr = &tr->link[i];
        if (!lr->has_call) continue;
        if (now - lr->call.last_activity > CALL_IDLE_TIMEOUT_S) {
            LOGW(LOGN, "link '%s': call idle for >%.0fs — force-ending",
                 tr->cfg->link[i].name, CALL_IDLE_TIMEOUT_S);
            if (lr->call.origin == CALL_ORIGIN_OBP) end_obp_origin_call(tr, i, "idle timeout");
            else end_cc_origin_call(tr, i, "idle timeout");
        }
    }
}
