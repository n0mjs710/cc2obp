/* obp_link.c — see obp_link.h.  Wire format confirmed against hblink3's
 * `class OPENBRIDGE` (hblink.py: send_system/datagram_received), not just
 * the informal description: 53-byte DMRD body + 20-byte HMAC-SHA1 (§12). */
#include "obp_link.h"
#include "obp_const.h"
#include "../translate.h"
#include "../net.h"
#include "../crypto.h"
#include "../log.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define LOGN "obp.link"

#define BIND_RETRY_S     10.0    /* retry interval for a peer whose bind failed */
#define BIND_REMINDER_S  300.0   /* re-log a peer that is still failing to bind */

struct obp_mux {
    Config     *cfg;
    struct translator *tr;
    ev_loop    *loop;
    int         fd[CFG_MAX_OPENBRIDGE];
    int         active[CFG_MAX_OPENBRIDGE];  /* mirrors cfg->openbridge[i].enabled at last (re)bind */
    struct { obp_mux *mx; int idx; } cbctx[CFG_MAX_OPENBRIDGE];

    /* bind failure state, per peer: bind_errno == 0 means not failing */
    int         bind_errno[CFG_MAX_OPENBRIDGE];
    int         bind_attempts[CFG_MAX_OPENBRIDGE];
    double      down_since[CFG_MAX_OPENBRIDGE];
    double      next_retry[CFG_MAX_OPENBRIDGE];
    double      next_reminder[CFG_MAX_OPENBRIDGE];
};

/* Constant-time-ish digest compare (defense in depth; not a hard requirement
 * of the plan, but cheap and matches good practice for an HMAC check). */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static void on_obp_readable(ev_loop *loop, int fd, void *ud)
{
    (void)loop;
    struct { obp_mux *mx; int idx; } *ctx = ud;
    obp_mux *mx = ctx->mx;
    int idx = ctx->idx;
    const ObpPeerConfig *o = &mx->cfg->openbridge[idx];

    uint8_t buf[128];
    char src_ip[INET6_ADDRSTRLEN]; int src_port;
    int n = udp_recvfrom(fd, buf, sizeof buf, src_ip, &src_port);
    if (n < 4 || memcmp(buf, "DMRD", 4) != 0) return;
    log_wire("obp.wire", "UDP RECV %s:%d %d %s", src_ip, src_port, n, log_hex(buf, n));

    if (n != OBP_DMRD_PKT_LEN) {
        LOGD(LOGN, "peer '%s': unexpected length %d (want %d) from %s:%d — dropped",
             o->name, n, OBP_DMRD_PKT_LEN, src_ip, src_port);
        return;
    }
    if (strcmp(src_ip, o->peer_ip) != 0 || src_port != o->peer_port) {
        LOGW(LOGN, "peer '%s': packet from unexpected source %s:%d (expected %s:%d) — dropped",
             o->name, src_ip, src_port, o->peer_ip, o->peer_port);
        return;
    }

    uint8_t expect[OBP_HMAC_LEN];
    hmac_sha1((const uint8_t *)o->passphrase, (size_t)o->passphrase_len,
              buf, OBP_DMRD_BODY_LEN, expect);
    if (!ct_eq(expect, buf + OBP_DMRD_BODY_LEN, OBP_HMAC_LEN)) {
        LOGW(LOGN, "peer '%s': HMAC verification failed — dropped", o->name);
        return;
    }

    /* §1: cc2obp is always slot 1 (an OpenBridge convention); no BOTH_SLOTS
     * support (out of scope). Group/unit/CSBK classification is translate.c's
     * job (§10.1), not this transport-layer gate. */
    uint8_t flags = buf[OBP_FLAGS_OFF];
    if (flags & OBPF_SLOT2) {
        LOGW(LOGN, "peer '%s': packet not on slot 1 — dropped (§1)", o->name);
        return;
    }

    translator_obp_dmrd_received(mx->tr, idx, buf);
}

/* Names of the enabled [[link]] entries routed through peer idx, for log lines. */
static void affected_links(const obp_mux *mx, int idx, char *out, size_t cap)
{
    size_t at = 0;
    out[0] = 0;
    for (int i = 0; i < mx->cfg->n_link && at < cap; i++) {
        const LinkConfig *l = &mx->cfg->link[i];
        if (l->vacant || !l->enabled || l->openbridge_idx != idx) continue;
        int n = snprintf(out + at, cap - at, "%s'%s'", at ? ", " : "", l->name);
        if (n < 0) break;
        at += (size_t)n;
    }
    if (!out[0]) snprintf(out, cap, "(none)");
}

static void clear_bind_failure(obp_mux *mx, int idx)
{
    mx->bind_errno[idx] = 0;
    mx->bind_attempts[idx] = 0;
}

static void note_bind_failure(obp_mux *mx, int idx, int err)
{
    const ObpPeerConfig *o = &mx->cfg->openbridge[idx];
    double now = ev_now(mx->loop);
    char links[1024];

    if (!mx->bind_errno[idx]) {
        mx->down_since[idx] = now;
        mx->bind_attempts[idx] = 0;
    }
    mx->bind_attempts[idx]++;
    mx->bind_errno[idx] = err;
    mx->next_retry[idx] = now + BIND_RETRY_S;
    mx->next_reminder[idx] = now + BIND_REMINDER_S;

    affected_links(mx, idx, links, sizeof links);
    LOGE(LOGN, "openbridge peer '%s' DOWN: cannot bind udp/%d (%s) — no traffic to or from it; "
               "links cut off: %s; retrying every %.0fs",
         o->name, o->bind_port, strerror(err), links, BIND_RETRY_S);
}

/* Returns 0 on success, else the errno of the failed bind. */
static int try_bind(obp_mux *mx, int idx)
{
    ObpPeerConfig *o = &mx->cfg->openbridge[idx];
    int fd = udp_bind("0.0.0.0", o->bind_port);
    if (fd < 0) return errno ? errno : EIO;
    mx->fd[idx] = fd;
    mx->cbctx[idx].mx = mx;
    mx->cbctx[idx].idx = idx;
    ev_add_fd(mx->loop, fd, on_obp_readable, &mx->cbctx[idx]);
    mx->active[idx] = 1;
    LOGI(LOGN, "openbridge peer '%s' socket up: local udp/%d -> remote %s:%d (network_id=%u)",
         o->name, o->bind_port, o->peer_ip, o->peer_port, o->network_id);
    return 0;
}

static void bind_peer(obp_mux *mx, int idx)
{
    int err = try_bind(mx, idx);
    if (err) note_bind_failure(mx, idx, err);
    else     clear_bind_failure(mx, idx);
}

static void unbind_peer(obp_mux *mx, int idx)
{
    if (mx->fd[idx] >= 0) {
        ev_del_fd(mx->loop, mx->fd[idx]);
        close(mx->fd[idx]);
        mx->fd[idx] = -1;
    }
    mx->active[idx] = 0;
    clear_bind_failure(mx, idx);
    LOGI(LOGN, "openbridge peer '%s' socket down", mx->cfg->openbridge[idx].name);
}

int obp_peer_is_enabled(const obp_mux *mx, int peer_idx)
{
    if (peer_idx < 0 || peer_idx >= mx->cfg->n_openbridge) return 0;
    return mx->active[peer_idx];
}

void obp_send_dmrd(obp_mux *mx, int peer_idx, uint8_t body[53])
{
    if (peer_idx < 0 || peer_idx >= mx->cfg->n_openbridge || mx->fd[peer_idx] < 0) {
        LOGD(LOGN, "obp_send_dmrd: peer idx=%d not enabled/bound — dropped", peer_idx);
        return;
    }
    ObpPeerConfig *o = &mx->cfg->openbridge[peer_idx];

    /* §12: bytes 11-14 (peer/network ID field) are normally overwritten with
     * OUR OWN network_id for this peer before signing — not anything from the
     * originating side. This field is not validated by the reference
     * implementation (auth = HMAC + source socket), so preserve_source_peer
     * leaves whatever the caller placed there (the CC-origin source-peer, set
     * by send_dmrd) intact for end-to-end provenance. Default: overwrite. */
    if (!o->preserve_source_peer) {
        body[OBP_NETID_OFF + 0] = (uint8_t)(o->network_id >> 24);
        body[OBP_NETID_OFF + 1] = (uint8_t)(o->network_id >> 16);
        body[OBP_NETID_OFF + 2] = (uint8_t)(o->network_id >> 8);
        body[OBP_NETID_OFF + 3] = (uint8_t)(o->network_id);
    }

    uint8_t pkt[OBP_DMRD_PKT_LEN];
    memcpy(pkt, body, OBP_DMRD_BODY_LEN);
    hmac_sha1((const uint8_t *)o->passphrase, (size_t)o->passphrase_len,
              pkt, OBP_DMRD_BODY_LEN, pkt + OBP_DMRD_BODY_LEN);
    log_wire("obp.wire", "UDP SEND %s:%d %d %s", o->peer_ip, o->peer_port, OBP_DMRD_PKT_LEN, log_hex(pkt, OBP_DMRD_PKT_LEN));
    udp_sendto(mx->fd[peer_idx], pkt, OBP_DMRD_PKT_LEN, o->peer_ip, o->peer_port);
}

obp_mux *obp_mux_new(Config *cfg, struct translator *tr, ev_loop *loop)
{
    obp_mux *mx = calloc(1, sizeof *mx);
    mx->cfg = cfg; mx->tr = tr; mx->loop = loop;
    for (int i = 0; i < CFG_MAX_OPENBRIDGE; i++) mx->fd[i] = -1;
    return mx;
}

int obp_mux_start(obp_mux *mx)
{
    for (int i = 0; i < mx->cfg->n_openbridge; i++)
        if (mx->cfg->openbridge[i].enabled)
            bind_peer(mx, i);   /* non-fatal per-peer failure: other peers/links are independent */
    return 0;
}

void obp_mux_retire_peer(obp_mux *mx, int peer_idx)
{
    if (mx->active[peer_idx]) unbind_peer(mx, peer_idx);
    clear_bind_failure(mx, peer_idx);
}

void obp_mux_reconcile(obp_mux *mx)
{
    /* Close before binding: a peer enabled by this reload may take the
     * bind_port of one disabled by it. */
    for (int i = 0; i < mx->cfg->n_openbridge; i++) {
        const ObpPeerConfig *o = &mx->cfg->openbridge[i];
        if (!o->enabled || o->vacant) {
            if (mx->active[i]) unbind_peer(mx, i);
            clear_bind_failure(mx, i);
        }
    }
    for (int i = 0; i < mx->cfg->n_openbridge; i++) {
        const ObpPeerConfig *o = &mx->cfg->openbridge[i];
        if (o->enabled && !o->vacant && !mx->active[i]) bind_peer(mx, i);
    }
}

void obp_mux_tick(obp_mux *mx)
{
    double now = ev_now(mx->loop);
    for (int i = 0; i < mx->cfg->n_openbridge; i++) {
        const ObpPeerConfig *o = &mx->cfg->openbridge[i];
        if (!mx->bind_errno[i] || mx->active[i] || !o->enabled || o->vacant) continue;
        if (now < mx->next_retry[i]) continue;

        mx->bind_attempts[i]++;
        int err = try_bind(mx, i);
        if (!err) {
            LOGW(LOGN, "openbridge peer '%s' RECOVERED: bound udp/%d after %d attempts, down %.0fs",
                 o->name, o->bind_port, mx->bind_attempts[i], now - mx->down_since[i]);
            clear_bind_failure(mx, i);
            continue;
        }
        mx->next_retry[i] = now + BIND_RETRY_S;
        if (err != mx->bind_errno[i] || now >= mx->next_reminder[i]) {
            char links[1024];
            affected_links(mx, i, links, sizeof links);
            mx->bind_errno[i] = err;
            mx->next_reminder[i] = now + BIND_REMINDER_S;
            LOGE(LOGN, "openbridge peer '%s' STILL DOWN for %.0fs: cannot bind udp/%d (%s), %d attempts — "
                       "links cut off: %s; still retrying every %.0fs",
                 o->name, now - mx->down_since[i], o->bind_port, strerror(err),
                 mx->bind_attempts[i], links, BIND_RETRY_S);
        }
    }
}

const char *obp_peer_down_reason(const obp_mux *mx, int peer_idx, char *buf, size_t cap)
{
    if (peer_idx < 0 || peer_idx >= mx->cfg->n_openbridge) { snprintf(buf, cap, "not configured"); return buf; }
    const ObpPeerConfig *o = &mx->cfg->openbridge[peer_idx];
    if (mx->active[peer_idx]) { snprintf(buf, cap, "up"); return buf; }
    if (!o->enabled) { snprintf(buf, cap, "disabled"); return buf; }
    if (mx->bind_errno[peer_idx])
        snprintf(buf, cap, "down (cannot bind udp/%d: %s)", o->bind_port, strerror(mx->bind_errno[peer_idx]));
    else
        snprintf(buf, cap, "down");
    return buf;
}

int obp_mux_failed_peers(const obp_mux *mx, char *buf, size_t cap)
{
    int count = 0;
    size_t at = 0;
    buf[0] = 0;
    for (int i = 0; i < mx->cfg->n_openbridge; i++) {
        const ObpPeerConfig *o = &mx->cfg->openbridge[i];
        if (!mx->bind_errno[i] || mx->active[i] || !o->enabled || o->vacant) continue;
        count++;
        if (at < cap) {
            int n = snprintf(buf + at, cap - at, "%s'%s' (udp/%d: %s)", at ? ", " : "",
                             o->name, o->bind_port, strerror(mx->bind_errno[i]));
            if (n > 0) at += (size_t)n;
        }
    }
    return count;
}

void obp_mux_stop(obp_mux *mx)
{
    for (int i = 0; i < mx->cfg->n_openbridge; i++)
        if (mx->active[i]) unbind_peer(mx, i);
}

void obp_mux_free(obp_mux *mx)
{
    if (!mx) return;
    free(mx);
}
