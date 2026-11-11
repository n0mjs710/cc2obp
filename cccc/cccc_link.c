/* cccc_link.c — see cccc_link.h.  Implements formal spec §3-§10:
 * handshake (§4), voice RTP (§6), call signaling (§7), keepalive (§8),
 * trial-echo (§9 of the formal spec — link-test diagnostics), teardown
 * (§10).  SSRC dispatch and inbound-match rules per Project Plan §7.1/§9. */
#include "cccc_link.h"
#include "cccc_const.h"
#include "../translate.h"
#include "../net.h"
#include "../log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/random.h>
#include <arpa/inet.h>

#define LOGN "cccc.link"

#define RECONNECT_DELAY_S     5.0
#define PENDING_TIMEOUT_S     5.0
#define MAX_PENDING           32
#define RXBUF_CAP             2048

typedef enum { LST_DOWN, LST_CONNECTING, LST_HANDSHAKING, LST_UP } link_state_t;

typedef struct {
    cccc_mux    *mx;
    int          idx;              /* index into cfg->link[] */
    link_state_t state;
    int          active;           /* outbound: are we supposed to be trying (mirrors lcfg->enabled) */
    int          fd;               /* -1 if none */
    ev_timer    *reconnect_timer;  /* outbound only */
    ev_timer    *keepalive_timer;  /* running once UP */
    uint32_t     sync_source;
    int          has_sync_source;
    double       last_keepalive_recv;

    char         rxbuf[RXBUF_CAP];
    int          rxlen;

    /* outbound handshake: accumulate Answer's 7 fields before validating */
    char         hslines[CCCC_ANSWER_NFIELDS][256];
    int          hsnlines;
} cc_link;

typedef struct {
    cccc_mux *mx;
    int       in_use;
    int       fd;
    char      src_ip[INET_ADDRSTRLEN];
    char      rxbuf[RXBUF_CAP];
    int       rxlen;
    char      qlines[CCCC_QUESTION_NFIELDS][256];
    int       qnlines;
    ev_timer *timeout_timer;
} pending_conn;

struct cccc_mux {
    Config     *cfg;
    struct translator *tr;
    ev_loop    *loop;

    int voice_fd;
    int trial_fd;
    int listen_fd;

    cc_link      links[CFG_MAX_LINKS];
    pending_conn pending[MAX_PENDING];
};

/* ---------------- small helpers ---------------- */

static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0]<<8)|p[1]); }
static void wr32(uint8_t *p, uint32_t v) { p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static void wr16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }

static uint32_t rand32(void)
{
    uint32_t v;
    if (getrandom(&v, sizeof v, 0) != (ssize_t)sizeof v) v = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
    return v;
}

static int find_link_by_ssrc(cccc_mux *mx, uint32_t ssrc)
{
    for (int i = 0; i < mx->cfg->n_link; i++)
        if (mx->links[i].has_sync_source && mx->links[i].sync_source == ssrc)
            return i;
    return -1;
}

/* §7.1: OUTBOUND mints its own SSRC and must not collide with our own
 * currently-active table (pure local bookkeeping). */
static uint32_t mint_sync_source(cccc_mux *mx)
{
    for (;;) {
        uint32_t s = rand32();
        if (find_link_by_ssrc(mx, s) < 0) return s;
    }
}

/* Generic line reassembly across arbitrary recv() boundaries: strips the
 * trailing \n (and \r, if present) and invokes cb once per complete line;
 * partial lines are retained in *rxlen across calls. */
typedef void (*line_cb)(void *ctx, const char *line);

static void feed_bytes(char *rxbuf, int *rxlen, int cap, const uint8_t *data, int len, line_cb cb, void *ctx)
{
    for (int i = 0; i < len; i++) {
        if (*rxlen < cap - 1) rxbuf[(*rxlen)++] = (char)data[i];
        if (data[i] == '\n') {
            int L = *rxlen - 1;
            if (L > 0 && rxbuf[L-1] == '\r') L--;
            rxbuf[L] = 0;
            cb(ctx, rxbuf);
            *rxlen = 0;
        }
    }
}

/* ---------------- Question/Answer builders (§4.1, §4.2) ---------------- */

static int build_question(char *out, size_t cap, uint32_t sync_source, int lid,
                          const char *channel, const char *sitename,
                          const char *mac, const char *coderev, const char *os)
{
    return snprintf(out, cap,
        "%x\n%d \n%s\n%s\n%s\n%s\n%s\n%s\n",
        sync_source, lid, channel, sitename, CCCC_CONNTYPE_SERVER_INBOUND, mac, coderev, os);
}

static int build_answer(char *out, size_t cap, const char *sitename, const char *os, const char *version)
{
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return snprintf(out, cap,
        "%s\n%d\n%ld %ld\n%s\n%s\n0\n%s\n",
        CCCC_CODEC_AMBE, CCCC_MS_PER_FRAME, (long)ts.tv_sec, (long)(ts.tv_nsec/1000),
        version, sitename, os);
}

/* ---------------- B-on/B-off builders (§7.1, §7.2) — probe-validated format ---------------- */

static int build_bon(char *out, size_t cap, int lid, int user, uint32_t radio, uint32_t peer,
                     int src_lid, int tgid, char call_type)
{
    return snprintf(out, cap, "B01%02d%03d %u %u 0.0 radioid=%u peerid=%u Bee=B01%02d%03d%c\n",
                    lid, user, radio, peer, radio, peer, src_lid, tgid, call_type);
}

static int build_boff(char *out, size_t cap, int lid, int lost, int total, double rssi)
{
    return snprintf(out, cap, "B%02d00000  LOSS=%d/%d RSSI=%.0f\n", lid, lost, total, rssi);
}

/* B-on: "B01<LID><user> <radio> <peer> <rssi> radioid=<radio> peerid=<peer>
 *        Bee=B01<srcLID><TGID><type>" (§7.1) */
static int parse_bon(const char *line, uint32_t *radio, uint32_t *peer, int *src_lid, int *tgid, char *call_type)
{
    const char *bee = strstr(line, "Bee=");
    if (!bee) return -1;
    char tok0[64], tok1[32], tok2[32];
    if (sscanf(line, "%63s %31s %31s", tok0, tok1, tok2) != 3) return -1;
    *radio = (uint32_t)strtoul(tok1, NULL, 10);
    *peer  = (uint32_t)strtoul(tok2, NULL, 10);

    const char *p = bee + 4;                  /* skip "Bee=" */
    if (strncmp(p, "B01", 3) != 0) return -1;
    p += 3;
    size_t plen = strlen(p);
    while (plen > 0 && (p[plen-1] == '\r' || p[plen-1] == '\n' || p[plen-1] == ' ')) plen--;
    if (plen < 3) return -1;                  /* need >=2 digit srcLID + 1 char type */
    char lidbuf[3] = { p[0], p[1], 0 };
    *src_lid = atoi(lidbuf);
    *call_type = p[plen - 1];
    char tgbuf[16]; size_t tglen = plen - 3;
    if (tglen >= sizeof tgbuf) tglen = sizeof tgbuf - 1;
    memcpy(tgbuf, p + 2, tglen); tgbuf[tglen] = 0;
    *tgid = atoi(tgbuf);
    return 0;
}

/* B-off: "B<LID>00000  LOSS=<lost>/<total> RSSI=<rssi>" (§7.2) */
static int parse_boff(const char *line, int *lost, int *total)
{
    const char *loss = strstr(line, "LOSS=");
    if (!loss) return -1;
    if (sscanf(loss, "LOSS=%d/%d", lost, total) != 2) return -1;
    return 0;
}

/* ---------------- outbound send primitives ---------------- */

static void udp_send_to_link(cccc_mux *mx, int idx, const void *buf, int len)
{
    const LinkConfig *lcfg = &mx->cfg->link[idx];
    log_wire("cccc.wire", "UDP SEND %s:%d %d %s", lcfg->cc_remote_ip, lcfg->cc_remote_voice_port,
             len, log_hex(buf, len));
    udp_sendto(mx->voice_fd, buf, (size_t)len, lcfg->cc_remote_ip, lcfg->cc_remote_voice_port);
}

/* TCP control-channel send with --wire logging; used for Question, Answer,
 * B-on, and B-off (the only things this program ever writes to a CC-CC
 * connection). */
static void tcp_send(cc_link *lk, const void *buf, int n)
{
    log_wire("cccc.wire", "TCP SEND %s %d %s", lk->mx->cfg->link[lk->idx].cc_remote_ip, n, log_hex(buf, n));
    ssize_t wr = write(lk->fd, buf, (size_t)n);
    (void)wr;
}

static void build_keepalive(uint8_t out[CCCC_KEEPALIVE_LEN], uint32_t ssrc)
{
    out[0] = CCCC_RTP_VPXCC;
    out[1] = CCCC_RTP_PT_KEEPALIVE;
    wr16(out + 2, 0);
    wr32(out + 4, 0);
    wr32(out + 8, ssrc);
    wr32(out + 12, CCCC_KEEPALIVE_PAYLOAD);
}

int cccc_link_is_up(const cccc_mux *mx, int link_idx)
{
    if (link_idx < 0 || link_idx >= mx->cfg->n_link) return 0;
    return mx->links[link_idx].state == LST_UP;
}

void cccc_send_bon(cccc_mux *mx, int link_idx, uint32_t radio_id, uint32_t peer_id,
                   int src_lid, int tgid, char call_type)
{
    cc_link *lk = &mx->links[link_idx];
    if (lk->state != LST_UP) { LOGD(LOGN, "cccc_send_bon: link idx=%d not up, dropped", link_idx); return; }
    const LinkConfig *lcfg = &mx->cfg->link[link_idx];
    static int user_ctr[CFG_MAX_LINKS];
    int user = (user_ctr[link_idx] = (user_ctr[link_idx] + 1) % 1000);
    char buf[256];
    int n = build_bon(buf, sizeof buf, lcfg->cc_lid, user, radio_id, peer_id, src_lid, tgid, call_type);
    tcp_send(lk, buf, n);
    LOGI(LOGN, "link '%s': -> B-on  radio=%u peer=%u src_lid=%d tgid=%d type=%c",
         lcfg->name, radio_id, peer_id, src_lid, tgid, call_type);
}

void cccc_send_boff(cccc_mux *mx, int link_idx, int lost, int total, double rssi)
{
    cc_link *lk = &mx->links[link_idx];
    if (lk->state != LST_UP) { LOGD(LOGN, "cccc_send_boff: link idx=%d not up, dropped", link_idx); return; }
    const LinkConfig *lcfg = &mx->cfg->link[link_idx];
    char buf[256];
    int n = build_boff(buf, sizeof buf, lcfg->cc_lid, lost, total, rssi);
    tcp_send(lk, buf, n);
    LOGI(LOGN, "link '%s': -> B-off  LOSS=%d/%d RSSI=%.0f", lcfg->name, lost, total, rssi);
}

void cccc_send_voice(cccc_mux *mx, int link_idx, uint16_t seq, uint32_t timestamp,
                     int marker, const uint8_t ambe21[21])
{
    cc_link *lk = &mx->links[link_idx];
    if (lk->state != LST_UP) return;
    uint8_t pkt[CCCC_RTP_PKT_LEN];
    pkt[0] = CCCC_RTP_VPXCC;
    pkt[1] = (uint8_t)(CCCC_RTP_PT_VOICE | (marker ? CCCC_RTP_MARKER_BIT : 0));
    wr16(pkt + 2, seq);
    wr32(pkt + 4, timestamp);
    wr32(pkt + 8, lk->sync_source);
    memcpy(pkt + CCCC_RTP_HDR_LEN, ambe21, CCCC_RTP_PAYLOAD_LEN);
    udp_send_to_link(mx, link_idx, pkt, sizeof pkt);
}

/* ---------------- teardown / reconnect ---------------- */

static void schedule_reconnect(cccc_mux *mx, int idx);
static void cccc_start_outbound_connect(cccc_mux *mx, int idx);

static void teardown_link_connection(cccc_mux *mx, int idx, const char *reason)
{
    cc_link *lk = &mx->links[idx];
    const LinkConfig *lcfg = &mx->cfg->link[idx];
    int was_up = (lk->state == LST_UP);

    if (lk->keepalive_timer) { ev_timer_cancel(mx->loop, lk->keepalive_timer); lk->keepalive_timer = NULL; }
    if (lk->fd >= 0) {
        ev_del_fd(mx->loop, lk->fd);
        ev_del_fd_write(mx->loop, lk->fd);
        close(lk->fd);
        lk->fd = -1;
    }
    lk->state = LST_DOWN;
    lk->has_sync_source = 0;
    lk->rxlen = 0;
    lk->hsnlines = 0;

    if (was_up) {
        LOGW(LOGN, "link '%s' down: %s", lcfg->name, reason);
        translator_cccc_link_down(mx->tr, idx);
    } else {
        LOGI(LOGN, "link '%s' connection ended before becoming active: %s", lcfg->name, reason);
    }

    if (lcfg->cc_role == CC_ROLE_OUTBOUND && lk->active)
        schedule_reconnect(mx, idx);
}

static void reconnect_cb(ev_loop *loop, void *ud)
{
    (void)loop;
    cc_link *lk = ud;
    lk->reconnect_timer = NULL;
    if (lk->active) cccc_start_outbound_connect(lk->mx, lk->idx);
}

static void schedule_reconnect(cccc_mux *mx, int idx)
{
    cc_link *lk = &mx->links[idx];
    LOGI(LOGN, "link '%s': reconnecting in %.0fs", mx->cfg->link[idx].name, RECONNECT_DELAY_S);
    lk->reconnect_timer = ev_timer_after(mx->loop, RECONNECT_DELAY_S, reconnect_cb, lk);
}

/* ---------------- keepalive origination + liveness watchdog (§8) ---------------- */

static void keepalive_cb(ev_loop *loop, void *ud)
{
    cc_link *lk = ud;
    cccc_mux *mx = lk->mx;
    lk->keepalive_timer = NULL;
    if (lk->state != LST_UP) return;

    uint8_t ka[CCCC_KEEPALIVE_LEN];
    build_keepalive(ka, lk->sync_source);
    udp_send_to_link(mx, lk->idx, ka, sizeof ka);

    double age = ev_now(loop) - lk->last_keepalive_recv;
    if (age > mx->cfg->cc_link_timeout) {
        teardown_link_connection(mx, lk->idx, "keepalive timeout");
        return;
    }
    lk->keepalive_timer = ev_timer_after(loop, mx->cfg->cc_keepalive_interval, keepalive_cb, lk);
}

static void arm_keepalive(cccc_mux *mx, cc_link *lk)
{
    lk->last_keepalive_recv = ev_now(mx->loop);
    lk->keepalive_timer = ev_timer_after(mx->loop, mx->cfg->cc_keepalive_interval, keepalive_cb, lk);
}

/* ---------------- established-link line dispatch ---------------- */

static void finish_outbound_handshake(cccc_mux *mx, cc_link *lk)
{
    const LinkConfig *lcfg = &mx->cfg->link[lk->idx];
    const char *codec = lk->hslines[0];
    int ms = atoi(lk->hslines[1]);
    lk->hsnlines = 0;

    /* §4.3: only codec/ms are validated; disagreement -> close */
    if (strcmp(codec, CCCC_CODEC_AMBE) != 0 || ms != CCCC_MS_PER_FRAME) {
        LOGE(LOGN, "link '%s': Answer codec/ms mismatch (codec='%s' ms=%d) — closing (§4.3)",
             lcfg->name, codec, ms);
        teardown_link_connection(mx, lk->idx, "Answer validation failed");
        return;
    }
    lk->state = LST_UP;
    arm_keepalive(mx, lk);
    LOGI(LOGN, "link '%s': UP (outbound, sync_source=%08x)", lcfg->name, lk->sync_source);
    translator_cccc_link_up(mx->tr, lk->idx);
}

static void dispatch_established_line(cccc_mux *mx, cc_link *lk, const char *line)
{
    const LinkConfig *lcfg = &mx->cfg->link[lk->idx];
    if (strstr(line, "Bee=")) {
        uint32_t radio, peer; int src_lid, tgid; char calltype;
        if (parse_bon(line, &radio, &peer, &src_lid, &tgid, &calltype) != 0) {
            LOGW(LOGN, "link '%s': malformed B-on line: %s", lcfg->name, line);
            return;
        }
        LOGI(LOGN, "link '%s': <- B-on  radio=%u peer=%u src_lid=%d tgid=%d type=%c",
             lcfg->name, radio, peer, src_lid, tgid, calltype);
        translator_cccc_bon(mx->tr, lk->idx, radio, peer, src_lid, tgid, calltype);
    } else if (strstr(line, "LOSS=")) {
        int lost, total;
        if (parse_boff(line, &lost, &total) != 0) {
            LOGW(LOGN, "link '%s': malformed B-off line: %s", lcfg->name, line);
            return;
        }
        LOGI(LOGN, "link '%s': <- B-off  LOSS=%d/%d", lcfg->name, lost, total);
        translator_cccc_boff(mx->tr, lk->idx, lost, total);
    } else {
        LOGD(LOGN, "link '%s': unrecognized control line: %s", lcfg->name, line);
    }
}

static void link_on_line(void *ctx, const char *line)
{
    cc_link *lk = ctx;
    cccc_mux *mx = lk->mx;
    if (lk->state == LST_HANDSHAKING) {
        if (lk->hsnlines < CCCC_ANSWER_NFIELDS) {
            snprintf(lk->hslines[lk->hsnlines], sizeof lk->hslines[0], "%.255s", line);
            lk->hsnlines++;
        }
        if (lk->hsnlines == CCCC_ANSWER_NFIELDS)
            finish_outbound_handshake(mx, lk);
    } else if (lk->state == LST_UP) {
        dispatch_established_line(mx, lk, line);
    }
    /* LST_DOWN/LST_CONNECTING: stray bytes on a socket we no longer own — ignore */
}

static void on_link_tcp_readable(ev_loop *loop, int fd, void *ud)
{
    (void)loop;
    cc_link *lk = ud;
    uint8_t buf[1024];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
            teardown_link_connection(lk->mx, lk->idx, n == 0 ? "peer closed (FIN)" : "recv error");
        return;
    }
    log_wire("cccc.wire", "TCP RECV %s %zd %s", lk->mx->cfg->link[lk->idx].cc_remote_ip, n, log_hex(buf, (int)n));
    feed_bytes(lk->rxbuf, &lk->rxlen, RXBUF_CAP, buf, (int)n, link_on_line, lk);
}

/* ---------------- outbound connect ---------------- */

static void on_connect_writable(ev_loop *loop, int fd, void *ud)
{
    cc_link *lk = ud;
    cccc_mux *mx = lk->mx;
    const LinkConfig *lcfg = &mx->cfg->link[lk->idx];
    ev_del_fd_write(loop, fd);

    int sockerr = 0;
    if (tcp_connect_finish(fd, &sockerr) != 0) {
        LOGW(LOGN, "link '%s': connect to %s:%d failed (errno=%d)",
             lcfg->name, lcfg->cc_remote_ip, lcfg->cc_remote_port, sockerr);
        close(fd);
        lk->fd = -1;
        lk->state = LST_DOWN;
        if (lk->active) schedule_reconnect(mx, lk->idx);
        return;
    }

    lk->state = LST_HANDSHAKING;
    lk->sync_source = mint_sync_source(mx);
    /* Register provisionally so §7.1's global collision table sees this
     * connection's SSRC even before the Answer confirms the link is UP. */
    lk->has_sync_source = 1;
    ev_add_fd(loop, fd, on_link_tcp_readable, lk);

    char q[512];
    int n = build_question(q, sizeof q, lk->sync_source, lcfg->cc_lid, lcfg->cc_channel_name,
                           mx->cfg->cc_site_name, mx->cfg->cc_mac_address,
                           mx->cfg->cc_code_revision, mx->cfg->cc_os_version);
    tcp_send(lk, q, n);
    LOGI(LOGN, "link '%s': -> Question  lid=%d sync_source=%08x", lcfg->name, lcfg->cc_lid, lk->sync_source);
}

static void cccc_start_outbound_connect(cccc_mux *mx, int idx)
{
    cc_link *lk = &mx->links[idx];
    const LinkConfig *lcfg = &mx->cfg->link[idx];

    lk->rxlen = 0;
    lk->hsnlines = 0;
    lk->has_sync_source = 0;

    lk->fd = tcp_connect_start(lcfg->cc_remote_ip, lcfg->cc_remote_port);
    if (lk->fd < 0) {
        LOGW(LOGN, "link '%s': failed to start connect to %s:%d",
             lcfg->name, lcfg->cc_remote_ip, lcfg->cc_remote_port);
        if (lk->active) schedule_reconnect(mx, idx);
        return;
    }
    lk->state = LST_CONNECTING;
    ev_add_fd_write(mx->loop, lk->fd, on_connect_writable, lk);
}

/* ---------------- inbound: shared TCP 42421 listener + pending table ---------------- */

static void free_pending(cccc_mux *mx, pending_conn *p, int also_close)
{
    if (p->timeout_timer) { ev_timer_cancel(mx->loop, p->timeout_timer); p->timeout_timer = NULL; }
    if (also_close && p->fd >= 0) { ev_del_fd(mx->loop, p->fd); close(p->fd); }
    p->in_use = 0;
    p->fd = -1;
}

static void pending_timeout_cb(ev_loop *loop, void *ud)
{
    (void)loop;
    pending_conn *p = ud;
    p->timeout_timer = NULL;
    LOGW(LOGN, "inbound connection from %s timed out before completing the Question", p->src_ip);
    free_pending(p->mx, p, 1);
}

static void handle_question_complete(cccc_mux *mx, pending_conn *p)
{
    if (p->timeout_timer) { ev_timer_cancel(mx->loop, p->timeout_timer); p->timeout_timer = NULL; }

    uint32_t sync_source = (uint32_t)strtoul(p->qlines[0], NULL, 16);
    int lid = atoi(p->qlines[1]);

    int matched = -1;
    for (int i = 0; i < mx->cfg->n_link; i++) {
        const LinkConfig *lcfg = &mx->cfg->link[i];
        if (!lcfg->vacant && lcfg->cc_role == CC_ROLE_INBOUND && lcfg->enabled &&
            !strcmp(lcfg->cc_remote_ip, p->src_ip) && lcfg->cc_lid == lid) {
            matched = i;
            break;
        }
    }
    if (matched < 0) {
        LOGW(LOGN, "inbound Question from %s LID %d: no matching enabled [[link]] — closing (§9)",
             p->src_ip, lid);
        free_pending(mx, p, 1);
        return;
    }

    /* §7.1 INBOUND SSRC collision policy: refuse (no Answer), close. The
     * remote's own reconnect logic will retry with a fresh sync source. */
    int collider = find_link_by_ssrc(mx, sync_source);
    if (collider >= 0 && collider != matched) {
        LOGW(LOGN, "inbound Question from %s LID %d: sync_source %08x collides with active link '%s' "
             "— refusing (no Answer), closing (§7.1)",
             p->src_ip, lid, sync_source, mx->cfg->link[collider].name);
        free_pending(mx, p, 1);
        return;
    }

    const LinkConfig *lcfg = &mx->cfg->link[matched];
    cc_link *lk = &mx->links[matched];
    if (lk->state != LST_DOWN)
        teardown_link_connection(mx, matched, "replaced by new inbound connection (reconnect)");

    lk->fd = p->fd;
    lk->rxlen = 0;
    lk->hsnlines = 0;
    lk->sync_source = sync_source;
    lk->has_sync_source = 1;
    lk->state = LST_UP;
    ev_add_fd(mx->loop, lk->fd, on_link_tcp_readable, lk);

    char ans[512];
    int n = build_answer(ans, sizeof ans, mx->cfg->cc_site_name, mx->cfg->cc_os_version, mx->cfg->cc_version);
    tcp_send(lk, ans, n);

    arm_keepalive(mx, lk);
    LOGI(LOGN, "link '%s': UP (inbound from %s, lid=%d, sync_source=%08x)",
         lcfg->name, p->src_ip, lid, sync_source);

    p->fd = -1;   /* ownership moved to lk->fd; do not close on free */
    free_pending(mx, p, 0);

    translator_cccc_link_up(mx->tr, matched);
}

static void pending_on_line(void *ctx, const char *line)
{
    pending_conn *p = ctx;
    if (p->qnlines < CCCC_QUESTION_NFIELDS) {
        snprintf(p->qlines[p->qnlines], sizeof p->qlines[0], "%.255s", line);
        p->qnlines++;
    }
    if (p->qnlines == CCCC_QUESTION_NFIELDS)
        handle_question_complete(p->mx, p);
}

static void on_pending_readable(ev_loop *loop, int fd, void *ud)
{
    (void)loop;
    pending_conn *p = ud;
    uint8_t buf[1024];
    ssize_t n = recv(fd, buf, sizeof buf, 0);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
            free_pending(p->mx, p, 1);
        return;
    }
    log_wire("cccc.wire", "TCP RECV %s %zd %s", p->src_ip, n, log_hex(buf, (int)n));
    feed_bytes(p->rxbuf, &p->rxlen, RXBUF_CAP, buf, (int)n, pending_on_line, p);
}

static void on_listen_readable(ev_loop *loop, int fd, void *ud)
{
    cccc_mux *mx = ud;
    for (;;) {
        char ip[INET_ADDRSTRLEN]; int port;
        int cfd = tcp_accept(fd, ip, &port);
        if (cfd < 0) break;

        int slot = -1;
        for (int i = 0; i < MAX_PENDING; i++) if (!mx->pending[i].in_use) { slot = i; break; }
        if (slot < 0) {
            LOGW(LOGN, "inbound pending table full — rejecting connection from %s", ip);
            close(cfd);
            continue;
        }
        pending_conn *p = &mx->pending[slot];
        memset(p, 0, sizeof *p);
        p->mx = mx; p->in_use = 1; p->fd = cfd;
        snprintf(p->src_ip, sizeof p->src_ip, "%s", ip);
        ev_add_fd(loop, cfd, on_pending_readable, p);
        p->timeout_timer = ev_timer_after(loop, PENDING_TIMEOUT_S, pending_timeout_cb, p);
        LOGD(LOGN, "TCP accept from %s:%d — awaiting Question", ip, port);
    }
}

/* ---------------- shared UDP 42422 (voice + keepalive, §6, §8) ---------------- */

static void on_voice_readable(ev_loop *loop, int fd, void *ud)
{
    (void)loop;
    cccc_mux *mx = ud;
    uint8_t buf[256];
    char src_ip[INET_ADDRSTRLEN]; int src_port;
    int n = udp_recvfrom(fd, buf, sizeof buf, src_ip, &src_port);
    if (n < 2) return;
    log_wire("cccc.wire", "UDP RECV %s:%d %d %s", src_ip, src_port, n, log_hex(buf, n));

    int pt = buf[1] & 0x7F;
    int marker = (buf[1] & 0x80) != 0;

    if (n == CCCC_KEEPALIVE_LEN && pt == CCCC_RTP_PT_KEEPALIVE) {
        uint32_t ssrc = rd32(buf + 8);
        int idx = find_link_by_ssrc(mx, ssrc);
        if (idx < 0) { LOGD(LOGN, "keepalive: unknown ssrc %08x from %s — dropped", ssrc, src_ip); return; }
        const LinkConfig *lcfg = &mx->cfg->link[idx];
        if (strcmp(src_ip, lcfg->cc_remote_ip) != 0) {
            LOGW(LOGN, "link '%s': keepalive source %s does not match configured cc_remote_ip %s — dropped",
                 lcfg->name, src_ip, lcfg->cc_remote_ip);
            return;
        }
        mx->links[idx].last_keepalive_recv = ev_now(mx->loop);
        /* §8: reflect received keepalives, in addition to our own periodic origination */
        log_wire("cccc.wire", "UDP SEND %s:%d %d %s (keepalive reflect)", src_ip, src_port, n, log_hex(buf, n));
        udp_sendto(fd, buf, (size_t)n, src_ip, src_port);
        return;
    }

    if (n == CCCC_RTP_PKT_LEN && pt == CCCC_RTP_PT_VOICE) {
        uint32_t ssrc = rd32(buf + 8);
        int idx = find_link_by_ssrc(mx, ssrc);
        if (idx < 0) { LOGD(LOGN, "voice: unknown ssrc %08x from %s — dropped", ssrc, src_ip); return; }
        const LinkConfig *lcfg = &mx->cfg->link[idx];
        if (strcmp(src_ip, lcfg->cc_remote_ip) != 0) {
            LOGW(LOGN, "link '%s': voice source %s does not match configured cc_remote_ip %s — dropped",
                 lcfg->name, src_ip, lcfg->cc_remote_ip);
            return;
        }
        uint16_t seq = rd16(buf + 2);
        uint32_t ts  = rd32(buf + 4);
        translator_cccc_voice(mx->tr, idx, seq, ts, marker, buf + CCCC_RTP_HDR_LEN);
        return;
    }

    LOGD(LOGN, "UDP 42422: unrecognized packet from %s (len=%d pt=%d) — dropped", src_ip, n, pt);
}

/* ---------------- shared UDP 42420 trial-echo (§9 of formal spec) — stateless ---------------- */

static void on_trial_readable(ev_loop *loop, int fd, void *ud)
{
    (void)loop; (void)ud;
    uint8_t buf[2048];
    char src_ip[INET_ADDRSTRLEN]; int src_port;
    int n = udp_recvfrom(fd, buf, sizeof buf, src_ip, &src_port);
    if (n <= 0) return;
    log_wire("cccc.wire", "UDP 42420 TRIAL %s:%d %d %s (reflected)", src_ip, src_port, n, log_hex(buf, n));
    udp_sendto(fd, buf, (size_t)n, src_ip, src_port);
}

/* ---------------- lifecycle ---------------- */

cccc_mux *cccc_mux_new(Config *cfg, struct translator *tr, ev_loop *loop)
{
    cccc_mux *mx = calloc(1, sizeof *mx);
    mx->cfg = cfg; mx->tr = tr; mx->loop = loop;
    mx->voice_fd = mx->trial_fd = mx->listen_fd = -1;
    for (int i = 0; i < CFG_MAX_LINKS; i++) {
        mx->links[i].mx = mx;
        mx->links[i].idx = i;
        mx->links[i].fd = -1;
        mx->links[i].state = LST_DOWN;
    }
    return mx;
}

int cccc_mux_start(cccc_mux *mx)
{
    mx->voice_fd = udp_bind("0.0.0.0", CCCC_VOICE_PORT);
    if (mx->voice_fd < 0) { LOGE(LOGN, "failed to bind UDP %d (voice)", CCCC_VOICE_PORT); return -1; }
    ev_add_fd(mx->loop, mx->voice_fd, on_voice_readable, mx);

    mx->trial_fd = udp_bind("0.0.0.0", CCCC_TRIAL_PORT);
    if (mx->trial_fd < 0) { LOGE(LOGN, "failed to bind UDP %d (trial-echo)", CCCC_TRIAL_PORT); return -1; }
    ev_add_fd(mx->loop, mx->trial_fd, on_trial_readable, mx);

    mx->listen_fd = tcp_listen("0.0.0.0", CCCC_CONTROL_PORT);
    if (mx->listen_fd < 0) { LOGE(LOGN, "failed to listen on TCP %d (control)", CCCC_CONTROL_PORT); return -1; }
    ev_add_fd(mx->loop, mx->listen_fd, on_listen_readable, mx);

    LOGI(LOGN, "CC-CC sockets up — voice/keepalive udp/%d, trial-echo udp/%d, control tcp/%d",
         CCCC_VOICE_PORT, CCCC_TRIAL_PORT, CCCC_CONTROL_PORT);

    for (int i = 0; i < mx->cfg->n_link; i++) {
        const LinkConfig *lcfg = &mx->cfg->link[i];
        mx->links[i].active = lcfg->enabled;
        if (lcfg->cc_role == CC_ROLE_OUTBOUND && lcfg->enabled)
            cccc_start_outbound_connect(mx, i);
    }
    return 0;
}

void cccc_mux_retire_link(cccc_mux *mx, int link_idx)
{
    cc_link *lk = &mx->links[link_idx];
    lk->active = 0;   /* before teardown, so it does not schedule a reconnect */
    if (lk->reconnect_timer) { ev_timer_cancel(mx->loop, lk->reconnect_timer); lk->reconnect_timer = NULL; }
    if (lk->state != LST_DOWN) teardown_link_connection(mx, link_idx, "changed or removed via config reload");
}

void cccc_mux_reconcile(cccc_mux *mx)
{
    for (int i = 0; i < mx->cfg->n_link; i++) {
        const LinkConfig *lcfg = &mx->cfg->link[i];
        cc_link *lk = &mx->links[i];
        if (lcfg->vacant) continue;
        if (lcfg->cc_role == CC_ROLE_OUTBOUND) {
            if (lcfg->enabled && !lk->active) {
                lk->active = 1;
                cccc_start_outbound_connect(mx, i);
            } else if (!lcfg->enabled && lk->active) {
                lk->active = 0;
                if (lk->reconnect_timer) { ev_timer_cancel(mx->loop, lk->reconnect_timer); lk->reconnect_timer = NULL; }
                if (lk->state != LST_DOWN) teardown_link_connection(mx, i, "disabled via config reload");
            }
        } else {
            lk->active = lcfg->enabled;
            if (!lcfg->enabled && lk->state != LST_DOWN)
                teardown_link_connection(mx, i, "disabled via config reload");
        }
    }
}

void cccc_mux_stop(cccc_mux *mx)
{
    for (int i = 0; i < mx->cfg->n_link; i++) {
        cc_link *lk = &mx->links[i];
        lk->active = 0;
        if (lk->reconnect_timer) { ev_timer_cancel(mx->loop, lk->reconnect_timer); lk->reconnect_timer = NULL; }
        if (lk->state != LST_DOWN) teardown_link_connection(mx, i, "shutdown");
    }
    for (int i = 0; i < MAX_PENDING; i++)
        if (mx->pending[i].in_use) free_pending(mx, &mx->pending[i], 1);
    if (mx->voice_fd >= 0)  { ev_del_fd(mx->loop, mx->voice_fd);  close(mx->voice_fd);  mx->voice_fd = -1; }
    if (mx->trial_fd >= 0)  { ev_del_fd(mx->loop, mx->trial_fd);  close(mx->trial_fd);  mx->trial_fd = -1; }
    if (mx->listen_fd >= 0) { ev_del_fd(mx->loop, mx->listen_fd); close(mx->listen_fd); mx->listen_fd = -1; }
}

void cccc_mux_free(cccc_mux *mx)
{
    if (!mx) return;
    free(mx);
}
