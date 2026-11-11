/* test_reload.c — SIGHUP reload (§6.3) touches only what changed, as a real
 * system test against the compiled cc2obp binary (fork/exec + loopback
 * sockets), in the style of test_obp_scenarios.c: this test plays the
 * CC-CC remotes (inbound-role links, so it only ever connects out to
 * cc2obp's TCP 42421) and one OpenBridge peer (raw UDP + HMAC-SHA1).
 *
 * Each step rewrites the config, sends SIGHUP and checks the wire:
 *   1. one link changed, one removed, one added, one untouched: the changed
 *      and removed links' connections are closed, the untouched link's
 *      connection stays open and keeps bridging, the changed link accepts
 *      its new identity and refuses the old one, the added link comes up;
 *   2. the OpenBridge peer's bind_port changes: only its socket moves, the
 *      untouched link stays up and bridges on the new port;
 *   3. enabled = false on one link: only that link drops; a link added
 *      when no slot is free is appended and comes up;
 *   4. a [global] change, then an unparseable file, then an entry with an
 *      empty name: nothing drops, the running config keeps working. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

#include "../dmr/dmr.h"
#include "../crypto.h"
#include "../openbridge/obp_const.h"

#define FAKE_PEER_PORT  63101   /* this test's own OpenBridge socket (== peer_port in config) */
#define BIND_PORT_1     63102   /* cc2obp's OpenBridge socket before step 2 */
#define BIND_PORT_2     63103   /* ... and after */
#define VOICE_TEST_PORT 43101   /* this test's CC-CC voice receiver (== cc_remote_voice_port) */
#define PASSPHRASE      "test-passphrase"
#define CFG_PATH        "/tmp/cc2obp_test_reload.toml"

#define LID_KEEP        61      /* link "keep",   tgid 1: never changes */
#define LID_CHANGE_OLD  62      /* link "change", tgid 2: its LID moves 62 -> 65 in step 1 */
#define LID_CHANGE_NEW  65
#define LID_REMOVE      63      /* link "remove", tgid 3: gone in step 1 */
#define LID_ADD         64      /* link "add",    tgid 4: new in step 1 (takes "remove"'s slot), disabled in step 3 */
#define LID_EXTRA       66      /* link "extra",  tgid 5: new in step 3 (no free slot: appended) */

static int fails = 0, checks = 0;
static void check(const char *what, int cond)
{
    checks++;
    if (!cond) { fails++; fprintf(stderr, "FAIL: %s\n", what); }
    else fprintf(stderr, "ok:   %s\n", what);
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* ---------------- config ---------------- */

typedef struct {
    int bind_port;
    int change_lid;
    int with_remove, with_add, add_enabled, with_extra;
    const char *site_name;
} cfg_spec;

static void write_link(FILE *f, const char *name, int enabled, int tgid, int lid)
{
    fprintf(f,
        "[[link]]\n"
        "name = \"%s\"\nenabled = %s\ncross_connect_active = true\n"
        "tgid = %d\nopenbridge_system = \"fakepeer\"\ncc_role = \"inbound\"\n"
        "cc_lid = %d\ncc_remote_ip = \"127.0.0.1\"\ncc_remote_voice_port = %d\n\n",
        name, enabled ? "true" : "false", tgid, lid, VOICE_TEST_PORT);
}

static void write_config(const cfg_spec *c)
{
    FILE *f = fopen(CFG_PATH, "w");
    if (!f) { perror("fopen"); exit(2); }
    fprintf(f,
        "[global]\nlog_level = \"DEBUG\"\ncc_site_name = \"%s\"\n\n"
        "[[openbridge]]\n"
        "name = \"fakepeer\"\nenabled = true\n"
        "peer_ip = \"127.0.0.1\"\npeer_port = %d\nbind_port = %d\n"
        "network_id = 3129999\npassphrase = \"%s\"\n\n",
        c->site_name, FAKE_PEER_PORT, c->bind_port, PASSPHRASE);
    write_link(f, "keep", 1, 1, LID_KEEP);
    write_link(f, "change", 1, 2, c->change_lid);
    if (c->with_remove) write_link(f, "remove", 1, 3, LID_REMOVE);
    if (c->with_add)    write_link(f, "add", c->add_enabled, 4, LID_ADD);
    if (c->with_extra)  write_link(f, "extra", 1, 5, LID_EXTRA);
    fclose(f);
}

/* ---------------- sockets ---------------- */

static int udp_bind_local(int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

static int tcp_connect_retry(int port)
{
    for (int i = 0; i < 40; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) return fd;
        close(fd);
        sleep_ms(50);
    }
    return -1;
}

typedef struct { int fd; char buf[2048]; int len; } tcp_reader;

/* 1 = line read, 0 = timeout, -1 = EOF/error */
static int tcp_read_line(tcp_reader *r, char *line, size_t cap, int timeout_ms)
{
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }

    for (;;) {
        for (int i = 0; i < r->len; i++) {
            if (r->buf[i] == '\n') {
                int n = i; if (n > 0 && r->buf[n-1] == '\r') n--;
                if ((size_t)n >= cap) n = (int)cap - 1;
                memcpy(line, r->buf, (size_t)n); line[n] = 0;
                memmove(r->buf, r->buf + i + 1, (size_t)(r->len - i - 1));
                r->len -= i + 1;
                return 1;
            }
        }
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        double remain = (double)(deadline.tv_sec - now.tv_sec) + (double)(deadline.tv_nsec - now.tv_nsec) / 1e9;
        if (remain <= 0) return 0;

        fd_set rfds; FD_ZERO(&rfds); FD_SET(r->fd, &rfds);
        struct timeval tv = { (long)remain, (long)((remain - (long)remain) * 1e6) };
        int sr = select(r->fd + 1, &rfds, NULL, NULL, &tv);
        if (sr <= 0) return 0;
        ssize_t n = read(r->fd, r->buf + r->len, sizeof r->buf - (size_t)r->len);
        if (n <= 0) return -1;
        r->len += (int)n;
    }
}

/* Wait for the far end to close the connection; any line read meanwhile is
 * discarded.  1 = closed (r->fd released), 0 = still open after timeout_ms. */
static int wait_closed(tcp_reader *r, int timeout_ms)
{
    char line[512];
    if (r->fd < 0) return 1;
    for (int waited = 0; waited < timeout_ms; waited += 250) {
        if (tcp_read_line(r, line, sizeof line, 250) < 0) {
            close(r->fd); r->fd = -1;
            return 1;
        }
    }
    return 0;
}

/* ---------------- CC-CC side: an inbound-role remote ---------------- */

/* Connect, send a Question for lid, read the 7-field Answer.
 * 1 = link up (r->fd open), 0 = refused (cc2obp closed the connection),
 * -1 = no answer and not closed either (r->fd released in both failure cases). */
static int cc_connect(tcp_reader *r, uint32_t sync_source, int lid)
{
    r->len = 0;
    r->fd = tcp_connect_retry(42421);
    if (r->fd < 0) return 0;
    char q[512];
    int n = snprintf(q, sizeof q, "%x\n%d \ntest-channel\ntest-site\nServer Inbound\nDEADBEEF0002\n9999\nLinux test\n",
                     sync_source, lid);
    ssize_t wr = write(r->fd, q, (size_t)n);
    (void)wr;
    char line[512];
    for (int i = 0; i < 7; i++) {
        int got = tcp_read_line(r, line, sizeof line, 2000);
        if (got != 1) { close(r->fd); r->fd = -1; return got < 0 ? 0 : -1; }
    }
    return 1;
}

/* ---------------- OpenBridge side: one call on tgid (mirrors translate.c) ---------------- */

static void wr24(uint8_t *p, uint32_t v) { p[0]=(uint8_t)(v>>16); p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)v; }

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

static void send_head_or_term(int fd, int to_port, uint32_t tgid, uint32_t rf_src, const uint8_t stream[4], int is_term)
{
    uint8_t lc[9];
    lc[0]=DMR_LC_OPT[0]; lc[1]=DMR_LC_OPT[1]; lc[2]=DMR_LC_OPT[2];
    wr24(lc+3, tgid);
    wr24(lc+6, rf_src);
    uint8_t payload33[33];
    build_head_term_payload(lc, is_term, payload33);

    uint8_t pkt[OBP_DMRD_PKT_LEN];
    memset(pkt, 0, sizeof pkt);
    memcpy(pkt, "DMRD", 4);
    wr24(pkt + OBP_SRC_OFF, rf_src);
    wr24(pkt + OBP_DST_OFF, tgid);
    pkt[OBP_FLAGS_OFF] = (uint8_t)(OBPF_FRAMETYPE_DATASYNC | (is_term ? OBPF_SLT_VTERM : OBPF_SLT_VHEAD));
    memcpy(pkt + OBP_STREAM_OFF, stream, 4);
    memcpy(pkt + OBP_PAYLOAD_OFF, payload33, 33);
    hmac_sha1((const uint8_t *)PASSPHRASE, strlen(PASSPHRASE), pkt, OBP_DMRD_BODY_LEN, pkt + OBP_DMRD_BODY_LEN);

    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)to_port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    ssize_t wr = sendto(fd, pkt, sizeof pkt, 0, (struct sockaddr *)&a, sizeof a);
    (void)wr;
}

/* A short call from the OpenBridge side on tgid: 1 if the link's CC-CC
 * connection saw both its B-on and its B-off. */
static int call_bridges(int peer_fd, int to_port, uint32_t tgid, tcp_reader *link)
{
    static uint8_t next_stream = 0x10;
    uint8_t stream[4] = { next_stream, next_stream, next_stream, next_stream };
    next_stream++;
    char line[512];
    send_head_or_term(peer_fd, to_port, tgid, 2001, stream, 0);
    int bon = tcp_read_line(link, line, sizeof line, 2000) == 1 && strstr(line, "Bee=");
    send_head_or_term(peer_fd, to_port, tgid, 2001, stream, 1);
    int boff = tcp_read_line(link, line, sizeof line, 2000) == 1 && strstr(line, "LOSS=");
    return bon && boff;
}

/* ---------------- test ---------------- */

static pid_t g_pid;

/* The reload runs on cc2obp's 1 s tick: give it two ticks to land. */
static void reload(const cfg_spec *c)
{
    write_config(c);
    kill(g_pid, SIGHUP);
    sleep_ms(2200);
}

int main(void)
{
    cfg_spec c = { BIND_PORT_1, LID_CHANGE_OLD, 1, 0, 1, 0, "cc2obp" };
    write_config(&c);

    g_pid = fork();
    if (g_pid < 0) { perror("fork"); return 2; }
    if (g_pid == 0) {
        execl("./cc2obp", "cc2obp", "-c", CFG_PATH, "--log-level", "DEBUG", (char *)NULL);
        perror("execl"); _exit(127);
    }

    int peer_fd = udp_bind_local(FAKE_PEER_PORT);
    check("fake OpenBridge peer bound", peer_fd >= 0);
    int voice_fd = udp_bind_local(VOICE_TEST_PORT);
    check("fake CC-CC voice receiver bound", voice_fd >= 0);

    tcp_reader keep = {0}, change = {0}, removed = {0}, added = {0}, old_id = {0}, extra = {0};
    check("link 'keep' up",   cc_connect(&keep,    0x11110001, LID_KEEP) == 1);
    check("link 'change' up", cc_connect(&change,  0x11110002, LID_CHANGE_OLD) == 1);
    check("link 'remove' up", cc_connect(&removed, 0x11110003, LID_REMOVE) == 1);
    check("'keep' bridges a call before any reload", call_bridges(peer_fd, BIND_PORT_1, 1, &keep));

    /* ---- step 1: change one link, remove one, add one ---- */
    c.change_lid = LID_CHANGE_NEW; c.with_remove = 0; c.with_add = 1;
    reload(&c);
    check("step 1: changed link's connection closed", wait_closed(&change, 2000));
    check("step 1: removed link's connection closed", wait_closed(&removed, 2000));
    check("step 1: untouched link's connection still open", !wait_closed(&keep, 500));
    check("step 1: untouched link still bridges", call_bridges(peer_fd, BIND_PORT_1, 1, &keep));
    check("step 1: changed link refuses its old LID", cc_connect(&old_id, 0x11110004, LID_CHANGE_OLD) == 0);
    check("step 1: changed link accepts its new LID", cc_connect(&change, 0x11110005, LID_CHANGE_NEW) == 1);
    check("step 1: changed link bridges on its tgid", call_bridges(peer_fd, BIND_PORT_1, 2, &change));
    check("step 1: added link comes up", cc_connect(&added, 0x11110006, LID_ADD) == 1);
    check("step 1: added link bridges on its tgid", call_bridges(peer_fd, BIND_PORT_1, 4, &added));
    check("step 1: removed link's LID is refused", cc_connect(&removed, 0x11110007, LID_REMOVE) == 0);

    /* ---- step 2: move the OpenBridge peer's local port ---- */
    c.bind_port = BIND_PORT_2;
    reload(&c);
    check("step 2: untouched link's connection still open", !wait_closed(&keep, 500));
    check("step 2: peer change did not drop the other links", !wait_closed(&change, 250) && !wait_closed(&added, 250));
    check("step 2: untouched link bridges via the new bind_port", call_bridges(peer_fd, BIND_PORT_2, 1, &keep));

    /* ---- step 3: disable one link, add another ---- */
    c.add_enabled = 0; c.with_extra = 1;
    reload(&c);
    check("step 3: disabled link's connection closed", wait_closed(&added, 2000));
    check("step 3: appended link comes up", cc_connect(&extra, 0x11110008, LID_EXTRA) == 1);
    check("step 3: appended link bridges on its tgid", call_bridges(peer_fd, BIND_PORT_2, 5, &extra));
    check("step 3: untouched link's connection still open", !wait_closed(&keep, 500));
    check("step 3: untouched link still bridges", call_bridges(peer_fd, BIND_PORT_2, 1, &keep));

    /* ---- step 4: [global] change, then a broken file ---- */
    c.site_name = "renamed";
    reload(&c);
    check("step 4: [global] change dropped nothing", !wait_closed(&keep, 500) && !wait_closed(&change, 250));
    FILE *f = fopen(CFG_PATH, "w");
    if (f) { fputs("[[link]]\nname = \"broken\nthis is not toml\n", f); fclose(f); }
    kill(g_pid, SIGHUP);
    sleep_ms(2200);
    check("step 4: unparseable file dropped nothing", !wait_closed(&keep, 500) && !wait_closed(&change, 250));
    write_config(&c);
    f = fopen(CFG_PATH, "a");   /* valid TOML, but an entry with an empty name fails validation */
    if (f) { fputs("[[link]]\nname = \"\"\ntgid = 9\nopenbridge_system = \"fakepeer\"\ncc_role = \"inbound\"\n"
                   "cc_lid = 69\ncc_remote_ip = \"127.0.0.1\"\ncc_remote_voice_port = 43101\n", f); fclose(f); }
    kill(g_pid, SIGHUP);
    sleep_ms(2200);
    check("step 4: empty entry name refused, nothing dropped", !wait_closed(&keep, 500) && !wait_closed(&change, 250));
    check("step 4: the refused entry never came up", cc_connect(&old_id, 0x11110009, 69) == 0);
    check("step 4: running config still bridges", call_bridges(peer_fd, BIND_PORT_2, 1, &keep));

    if (keep.fd >= 0) close(keep.fd);
    if (change.fd >= 0) close(change.fd);
    if (extra.fd >= 0) close(extra.fd);
    if (peer_fd >= 0) close(peer_fd);
    if (voice_fd >= 0) close(voice_fd);

    kill(g_pid, SIGTERM);
    int status; waitpid(g_pid, &status, 0);
    unlink(CFG_PATH);

    printf("reload self-test: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
