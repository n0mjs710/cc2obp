/* test_obp_seq.c — the DMRD sequence number cc2obp sends to an OpenBridge
 * peer is per call: it starts at 0 on each call's VOICE_HEAD and steps by 1
 * through that call's voice bursts and VOICE_TERM, even when two links carry
 * calls to the same peer at the same time.  FreeDMR and ADN check loss per
 * stream, so a counter shared by every call on the peer reads as missed
 * packets on both calls whenever two of them overlap.
 *
 * A real system test against the compiled cc2obp binary (fork/exec + loopback
 * sockets), in the style of test_reload.c: this test plays two CC-CC remotes
 * (inbound-role links) and one OpenBridge peer (raw UDP).
 *
 *   1. a call on link 'a', then a call on link 'b' while 'a' is still up,
 *      their voice interleaved: each call's DMRDs number 0, 1, 2, ... with no
 *      gap, and every burst arrives;
 *   2. a second call on link 'a': its numbering starts again at 0. */
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
#include <fcntl.h>
#include <time.h>

#include "../openbridge/obp_const.h"
#include "../cccc/cccc_const.h"

#define FAKE_PEER_PORT  63201   /* this test's own OpenBridge socket (== peer_port in config) */
#define BIND_PORT       63202   /* cc2obp's OpenBridge socket */
#define VOICE_TEST_PORT 43201   /* this test's CC-CC voice receiver (== cc_remote_voice_port) */
#define CFG_PATH        "/tmp/cc2obp_test_obp_seq.toml"
#define LOG_PATH        "/tmp/cc2obp_test_obp_seq.log"

#define LID_A           71      /* link "a", tgid 1 */
#define LID_B           72      /* link "b", tgid 2 */
#define SSRC_A          0x22220001
#define SSRC_B          0x22220002
#define BURSTS          12      /* voice packets per call */

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

static void write_config(void)
{
    FILE *f = fopen(CFG_PATH, "w");
    if (!f) { perror("fopen"); exit(2); }
    fprintf(f,
        "[global]\nlog_level = \"DEBUG\"\n\n"
        "[[openbridge]]\n"
        "name = \"fakepeer\"\nenabled = true\n"
        "peer_ip = \"127.0.0.1\"\npeer_port = %d\nbind_port = %d\n"
        "network_id = 3129999\npassphrase = \"x\"\n\n",
        FAKE_PEER_PORT, BIND_PORT);
    for (int i = 0; i < 2; i++)
        fprintf(f,
            "[[link]]\n"
            "name = \"%s\"\nenabled = true\ncross_connect_active = true\n"
            "tgid = %d\nopenbridge_system = \"fakepeer\"\ncc_role = \"inbound\"\n"
            "cc_lid = %d\ncc_remote_ip = \"127.0.0.1\"\ncc_remote_voice_port = %d\n\n",
            i ? "b" : "a", i + 1, i ? LID_B : LID_A, VOICE_TEST_PORT);
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

/* 1 if a full line arrived within timeout_ms (the Answer's lines are read and discarded). */
static int read_line(int fd, int timeout_ms)
{
    char c;
    for (;;) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) return 0;
        if (read(fd, &c, 1) != 1) return 0;
        if (c == '\n') return 1;
    }
}

/* ---------------- CC-CC side: an inbound-role remote ---------------- */

/* Connect, send a Question for lid, read the 7-field Answer: fd if the link is up, else -1. */
static int cc_connect(uint32_t sync_source, int lid)
{
    int fd = tcp_connect_retry(42421);
    if (fd < 0) return -1;
    char q[512];
    int n = snprintf(q, sizeof q, "%x\n%d \ntest-channel\ntest-site\nServer Inbound\nDEADBEEF0003\n9999\nLinux test\n",
                     sync_source, lid);
    ssize_t wr = write(fd, q, (size_t)n);
    (void)wr;
    for (int i = 0; i < 7; i++)
        if (!read_line(fd, 2000)) { close(fd); return -1; }
    return fd;
}

static void send_line(int fd, const char *l)
{
    ssize_t wr = write(fd, l, strlen(l));
    (void)wr;
}

static void send_bon(int fd, int lid, int tgid)
{
    char l[256];
    snprintf(l, sizeof l, "B01%02d000 3100001 31000 0.0 radioid=3100001 peerid=31000 Bee=B0199%03dG\n", lid, tgid);
    send_line(fd, l);
}

static void send_boff(int fd, int lid)
{
    char l[64];
    snprintf(l, sizeof l, "B%02d00000  LOSS=0/%d RSSI=0\n", lid, BURSTS);
    send_line(fd, l);
}

/* One CC-CC voice packet (§6): RTP PT 94, marker on the call's first packet. */
static void send_voice(int fd, uint32_t ssrc, uint16_t seq)
{
    uint8_t pkt[CCCC_RTP_PKT_LEN];
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0x80;
    pkt[1] = (uint8_t)(CCCC_RTP_PT_VOICE | (seq == 0 ? 0x80 : 0));
    pkt[2] = (uint8_t)(seq >> 8); pkt[3] = (uint8_t)seq;
    uint32_t ts = (uint32_t)seq * 480u;
    pkt[4] = (uint8_t)(ts >> 24); pkt[5] = (uint8_t)(ts >> 16); pkt[6] = (uint8_t)(ts >> 8); pkt[7] = (uint8_t)ts;
    pkt[8] = (uint8_t)(ssrc >> 24); pkt[9] = (uint8_t)(ssrc >> 16); pkt[10] = (uint8_t)(ssrc >> 8); pkt[11] = (uint8_t)ssrc;

    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(42422);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    ssize_t wr = sendto(fd, pkt, sizeof pkt, 0, (struct sockaddr *)&a, sizeof a);
    (void)wr;
}

/* ---------------- OpenBridge side: what the peer received, per tgid ---------------- */

typedef struct {
    int n;              /* DMRDs received for the call */
    int first_seq;      /* sequence of the first one (-1: none yet) */
    int gaps;           /* steps other than +1 */
    int heads, terms;
    int last_seq;
} obp_call;

/* Read DMRDs until the peer socket has been quiet for 500 ms; tally them
 * into calls[tgid].  Only tgids 1 and 2 are expected. */
static void collect(int peer_fd, obp_call calls[3])
{
    for (int t = 0; t < 3; t++) { memset(&calls[t], 0, sizeof calls[t]); calls[t].first_seq = -1; }
    uint8_t pkt[256];
    for (;;) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(peer_fd, &rfds);
        struct timeval tv = { 0, 500000 };
        if (select(peer_fd + 1, &rfds, NULL, NULL, &tv) <= 0) return;
        ssize_t n = recv(peer_fd, pkt, sizeof pkt, 0);
        if (n != OBP_DMRD_PKT_LEN || memcmp(pkt, "DMRD", 4) != 0) continue;
        int tgid = (pkt[OBP_DST_OFF] << 16) | (pkt[OBP_DST_OFF + 1] << 8) | pkt[OBP_DST_OFF + 2];
        if (tgid < 1 || tgid > 2) continue;
        obp_call *c = &calls[tgid];
        int seq = pkt[OBP_SEQ_OFF];
        int flags = pkt[OBP_FLAGS_OFF];
        if (c->first_seq < 0) c->first_seq = seq;
        else if (seq != ((c->last_seq + 1) & 0xFF)) c->gaps++;
        c->last_seq = seq;
        c->n++;
        if ((flags & OBPF_FRAMETYPE_MASK) == OBPF_FRAMETYPE_DATASYNC) {
            if ((flags & OBPF_DTYPE_MASK) == OBPF_SLT_VHEAD) c->heads++;
            if ((flags & OBPF_DTYPE_MASK) == OBPF_SLT_VTERM) c->terms++;
        }
    }
}

/* ---------------- test ---------------- */

int main(void)
{
    write_config();

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) {
        int lf = open(LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (lf >= 0) { dup2(lf, 1); dup2(lf, 2); close(lf); }
        execl("./cc2obp", "cc2obp", "-c", CFG_PATH, "--log-level", "DEBUG", (char *)NULL);
        perror("execl"); _exit(127);
    }

    int peer_fd = udp_bind_local(FAKE_PEER_PORT);
    check("fake OpenBridge peer bound", peer_fd >= 0);
    int voice_fd = udp_bind_local(VOICE_TEST_PORT);
    check("fake CC-CC voice socket bound", voice_fd >= 0);

    int a = cc_connect(SSRC_A, LID_A);
    int b = cc_connect(SSRC_B, LID_B);
    check("link 'a' up", a >= 0);
    check("link 'b' up", b >= 0);
    if (a < 0 || b < 0 || peer_fd < 0 || voice_fd < 0) goto done;

    /* ---- step 1: two calls to the same peer, overlapping ---- */
    send_bon(a, LID_A, 1);
    sleep_ms(100);
    for (uint16_t s = 0; s < 3; s++) { send_voice(voice_fd, SSRC_A, s); sleep_ms(5); }
    send_bon(b, LID_B, 2);
    sleep_ms(100);
    for (uint16_t s = 0; s < BURSTS; s++) {
        if (s + 3 < BURSTS) send_voice(voice_fd, SSRC_A, (uint16_t)(s + 3));
        sleep_ms(5);
        send_voice(voice_fd, SSRC_B, s);
        sleep_ms(5);
    }
    send_boff(a, LID_A);
    sleep_ms(50);
    send_boff(b, LID_B);

    obp_call calls[3];
    collect(peer_fd, calls);
    fprintf(stderr, "  call a: %d DMRDs, seq %d..%d, %d gaps;  call b: %d DMRDs, seq %d..%d, %d gaps\n",
            calls[1].n, calls[1].first_seq, calls[1].last_seq, calls[1].gaps,
            calls[2].n, calls[2].first_seq, calls[2].last_seq, calls[2].gaps);
    check("step 1: every burst of both calls reached the peer (head + voice + term)",
          calls[1].n == BURSTS + 2 && calls[2].n == BURSTS + 2 &&
          calls[1].heads == 1 && calls[1].terms == 1 && calls[2].heads == 1 && calls[2].terms == 1);
    check("step 1: each call's sequence starts at 0", calls[1].first_seq == 0 && calls[2].first_seq == 0);
    check("step 1: each call's sequence steps by 1 with no gap while the calls overlap",
          calls[1].gaps == 0 && calls[2].gaps == 0);

    /* ---- step 2: the next call on the same link starts again at 0 ---- */
    send_bon(a, LID_A, 1);
    sleep_ms(100);
    for (uint16_t s = 0; s < BURSTS; s++) { send_voice(voice_fd, SSRC_A, s); sleep_ms(5); }
    send_boff(a, LID_A);
    collect(peer_fd, calls);
    check("step 2: a later call on the same link starts again at 0, no gap",
          calls[1].n == BURSTS + 2 && calls[1].first_seq == 0 && calls[1].gaps == 0);

done:
    if (a >= 0) close(a);
    if (b >= 0) close(b);
    if (peer_fd >= 0) close(peer_fd);
    if (voice_fd >= 0) close(voice_fd);

    kill(pid, SIGTERM);
    int status; waitpid(pid, &status, 0);
    unlink(CFG_PATH);
    if (fails) fprintf(stderr, "cc2obp log: %s\n", LOG_PATH);
    else unlink(LOG_PATH);

    printf("obp seq self-test: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
