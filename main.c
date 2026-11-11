/* main.c — cc2obp entry point: args, config load, wires cccc_mux <-> obp_mux
 * <-> translator together, runs the event loop.  SIGHUP reload (§6.3) is
 * deferred out of the signal handler (config parsing/logging are not
 * async-signal-safe) via a flag checked on the periodic tick. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "config.h"
#include "log.h"
#include "eventloop.h"
#include "cccc/cccc_link.h"
#include "openbridge/obp_link.h"
#include "translate.h"

#define TICK_INTERVAL_S 1.0

static ev_loop  *g_loop = NULL;
static cccc_mux *g_cc   = NULL;
static obp_mux  *g_ob   = NULL;
static translator *g_tr = NULL;
static const char *g_cfg_path = NULL;
static Config    g_cfg;

static volatile sig_atomic_t g_reload_requested = 0;
static volatile sig_atomic_t g_shutdown_requested = 0;

static void on_sighup(int signum)  { (void)signum; g_reload_requested = 1; }
static void on_sigterm(int signum) { (void)signum; g_shutdown_requested = 1; }

/* Only what changed is touched: a changed or removed link loses its own
 * connection, a changed or removed peer its own socket.  Every other link
 * stays up through the reload. */
static void do_reload(void)
{
    static Config next;          /* ~60 KB: keep it off the stack */
    static ReloadPlan plan;
    char err[8192];

    LOGI("cc2obp", "SIGHUP received — reloading %s (§6.3)", g_cfg_path);
    if (config_reload_plan(g_cfg_path, &g_cfg, &next, &plan, err, sizeof err) != 0) {
        LOGE("cc2obp", "reload failed, keeping running config: %s", err);
        return;
    }
    if (plan.global_changed)
        LOGW("cc2obp", "reload: [global] changed — ignored, applies on the next restart");

    /* 1. Bring down what goes away or changes, while g_cfg still describes it.
     *    Links first: a link going down may still send a VOICE_TERM to its peer. */
    for (int i = 0; i < g_cfg.n_link; i++) {
        if (plan.link[i] != RELOAD_CHANGE && plan.link[i] != RELOAD_REMOVE && plan.link[i] != RELOAD_REPLACE)
            continue;
        LOGI("cc2obp", "reload: link '%s' %s", g_cfg.link[i].name,
             plan.link[i] == RELOAD_CHANGE ? "changed" : "removed");
        cccc_mux_retire_link(g_cc, i);
        translator_link_reset(g_tr, i);
    }
    for (int i = 0; i < g_cfg.n_openbridge; i++) {
        if (plan.openbridge[i] != RELOAD_CHANGE && plan.openbridge[i] != RELOAD_REMOVE &&
            plan.openbridge[i] != RELOAD_REPLACE)
            continue;
        LOGI("cc2obp", "reload: openbridge '%s' %s", g_cfg.openbridge[i].name,
             plan.openbridge[i] == RELOAD_CHANGE ? "changed" : "removed");
        obp_mux_retire_peer(g_ob, i);
    }

    /* 2. Switch to the new config (the muxes and translator hold &g_cfg). */
    g_cfg = next;

    /* 3. Bring up whatever is enabled and not running: added and rebuilt
     *    entries, and toggles in either direction. */
    for (int i = 0; i < g_cfg.n_link; i++)
        if (plan.link[i] == RELOAD_ADD || plan.link[i] == RELOAD_REPLACE || plan.link[i] == RELOAD_TOGGLE)
            LOGI("cc2obp", "reload: link '%s' %s", g_cfg.link[i].name,
                 plan.link[i] == RELOAD_TOGGLE ? "toggled" : "added");
    for (int i = 0; i < g_cfg.n_openbridge; i++)
        if (plan.openbridge[i] == RELOAD_ADD || plan.openbridge[i] == RELOAD_REPLACE ||
            plan.openbridge[i] == RELOAD_TOGGLE)
            LOGI("cc2obp", "reload: openbridge '%s' %s", g_cfg.openbridge[i].name,
                 plan.openbridge[i] == RELOAD_TOGGLE ? "toggled" : "added");
    config_warn_soft_issues(&g_cfg);
    obp_mux_reconcile(g_ob);
    cccc_mux_reconcile(g_cc);
    LOGI("cc2obp", "reload complete");
}

static void tick_cb(ev_loop *loop, void *ud)
{
    translator *tr = ud;
    translator_tick(tr);
    if (g_reload_requested) { g_reload_requested = 0; do_reload(); }
    if (g_shutdown_requested) { ev_stop(loop); return; }
    ev_timer_after(loop, TICK_INTERVAL_S, tick_cb, tr);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-c config.toml] [--log-level LEVEL] [--wire] [--check]\n"
        "  -c, --config PATH    Path to TOML config (default: /etc/cc2obp/cc2obp.toml)\n"
        "  --log-level LEVEL    Override config log level (DEBUG|INFO|WARNING|ERROR)\n"
        "  --wire                Log raw CC-CC/OpenBridge hex only; silence everything else\n"
        "  --check               Parse and validate the config, print a summary, exit.\n"
        "                        Never binds a socket — safe to run against a config\n"
        "                        edit while a real instance is already running on the\n"
        "                        same ports (e.g. before `systemctl reload`).\n",
        prog);
}

static void print_check_summary(const Config *cfg)
{
    printf("Configuration OK: %d openbridge peer(s), %d link(s)\n\n", cfg->n_openbridge, cfg->n_link);

    for (int i = 0; i < cfg->n_openbridge; i++) {
        const ObpPeerConfig *o = &cfg->openbridge[i];
        printf("  [[openbridge]] %-16s %-8s %s:%d (bind_port %d)\n",
               o->name, o->enabled ? "enabled" : "disabled", o->peer_ip, o->peer_port, o->bind_port);
    }
    if (cfg->n_openbridge > 0) printf("\n");

    for (int i = 0; i < cfg->n_link; i++) {
        const LinkConfig *l = &cfg->link[i];
        printf("  [[link]] %-20s %-8s xc=%-8s %-8s tgid=%-6d lid=%-3d -> %s (%s)\n",
               l->name, l->enabled ? "enabled" : "disabled",
               l->cross_connect_active ? "active" : "inactive",
               l->cc_role == CC_ROLE_OUTBOUND ? "outbound" : "inbound",
               l->tgid, l->cc_lid, l->cc_remote_ip, l->openbridge_system);
    }
}

int main(int argc, char **argv)
{
    const char *cfg_path = "/etc/cc2obp/cc2obp.toml";
    const char *log_level_override = NULL;
    int wire = 0;
    int check_mode = 0;

    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc) {
            cfg_path = argv[++i];
        } else if (!strcmp(argv[i], "--log-level") && i + 1 < argc) {
            log_level_override = argv[++i];
        } else if (!strcmp(argv[i], "--wire")) {
            wire = 1;
        } else if (!strcmp(argv[i], "--check")) {
            check_mode = 1;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]); return 0;
        } else {
            usage(argv[0]); return 2;
        }
    }
    g_cfg_path = cfg_path;

    char err[8192];
    if (config_load(cfg_path, &g_cfg, err, sizeof err) != 0) {
        fprintf(stderr, "%s\n", err);   /* err is already a complete, framed message (config.c/toml.c) */
        return 1;
    }

    int level = g_cfg.log_level;
    if (log_level_override) {
        int l = log_level_from_str(log_level_override);
        if (l >= 0) level = l;
    }
    log_init(level, wire);
    config_warn_soft_issues(&g_cfg);

    if (check_mode) {
        print_check_summary(&g_cfg);
        return 0;
    }

    LOGI("cc2obp", "cc2obp starting — %d openbridge peer(s), %d link(s), config=%s",
         g_cfg.n_openbridge, g_cfg.n_link, cfg_path);

    g_loop = ev_new();
    translator *tr = g_tr = translator_new(&g_cfg, g_loop);
    g_ob = obp_mux_new(&g_cfg, tr, g_loop);
    g_cc = cccc_mux_new(&g_cfg, tr, g_loop);
    translator_set_protocols(tr, g_cc, g_ob);

    struct sigaction sa_term; memset(&sa_term, 0, sizeof sa_term);
    sa_term.sa_handler = on_sigterm;
    sigaction(SIGTERM, &sa_term, NULL);
    sigaction(SIGINT, &sa_term, NULL);

    struct sigaction sa_hup; memset(&sa_hup, 0, sizeof sa_hup);
    sa_hup.sa_handler = on_sighup;
    sigaction(SIGHUP, &sa_hup, NULL);

    if (obp_mux_start(g_ob) != 0) {
        LOGE("cc2obp", "failed to start OpenBridge peers");
        return 1;
    }
    if (cccc_mux_start(g_cc) != 0) {
        fprintf(stderr, "Failed to bind CC-CC sockets\n");
        return 1;
    }

    ev_timer_after(g_loop, TICK_INTERVAL_S, tick_cb, tr);

    LOGI("cc2obp", "cc2obp running");
    ev_run(g_loop);

    LOGI("cc2obp", "shutting down");
    cccc_mux_stop(g_cc);
    obp_mux_stop(g_ob);
    cccc_mux_free(g_cc);
    obp_mux_free(g_ob);
    translator_free(tr);
    ev_free(g_loop);
    LOGI("cc2obp", "cc2obp stopped");
    return 0;
}
