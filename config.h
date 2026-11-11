/* config.h — cc2obp TOML config -> validated runtime struct (§6).
 *
 * The formal plan (§6.1, §6.2) specifies the [[openbridge]] and [[link]]
 * tables exactly; it defers to "this program's own [cccc] config" (§9) for
 * global identity/keepalive fields without enumerating them, since those are
 * dictated by the CC-CC handshake fields (§4.1, §4.2 of the formal spec) and
 * not by the plan itself.  Those are collected here under [global]. */
#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define CFG_MAX_OPENBRIDGE 32
#define CFG_MAX_LINKS      128

typedef enum { CC_ROLE_OUTBOUND, CC_ROLE_INBOUND } cc_role_t;

typedef struct {
    char     name[64];             /* this program's own identifier (§6.1) */
    int      enabled;
    char     peer_ip[64];
    int      peer_port;            /* remote's port: send-to AND expected source port on receive */
    int      bind_port;            /* OUR OWN local port — independent of peer_port; set equal to
                                     * it if the operator wants the common symmetric-port convention */
    uint32_t network_id;
    char     passphrase[256];
    int      passphrase_len;
    int      preserve_source_peer; /* if set, do NOT overwrite the DMRD Repeater-ID field
                                     * (bytes 11-14) with network_id on send — forward the
                                     * originating source-peer instead (unvalidated field;
                                     * see obp_send_dmrd / translate.c). Default off. */
    int      vacant;               /* slot left behind by a reload that removed this peer:
                                     * never bound, never matched; reused by a later add */
} ObpPeerConfig;

typedef struct {
    char      name[64];             /* this program's own identifier (§6.2, §6.4) */
    int       enabled;
    int       cross_connect_active;
    int       tgid;
    char      openbridge_system[64];/* references an ObpPeerConfig.name */
    int       openbridge_idx;       /* resolved index into Config.openbridge[], -1 until resolved */
    cc_role_t cc_role;
    int       cc_lid;
    char      cc_remote_ip[64];
    int       cc_remote_port;       /* outbound only; -1 if not applicable/unset (§6.4) */
    int       cc_remote_voice_port;
    char      cc_channel_name[128]; /* outbound only (§6.2) */
    int       vacant;               /* slot left behind by a reload that removed this link:
                                     * never dialed, never matched; reused by a later add */
} LinkConfig;

typedef struct {
    int      log_level;             /* LOG_* enum */

    /* [global] — CC-CC handshake identity (formal spec §4.1/§4.2) and timers,
     * not enumerated by the plan itself (see file header comment). */
    char     cc_site_name[128];
    char     cc_mac_address[32];    /* 12 hex chars, formal spec §4.1 field 5 */
    char     cc_code_revision[32];
    char     cc_version[128];       /* Answer field 3 */
    char     cc_os_version[128];
    double   cc_keepalive_interval; /* seconds, formal spec §8 ~10s */
    double   cc_link_timeout;       /* seconds without a keepalive -> link dead */

    ObpPeerConfig openbridge[CFG_MAX_OPENBRIDGE];
    int           n_openbridge;

    LinkConfig    link[CFG_MAX_LINKS];
    int           n_link;
} Config;

/* Load and validate a TOML config file.  Returns 0 on success; on failure
 * returns -1 and fills err with a human-readable message. */
int config_load(const char *path, Config *cfg, char *err, size_t errlen);

/* SIGHUP reload (§6.3).  What a reload does to one [[openbridge]] or [[link]]
 * slot.  Slots are matched by name and never move, so every index held by
 * cccc_link.c, obp_link.c and translate.c stays valid across a reload. */
typedef enum {
    RELOAD_KEEP = 0,   /* unchanged: left completely alone */
    RELOAD_TOGGLE,     /* only enabled/cross_connect_active changed (applied by *_reconcile) */
    RELOAD_CHANGE,     /* any other field changed: tear down, then bring up with the new values */
    RELOAD_REMOVE,     /* no longer in the file: tear down, slot becomes vacant */
    RELOAD_ADD,        /* new in the file: brought up in a vacant or new slot */
    RELOAD_REPLACE     /* removed, and its slot reused by an add in the same reload:
                        * the old entry comes down before the new one goes up */
} reload_action_t;

typedef struct {
    reload_action_t openbridge[CFG_MAX_OPENBRIDGE];
    reload_action_t link[CFG_MAX_LINKS];
    int           global_changed;   /* [global] differs: ignored until a full restart */
} ReloadPlan;

/* Re-parse path and lay the result out against *cur: every entry keeps the
 * slot it already has (matched by name), removed entries leave a vacant slot,
 * new entries take a vacant slot or are appended.  Fills *next (the config to
 * run after the reload; [global] is carried over from *cur unchanged) and
 * *plan.  Does not touch *cur.  Returns 0 on success, -1 on a parse or
 * validation error (err filled; the running config stays as it is). */
int config_reload_plan(const char *path, const Config *cur, Config *next, ReloadPlan *plan,
                       char *err, size_t errlen);

/* Log (LOGW), but do not fail, likely-typo duplicate outbound
 * (cc_remote_ip, cc_remote_port, cc_lid) tuples (§6.4).  Call after log_init,
 * since config_load necessarily runs before logging is set up. */
void config_warn_soft_issues(const Config *cfg);

#endif /* CONFIG_H */
