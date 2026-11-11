/* config.c — load and validate the TOML config (§6).  Style/helpers ported
 * from ipsc2hbpc's config.c (errbag accumulator + typed get_* helpers);
 * extended here to walk [[openbridge]]/[[link]] array-of-tables via
 * toml_array_len + a constructed "name#index" section string. */
#include "config.h"
#include "toml.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

/* error accumulator */
typedef struct { char buf[8192]; int n; } errbag;
static void adderr(errbag *e, const char *fmt, ...) {
    char line[256];
    va_list ap; va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    e->n += snprintf(e->buf + e->n, sizeof e->buf - (size_t)e->n, "  %s\n", line);
}

static void str_to_upper(char *s) { for (; *s; s++) *s = (char)toupper((unsigned char)*s); }

static char *trimcpy(char *dst, size_t cap, const char *src) {
    while (*src && isspace((unsigned char)*src)) src++;
    size_t len = strlen(src);
    while (len > 0 && isspace((unsigned char)src[len-1])) len--;
    if (len >= cap) len = cap - 1;
    memcpy(dst, src, len);
    dst[len] = 0;
    return dst;
}

static int get_str(const toml *t, errbag *e, const char *sec, const char *key,
                   int required, const char *deflt, char *out, size_t cap) {
    const toml_value *v = toml_get(t, sec, key);
    if (!v) {
        if (required) adderr(e, "[%s] %s: required", sec, key);
        if (deflt) snprintf(out, cap, "%s", deflt); else out[0] = 0;
        return 0;
    }
    if (v->type != TOML_STRING) {
        adderr(e, "[%s] %s: must be a string", sec, key);
        if (deflt) snprintf(out, cap, "%s", deflt); else out[0] = 0;
        return 0;
    }
    trimcpy(out, cap, v->s);
    return 1;
}

static int get_choice(const toml *t, errbag *e, const char *sec, const char *key,
                      int required, const char *deflt,
                      const char *const *choices, int nch, char *out, size_t cap) {
    const toml_value *v = toml_get(t, sec, key);
    if (!v) {
        if (required) adderr(e, "[%s] %s: required", sec, key);
        if (deflt) snprintf(out, cap, "%s", deflt); else out[0] = 0;
        return 0;
    }
    if (v->type != TOML_STRING) { adderr(e, "[%s] %s: must be a string", sec, key);
        if (deflt) snprintf(out, cap, "%s", deflt); else out[0]=0; return 0; }
    char tmp[64]; trimcpy(tmp, sizeof tmp, v->s); str_to_upper(tmp);
    for (int i = 0; i < nch; i++)
        if (!strcmp(tmp, choices[i])) { snprintf(out, cap, "%s", choices[i]); return 1; }
    adderr(e, "[%s] %s: invalid value '%s'", sec, key, v->s);
    if (deflt) snprintf(out, cap, "%s", deflt); else out[0]=0;
    return 0;
}

static long long get_int(const toml *t, errbag *e, const char *sec, const char *key,
                         int required, long long deflt, int has_min, long long mn,
                         int has_max, long long mx) {
    const toml_value *v = toml_get(t, sec, key);
    if (!v) { if (required) adderr(e, "[%s] %s: required", sec, key); return deflt; }
    if (v->type != TOML_INT) { adderr(e, "[%s] %s: must be an integer", sec, key); return deflt; }
    if (has_min && v->i < mn) adderr(e, "[%s] %s: must be >= %lld, got %lld", sec, key, mn, v->i);
    if (has_max && v->i > mx) adderr(e, "[%s] %s: must be <= %lld, got %lld", sec, key, mx, v->i);
    return v->i;
}

static int get_bool(const toml *t, errbag *e, const char *sec, const char *key,
                    int required, int deflt) {
    const toml_value *v = toml_get(t, sec, key);
    if (!v) { if (required) adderr(e, "[%s] %s: required", sec, key); return deflt; }
    if (v->type != TOML_BOOL) { adderr(e, "[%s] %s: must be true or false", sec, key); return deflt; }
    return v->b;
}

static int is_valid_ipv4(const char *s) {
    struct in_addr a;
    return inet_pton(AF_INET, s, &a) == 1;
}

/* ---------------- [[openbridge]] (§6.1) ---------------- */

static void load_openbridge(const toml *t, errbag *e, Config *cfg)
{
    int n = toml_array_len(t, "openbridge");
    if (n > CFG_MAX_OPENBRIDGE) {
        adderr(e, "[[openbridge]]: %d entries exceeds maximum of %d", n, CFG_MAX_OPENBRIDGE);
        n = CFG_MAX_OPENBRIDGE;
    }
    for (int i = 0; i < n; i++) {
        char sec[80]; snprintf(sec, sizeof sec, "openbridge#%d", i);
        ObpPeerConfig *o = &cfg->openbridge[cfg->n_openbridge++];
        memset(o, 0, sizeof *o);

        get_str(t, e, sec, "name", 1, "", o->name, sizeof o->name);
        if (!o->name[0]) adderr(e, "[%s] name: must not be empty (a reload matches entries by name)", sec);
        o->enabled = get_bool(t, e, sec, "enabled", 0, 1);
        get_str(t, e, sec, "peer_ip", 1, "", o->peer_ip, sizeof o->peer_ip);
        if (o->peer_ip[0] && !is_valid_ipv4(o->peer_ip))
            adderr(e, "[%s] peer_ip: not a valid IPv4 address: %s", sec, o->peer_ip);
        o->peer_port = (int)get_int(t, e, sec, "peer_port", 1, 0, 1, 1, 1, 65535);
        o->bind_port = (int)get_int(t, e, sec, "bind_port", 1, 0, 1, 1, 1, 65535);
        o->network_id = (uint32_t)get_int(t, e, sec, "network_id", 1, 0, 1, 0, 0, 0);
        o->preserve_source_peer = get_bool(t, e, sec, "preserve_source_peer", 0, 0);
        { char pp[256]; get_str(t, e, sec, "passphrase", 1, "", pp, sizeof pp);
          o->passphrase_len = (int)strlen(pp);
          memcpy(o->passphrase, pp, (size_t)o->passphrase_len); }
    }

    /* name uniqueness */
    for (int i = 0; i < cfg->n_openbridge; i++)
        for (int j = i + 1; j < cfg->n_openbridge; j++)
            if (cfg->openbridge[i].name[0] && !strcmp(cfg->openbridge[i].name, cfg->openbridge[j].name))
                adderr(e, "[[openbridge]]: duplicate name '%s' (entries %d and %d)",
                       cfg->openbridge[i].name, i, j);

    /* bind_port is OUR OWN local port per peer (obp_link.c binds it; §12's
     * hblink3 precedent has both PORT and TARGET_PORT — this mirrors that).
     * Two enabled peers sharing a bind_port would both try to bind the same
     * local port and fail at runtime — catch that here with a clear message
     * instead of a bare EADDRINUSE from bind(). Nothing stops bind_port from
     * equaling peer_port if the operator wants the common symmetric-port
     * convention; that's just two fields with the same value. */
    for (int i = 0; i < cfg->n_openbridge; i++) {
        if (!cfg->openbridge[i].enabled) continue;
        for (int j = i + 1; j < cfg->n_openbridge; j++) {
            if (!cfg->openbridge[j].enabled) continue;
            if (cfg->openbridge[i].bind_port == cfg->openbridge[j].bind_port)
                adderr(e, "[[openbridge]]: '%s' and '%s' both use bind_port %d — two enabled peers "
                       "cannot bind the same local port",
                       cfg->openbridge[i].name, cfg->openbridge[j].name, cfg->openbridge[i].bind_port);
        }
    }
}

/* ---------------- [[link]] (§6.2, §6.4) ---------------- */

static int find_openbridge(const Config *cfg, const char *name)
{
    for (int i = 0; i < cfg->n_openbridge; i++)
        if (!cfg->openbridge[i].vacant && !strcmp(cfg->openbridge[i].name, name)) return i;
    return -1;
}

static void load_links(const toml *t, errbag *e, Config *cfg)
{
    int n = toml_array_len(t, "link");
    if (n > CFG_MAX_LINKS) {
        adderr(e, "[[link]]: %d entries exceeds maximum of %d", n, CFG_MAX_LINKS);
        n = CFG_MAX_LINKS;
    }
    for (int i = 0; i < n; i++) {
        char sec[80]; snprintf(sec, sizeof sec, "link#%d", i);
        LinkConfig *l = &cfg->link[cfg->n_link++];
        memset(l, 0, sizeof *l);

        get_str(t, e, sec, "name", 1, "", l->name, sizeof l->name);
        if (!l->name[0]) adderr(e, "[%s] name: must not be empty (a reload matches entries by name)", sec);
        l->enabled = get_bool(t, e, sec, "enabled", 0, 1);
        l->cross_connect_active = get_bool(t, e, sec, "cross_connect_active", 0, 1);
        l->tgid = (int)get_int(t, e, sec, "tgid", 1, 0, 1, 0, 0, 0);

        get_str(t, e, sec, "openbridge_system", 1, "", l->openbridge_system, sizeof l->openbridge_system);
        l->openbridge_idx = find_openbridge(cfg, l->openbridge_system);
        if (l->openbridge_system[0] && l->openbridge_idx < 0)
            adderr(e, "[%s] openbridge_system: no [[openbridge]] named '%s'", sec, l->openbridge_system);

        { static const char *ROLES[] = {"OUTBOUND", "INBOUND"};
          char role[16];
          get_choice(t, e, sec, "cc_role", 1, "OUTBOUND", ROLES, 2, role, sizeof role);
          l->cc_role = !strcmp(role, "INBOUND") ? CC_ROLE_INBOUND : CC_ROLE_OUTBOUND;
        }

        /* No upper bound enforced: §16 notes LID > 99 encoding in Bee= is
         * undefined upstream, not that this program must reject it — that is
         * operator guidance ("should stay <= 99"), not one of §6.4's hard
         * validation rules. */
        l->cc_lid = (int)get_int(t, e, sec, "cc_lid", 1, 0, 1, 0, 0, 0);

        /* cc_remote_ip required for BOTH roles (§6.2, §6.4) */
        get_str(t, e, sec, "cc_remote_ip", 1, "", l->cc_remote_ip, sizeof l->cc_remote_ip);
        if (l->cc_remote_ip[0] && !is_valid_ipv4(l->cc_remote_ip))
            adderr(e, "[%s] cc_remote_ip: not a valid IPv4 address: %s", sec, l->cc_remote_ip);

        /* cc_remote_port: meaningful and required ONLY for outbound (§6.4).
         * For inbound, never read it from TOML — always -1 in the runtime
         * struct regardless of what (if anything) is present in the file. */
        if (l->cc_role == CC_ROLE_OUTBOUND)
            l->cc_remote_port = (int)get_int(t, e, sec, "cc_remote_port", 1, 0, 1, 1, 1, 65535);
        else
            l->cc_remote_port = -1;

        l->cc_remote_voice_port = (int)get_int(t, e, sec, "cc_remote_voice_port", 1, 0, 1, 1, 1, 65535);

        if (l->cc_role == CC_ROLE_OUTBOUND)
            get_str(t, e, sec, "cc_channel_name", 1, "", l->cc_channel_name, sizeof l->cc_channel_name);
        else
            get_str(t, e, sec, "cc_channel_name", 0, "", l->cc_channel_name, sizeof l->cc_channel_name);
    }

    /* §6.4 validation */

    /* link.name unique */
    for (int i = 0; i < cfg->n_link; i++)
        for (int j = i + 1; j < cfg->n_link; j++)
            if (cfg->link[i].name[0] && !strcmp(cfg->link[i].name, cfg->link[j].name))
                adderr(e, "[[link]]: duplicate name '%s' (entries %d and %d)", cfg->link[i].name, i, j);

    /* (openbridge_system, tgid) unique */
    for (int i = 0; i < cfg->n_link; i++)
        for (int j = i + 1; j < cfg->n_link; j++)
            if (cfg->link[i].openbridge_idx >= 0 && cfg->link[i].openbridge_idx == cfg->link[j].openbridge_idx &&
                cfg->link[i].tgid == cfg->link[j].tgid)
                adderr(e, "[[link]]: duplicate (openbridge_system, tgid) = ('%s', %d) — links '%s' and '%s'",
                       cfg->link[i].openbridge_system, cfg->link[i].tgid, cfg->link[i].name, cfg->link[j].name);

    /* (cc_remote_ip, cc_lid) unique among INBOUND entries only */
    for (int i = 0; i < cfg->n_link; i++) {
        if (cfg->link[i].cc_role != CC_ROLE_INBOUND) continue;
        for (int j = i + 1; j < cfg->n_link; j++) {
            if (cfg->link[j].cc_role != CC_ROLE_INBOUND) continue;
            if (!strcmp(cfg->link[i].cc_remote_ip, cfg->link[j].cc_remote_ip) &&
                cfg->link[i].cc_lid == cfg->link[j].cc_lid)
                adderr(e, "[[link]]: duplicate inbound (cc_remote_ip, cc_lid) = ('%s', %d) — links '%s' and '%s'",
                       cfg->link[i].cc_remote_ip, cfg->link[i].cc_lid, cfg->link[i].name, cfg->link[j].name);
        }
    }
}

/* Soft check (§6.4): duplicate (cc_remote_ip, cc_remote_port, cc_lid) among
 * OUTBOUND entries is a likely operator typo, not a correctness violation —
 * each outbound entry gets its own dedicated connection regardless.  Logged,
 * not refused; called from main.c after log_init (config_load runs first). */
void config_warn_soft_issues(const Config *cfg)
{
    for (int i = 0; i < cfg->n_link; i++) {
        if (cfg->link[i].vacant || cfg->link[i].cc_role != CC_ROLE_OUTBOUND) continue;
        for (int j = i + 1; j < cfg->n_link; j++) {
            if (cfg->link[j].vacant || cfg->link[j].cc_role != CC_ROLE_OUTBOUND) continue;
            if (!strcmp(cfg->link[i].cc_remote_ip, cfg->link[j].cc_remote_ip) &&
                cfg->link[i].cc_remote_port == cfg->link[j].cc_remote_port &&
                cfg->link[i].cc_lid == cfg->link[j].cc_lid)
                LOGW("config", "links '%s' and '%s' share (cc_remote_ip, cc_remote_port, cc_lid) = "
                     "('%s', %d, %d) — likely operator typo (not an error: each has its own connection)",
                     cfg->link[i].name, cfg->link[j].name,
                     cfg->link[i].cc_remote_ip, cfg->link[i].cc_remote_port, cfg->link[i].cc_lid);
        }
    }
}

int config_load(const char *path, Config *cfg, char *err, size_t errlen)
{
    char perr[256];
    toml *t = toml_parse_file(path, perr, sizeof perr);
    if (!t) { snprintf(err, errlen, "%s", perr); return -1; }

    errbag e; e.buf[0] = 0; e.n = 0;
    memset(cfg, 0, sizeof *cfg);

    /* [global] */
    { static const char *LV[] = {"DEBUG","INFO","WARNING","ERROR"};
      char lvl[16];
      get_choice(t, &e, "global", "log_level", 0, "INFO", LV, 4, lvl, sizeof lvl);
      cfg->log_level = log_level_from_str(lvl);
      if (cfg->log_level < 0) cfg->log_level = LOG_INFO;
    }
    get_str(t, &e, "global", "cc_site_name",     0, "cc2obp",  cfg->cc_site_name,     sizeof cfg->cc_site_name);
    get_str(t, &e, "global", "cc_mac_address",   0, "000000000000", cfg->cc_mac_address, sizeof cfg->cc_mac_address);
    get_str(t, &e, "global", "cc_code_revision", 0, "10252",   cfg->cc_code_revision, sizeof cfg->cc_code_revision);
    get_str(t, &e, "global", "cc_version",       0, "cc2obp",  cfg->cc_version,       sizeof cfg->cc_version);
    get_str(t, &e, "global", "cc_os_version",    0, "Linux",   cfg->cc_os_version,    sizeof cfg->cc_os_version);
    cfg->cc_keepalive_interval = (double)get_int(t, &e, "global", "cc_keepalive_interval", 0, 10, 1, 1, 1, 300);
    cfg->cc_link_timeout       = (double)get_int(t, &e, "global", "cc_link_timeout",       0, 35, 1, 1, 1, 3600);

    load_openbridge(t, &e, cfg);
    load_links(t, &e, cfg);

    toml_free(t);

    if (e.n > 0) {
        snprintf(err, errlen, "Configuration errors:\n%s", e.buf);
        return -1;
    }
    return 0;
}

/* ---------------- SIGHUP reload (§6.3) ---------------- */

static int peer_identity_differs(const ObpPeerConfig *a, const ObpPeerConfig *b)
{
    return strcmp(a->peer_ip, b->peer_ip) != 0 || a->peer_port != b->peer_port ||
           a->bind_port != b->bind_port || a->network_id != b->network_id ||
           a->passphrase_len != b->passphrase_len ||
           memcmp(a->passphrase, b->passphrase, (size_t)a->passphrase_len) != 0 ||
           a->preserve_source_peer != b->preserve_source_peer;
}

/* openbridge_system is compared by name: slots never move, so a link that
 * still names the same peer still points at the same index. */
static int link_identity_differs(const LinkConfig *a, const LinkConfig *b)
{
    return a->tgid != b->tgid || strcmp(a->openbridge_system, b->openbridge_system) != 0 ||
           a->cc_role != b->cc_role || a->cc_lid != b->cc_lid ||
           strcmp(a->cc_remote_ip, b->cc_remote_ip) != 0 ||
           a->cc_remote_port != b->cc_remote_port || a->cc_remote_voice_port != b->cc_remote_voice_port ||
           strcmp(a->cc_channel_name, b->cc_channel_name) != 0;
}

static int global_differs(const Config *a, const Config *b)
{
    return a->log_level != b->log_level ||
           strcmp(a->cc_site_name, b->cc_site_name) != 0 || strcmp(a->cc_mac_address, b->cc_mac_address) != 0 ||
           strcmp(a->cc_code_revision, b->cc_code_revision) != 0 || strcmp(a->cc_version, b->cc_version) != 0 ||
           strcmp(a->cc_os_version, b->cc_os_version) != 0 ||
           a->cc_keepalive_interval != b->cc_keepalive_interval || a->cc_link_timeout != b->cc_link_timeout;
}

/* Lay the fresh [[openbridge]] entries out over the running slots, matched
 * by name: a kept peer stays in its slot, a removed one leaves a vacant slot,
 * a new one takes the first vacant slot or is appended.  A slot freed by this
 * same reload still has its old peer running, so reusing it is a REPLACE (old
 * one down first), not an ADD. */
static int lay_out_openbridge(const Config *cur, const Config *fr, Config *next, ReloadPlan *plan,
                              char *err, size_t errlen)
{
    int used[CFG_MAX_OPENBRIDGE] = {0};
    next->n_openbridge = cur->n_openbridge;

    for (int i = 0; i < cur->n_openbridge; i++) {
        const ObpPeerConfig *o = &cur->openbridge[i];
        plan->openbridge[i] = RELOAD_KEEP;
        if (o->vacant) { next->openbridge[i] = *o; continue; }
        int j = 0;
        while (j < fr->n_openbridge && (used[j] || strcmp(fr->openbridge[j].name, o->name) != 0)) j++;
        if (j == fr->n_openbridge) {
            memset(&next->openbridge[i], 0, sizeof next->openbridge[i]);
            next->openbridge[i].vacant = 1;
            plan->openbridge[i] = RELOAD_REMOVE;
            continue;
        }
        used[j] = 1;
        next->openbridge[i] = fr->openbridge[j];
        if (peer_identity_differs(o, &fr->openbridge[j]))
            plan->openbridge[i] = RELOAD_CHANGE;
        else if (o->enabled != fr->openbridge[j].enabled)
            plan->openbridge[i] = RELOAD_TOGGLE;
    }

    for (int j = 0; j < fr->n_openbridge; j++) {
        if (used[j]) continue;
        int i = 0;
        while (i < next->n_openbridge && !next->openbridge[i].vacant) i++;
        if (i == next->n_openbridge) {
            if (next->n_openbridge >= CFG_MAX_OPENBRIDGE) {
                snprintf(err, errlen, "reload: [[openbridge]] '%s': no free slot (max %d)",
                         fr->openbridge[j].name, CFG_MAX_OPENBRIDGE);
                return -1;
            }
            next->n_openbridge++;
        }
        plan->openbridge[i] = (i < cur->n_openbridge && plan->openbridge[i] == RELOAD_REMOVE)
                              ? RELOAD_REPLACE : RELOAD_ADD;
        next->openbridge[i] = fr->openbridge[j];
    }
    return 0;
}

/* Same layout rules as lay_out_openbridge(), for [[link]]. */
static int lay_out_links(const Config *cur, const Config *fr, Config *next, ReloadPlan *plan,
                         char *err, size_t errlen)
{
    int used[CFG_MAX_LINKS] = {0};
    next->n_link = cur->n_link;

    for (int i = 0; i < cur->n_link; i++) {
        const LinkConfig *l = &cur->link[i];
        plan->link[i] = RELOAD_KEEP;
        if (l->vacant) { next->link[i] = *l; continue; }
        int j = 0;
        while (j < fr->n_link && (used[j] || strcmp(fr->link[j].name, l->name) != 0)) j++;
        if (j == fr->n_link) {
            memset(&next->link[i], 0, sizeof next->link[i]);
            next->link[i].vacant = 1;
            next->link[i].openbridge_idx = -1;
            plan->link[i] = RELOAD_REMOVE;
            continue;
        }
        used[j] = 1;
        next->link[i] = fr->link[j];
        if (link_identity_differs(l, &fr->link[j]))
            plan->link[i] = RELOAD_CHANGE;
        else if (l->enabled != fr->link[j].enabled || l->cross_connect_active != fr->link[j].cross_connect_active)
            plan->link[i] = RELOAD_TOGGLE;
    }

    for (int j = 0; j < fr->n_link; j++) {
        if (used[j]) continue;
        int i = 0;
        while (i < next->n_link && !next->link[i].vacant) i++;
        if (i == next->n_link) {
            if (next->n_link >= CFG_MAX_LINKS) {
                snprintf(err, errlen, "reload: [[link]] '%s': no free slot (max %d)",
                         fr->link[j].name, CFG_MAX_LINKS);
                return -1;
            }
            next->n_link++;
        }
        plan->link[i] = (i < cur->n_link && plan->link[i] == RELOAD_REMOVE) ? RELOAD_REPLACE : RELOAD_ADD;
        next->link[i] = fr->link[j];
    }
    return 0;
}

int config_reload_plan(const char *path, const Config *cur, Config *next, ReloadPlan *plan,
                       char *err, size_t errlen)
{
    static Config fresh;   /* ~60 KB: keep it off the stack */
    if (config_load(path, &fresh, err, errlen) != 0)
        return -1;

    memset(plan, 0, sizeof *plan);
    memset(next, 0, sizeof *next);

    /* [global] is out of scope for a reload (its identity fields already went
     * out in every live link's handshake): keep the running values until a restart. */
    plan->global_changed = global_differs(cur, &fresh);
    next->log_level = cur->log_level;
    memcpy(next->cc_site_name, cur->cc_site_name, sizeof next->cc_site_name);
    memcpy(next->cc_mac_address, cur->cc_mac_address, sizeof next->cc_mac_address);
    memcpy(next->cc_code_revision, cur->cc_code_revision, sizeof next->cc_code_revision);
    memcpy(next->cc_version, cur->cc_version, sizeof next->cc_version);
    memcpy(next->cc_os_version, cur->cc_os_version, sizeof next->cc_os_version);
    next->cc_keepalive_interval = cur->cc_keepalive_interval;
    next->cc_link_timeout = cur->cc_link_timeout;

    if (lay_out_openbridge(cur, &fresh, next, plan, err, errlen) != 0 ||
        lay_out_links(cur, &fresh, next, plan, err, errlen) != 0)
        return -1;

    /* Peers kept their slots by name; re-resolve each link against the new layout. */
    for (int i = 0; i < next->n_link; i++) {
        LinkConfig *l = &next->link[i];
        if (l->vacant) { l->openbridge_idx = -1; continue; }
        l->openbridge_idx = find_openbridge(next, l->openbridge_system);
        /* Cannot happen with name-stable slots; never keep a link on a stale index. */
        if (i < cur->n_link && (plan->link[i] == RELOAD_KEEP || plan->link[i] == RELOAD_TOGGLE) &&
            l->openbridge_idx != cur->link[i].openbridge_idx)
            plan->link[i] = RELOAD_CHANGE;
    }
    return 0;
}
