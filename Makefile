# cc2obp — CC-CC to OpenBridge translator
CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -D_DEFAULT_SOURCE
LDFLAGS ?=

CCCC_DIR := cccc
OBP_DIR  := openbridge
DMR_DIR  := dmr

SOURCES := \
	main.c \
	config.c \
	toml.c \
	log.c \
	eventloop.c \
	net.c \
	crypto.c \
	translate.c \
	$(CCCC_DIR)/cccc_link.c \
	$(CCCC_DIR)/cccc_ambe.c \
	$(OBP_DIR)/obp_link.c \
	$(DMR_DIR)/dmr_bits.c \
	$(DMR_DIR)/dmr_const.c \
	$(DMR_DIR)/hamming.c \
	$(DMR_DIR)/crc.c \
	$(DMR_DIR)/golay.c \
	$(DMR_DIR)/bptc.c \
	$(DMR_DIR)/ambe.c \
	$(DMR_DIR)/rs129.c
# NOTE: the plan's §11 table claims dmr_rs129_lc_encode is "not needed" here
# (called it IPSC-specific wire framing). That's inaccurate: dmr_bptc_encode_lc
# calls it internally to assemble the RS(12,9) parity into the 12-byte matrix
# BPTC(196,96) itself requires (bptc.c) — it is not an IPSC-only concern, it's
# how a Full LC (VOICE_HEAD/TERM) is built for ANY destination. Confirmed by
# the linker (undefined reference) when this file was first left out.

OBJECTS := $(SOURCES:.c=.o)
BIN     := cc2obp

# DMR module sources (used by the standalone DSP self-test)
DMR_SOURCES := $(filter $(DMR_DIR)/%,$(SOURCES))

.PHONY: all clean test install uninstall

all: $(BIN)

# FHS install (run as root: sudo make install)
#   binary  -> $(PREFIX)/bin/cc2obp              (default /usr/local/bin)
#   config  -> $(SYSCONFDIR)/cc2obp/              (default /etc/cc2obp)
#   unit    -> $(UNITDIR)/cc2obp.service          (default /lib/systemd/system)
# The live config is NEVER overwritten: cc2obp.toml is installed only if it
# does not already exist; the sample is always refreshed.  install does NOT
# enable or start the service.
PREFIX     ?= /usr/local
SYSCONFDIR ?= /etc
UNITDIR    ?= /lib/systemd/system
CONFDIR    := $(SYSCONFDIR)/cc2obp
UNIT       := $(UNITDIR)/cc2obp.service

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/cc2obp
	install -d $(DESTDIR)$(CONFDIR)
	install -m 0644 cc2obp.toml.sample $(DESTDIR)$(CONFDIR)/cc2obp.toml.sample
	@if [ -f $(DESTDIR)$(CONFDIR)/cc2obp.toml ]; then \
	    echo "Preserving existing $(DESTDIR)$(CONFDIR)/cc2obp.toml (not overwritten)"; \
	else \
	    install -m 0644 cc2obp.toml.sample $(DESTDIR)$(CONFDIR)/cc2obp.toml; \
	    echo "Installed fresh $(DESTDIR)$(CONFDIR)/cc2obp.toml — edit it before starting"; \
	fi
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 cc2obp.service $(DESTDIR)$(UNIT)
	-systemctl daemon-reload
	@echo
	@echo "Installed. NOT enabled/started. Edit $(CONFDIR)/cc2obp.toml then:"
	@echo "    sudo systemctl enable --now cc2obp"

# Remove binary and unit; the config directory is left in place on purpose.
uninstall:
	-systemctl disable --now cc2obp
	-rm -f $(DESTDIR)$(PREFIX)/bin/cc2obp
	-rm -f $(DESTDIR)$(UNIT)
	-systemctl daemon-reload
	@echo "Removed binary and unit. Left $(CONFDIR) intact (delete manually if desired)."

$(BIN): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Tests:
#  - test_dsp:          dmr module vs golden vectors generated from dmr_utils3 (shared with ipsc2hbpc)
#  - test_cccc_ambe:    cccc_ambe pack/unpack round-trip + bit-layout checks
#  - test_translate:    §15 SSRC collision, as a real system test against the
#    compiled $(BIN) (fork/exec + loopback CC-CC sockets).
#  - test_obp_scenarios: §15 orphaned call + seq/ts-gap consistency, driven
#    from the OpenBridge (UDP) side using a fake peer (dmr/+crypto primitives
#    to build valid DMRD frames) — see each file's header comment for scope.
#  - test_reload:       §6.3 SIGHUP reload touches only the links/peers that
#    changed — the untouched link's connection stays up and keeps bridging.
test: $(BIN) tests/test_dsp.c tests/test_cccc_ambe.c tests/test_translate.c tests/test_obp_scenarios.c tests/test_reload.c
	$(CC) $(CFLAGS) -I. -o /tmp/cc2obp_test_dsp tests/test_dsp.c $(DMR_SOURCES)
	/tmp/cc2obp_test_dsp tests/dsp_vectors.txt
	$(CC) $(CFLAGS) -I. -o /tmp/cc2obp_test_cccc_ambe tests/test_cccc_ambe.c $(CCCC_DIR)/cccc_ambe.c $(DMR_SOURCES)
	/tmp/cc2obp_test_cccc_ambe
	$(CC) $(CFLAGS) -I. -o /tmp/cc2obp_test_translate tests/test_translate.c
	/tmp/cc2obp_test_translate
	$(CC) $(CFLAGS) -I. -o /tmp/cc2obp_test_obp_scenarios tests/test_obp_scenarios.c crypto.c $(DMR_SOURCES)
	/tmp/cc2obp_test_obp_scenarios
	$(CC) $(CFLAGS) -I. -o /tmp/cc2obp_test_reload tests/test_reload.c crypto.c $(DMR_SOURCES)
	/tmp/cc2obp_test_reload

clean:
	rm -f $(OBJECTS) $(BIN)
