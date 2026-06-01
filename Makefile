CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=

BIN  := tg-scan tg-listen
HDRS := common.h config.h

all: $(BIN)

tg-scan: tg-scan.c $(HDRS)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

tg-listen: tg-listen.c $(HDRS)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN)

# Drop CAP_NET_RAW capability on the binaries so they can run as a non-root user.
setcap: $(BIN)
	sudo setcap cap_net_raw+ep ./tg-scan
	sudo setcap cap_net_raw+ep ./tg-listen

.PHONY: all clean setcap
