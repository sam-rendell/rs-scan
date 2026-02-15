BINARY  := rs-scan
PKG     := ./cmd/rs-scan
VERSION := $(shell grep 'Version =' internal/version/version.go | cut -d'"' -f2)
LDFLAGS := -s -w

PREFIX  ?= /usr/local
DATADIR  = $(PREFIX)/share/rs-scan/probes

.PHONY: build enrich test bench clean install uninstall

build:
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS) -X main.dataDir=$(DATADIR)" -o $(BINARY) $(PKG)

enrich:
	go build -ldflags "$(LDFLAGS)" -o rs-enrich ./cmd/rs-enrich

test:
	go test -race ./...

bench:
	go test -bench=. -benchmem ./internal/sender/ ./internal/stack/ ./internal/osfp/

clean:
	rm -f $(BINARY) rs-enrich rs-scan-*

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -d $(DESTDIR)$(DATADIR)/tcp $(DESTDIR)$(DATADIR)/udp
	install -m 644 probes/tcp/*.yaml $(DESTDIR)$(DATADIR)/tcp/
	install -m 644 probes/udp/*.yaml $(DESTDIR)$(DATADIR)/udp/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -rf $(DESTDIR)$(PREFIX)/share/rs-scan
