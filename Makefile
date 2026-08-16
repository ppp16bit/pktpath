BINARY ?= pktpath
PACKAGE ?= ./cmd/pktpath
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
INSTALL_PATH = $(DESTDIR)$(BINDIR)/$(notdir $(BINARY))

GO ?= go
INSTALL ?= install
SETCAP ?= setcap
SUDO ?= sudo
CAPABILITY ?= cap_net_raw+ep

.DEFAULT_GOAL := build

.PHONY: build install uninstall setcap test vet check clean

build:
	$(GO) build -o $(BINARY) $(PACKAGE)

install: build
ifeq ($(strip $(DESTDIR)),)
	$(SUDO) $(INSTALL) -Dm755 $(BINARY) $(INSTALL_PATH)
	$(SUDO) $(SETCAP) $(CAPABILITY) $(INSTALL_PATH)
else
	$(INSTALL) -Dm755 $(BINARY) $(INSTALL_PATH)
endif

setcap: build
	$(SUDO) $(SETCAP) $(CAPABILITY) $(BINARY)

uninstall:
ifeq ($(strip $(DESTDIR)),)
	$(SUDO) $(RM) $(INSTALL_PATH)
else
	$(RM) $(INSTALL_PATH)
endif

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

check:
	$(GO) vet ./...
	$(GO) test ./...
	find . -name '*.go' -not -path './vendor/*' -exec gopls check {} +

clean:
	$(RM) $(BINARY)
