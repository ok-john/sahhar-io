
.PHONY: all
all :: 

ifneq ($(MAKECMDGOALS),)
FIRST_GOAL := $(word 1, $(MAKECMDGOALS))
LAST_GOAL := $(word $(words $(MAKECMDGOALS)), $(MAKECMDGOALS))
else
FIRST_GOAL := all
LAST_GOAL := all
endif

CC := go
CFLAGS := build -o
SHELL := /bin/bash
SCRIPTS := scripts
BINARY := sahhar-io
DAEMON_PATH := /var/lib/local/sahhar-io
COPY_FOLDERS := public static $(BINARY) $(DAEMON_PATH)
SERVICE_CONFIG := $(BINARY).service

# Preprocessing
$(FIRST_GOAL) :: 
	mkdir -p $(DAEMON_PATH)
	$(CC) get ./... 
	$(CC) mod tidy

build ::
	$(CC) test ./...
	$(CC) build -o $(BINARY)

copy ::
	cat $(BINARY) | sha256sum | cut -c -64 > public/checksum
	cp -r $(COPY_FOLDERS)
	cp $(SERVICE_CONFIG) /etc/systemd/system/$(SERVICE_CONFIG)

disable ::
	systemctl stop $(BINARY)
	systemctl disable $(BINARY)

reload :: disable build copy
	systemctl daemon-reload
	systemctl enable $(BINARY)
	systemctl start $(BINARY)
tail ::
	journalctl -f -u $(BINARY)

fresh-redis ::
	./$(SCRIPTS)/init

# Postprocessing
$(LAST_GOAL) :: 
	cat $(BINARY) | sha256sum | cut -c -64 > local.checksum

