
.PHONY: all pull
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
BINARY := sahhar-io
DAEMON_PATH := /var/lib/local/sahhar-io
COPY_FOLDERS := public static
SERVICE_CONFIG := $(BINARY).service

#Preprocessing
$(FIRST_GOAL) :: 
	mkdir -p $(DAEMON_PATH)
	$(CC) get ./... 
	$(CC) mod tidy

build ::
	$(CC) test ./...
	$(CC) build -o $(BINARY)
	cp -r $(COPY_FOLDERS) $(BINARY) $(DAEMON_PATH)
	cp $(SERVICE_CONFIG) /etc/systemd/system/$(SERVICE_CONFIG)

install-redis ::
	cd lxc
	./init

reload :: disable build
	systemctl daemon-reload
	systemctl enable $(BINARY)
	systemctl start $(BINARY)

disable ::
	systemctl stop $(BINARY)
	systemctl disable $(BINARY)

tail ::
	journalctl -f -u $(BINARY)

$(LAST_GOAL) :: 
	rm -rf $(BINARY)

