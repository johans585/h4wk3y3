# Argus container — make helpers
.PHONY: build up down logs shell scan update-templates clean rebuild ps

# Default goal
.DEFAULT_GOAL := help

help:
	@echo "Argus container — targets:"
	@echo "  make build              Build image (kalilinux/kali-rolling base)"
	@echo "  make up                 Start dashboard (http://localhost:8000)"
	@echo "  make down               Stop dashboard"
	@echo "  make ps                 Show container status"
	@echo "  make logs               Follow dashboard logs"
	@echo "  make shell              Open bash inside running container"
	@echo "  make scan T=example.com Run a one-shot scan (full)"
	@echo "  make scan-fast T=...    Fast scan (m1-m4)"
	@echo "  make update-templates   Refresh nuclei templates"
	@echo "  make rebuild            Force rebuild without cache"
	@echo "  make clean              Stop + remove containers (keeps volumes)"
	@echo "  make purge              Stop + remove containers AND volumes (data loss!)"

build:
	./build.sh

up:
	docker compose up -d
	@echo "Dashboard: http://localhost:$$(grep -E '^ARGUS_DASHBOARD_PORT=' .env 2>/dev/null | cut -d= -f2 || echo 8000)"

down:
	docker compose down

ps:
	docker compose ps

logs:
	docker compose logs -f argus

shell:
	docker compose exec argus /bin/bash

scan:
	@test -n "$(T)" || (echo "Usage: make scan T=example.com"; exit 1)
	docker compose run --rm scan scan $(T) --full

scan-fast:
	@test -n "$(T)" || (echo "Usage: make scan-fast T=example.com"; exit 1)
	docker compose run --rm scan scan $(T) --fast

update-templates:
	docker compose run --rm argus update-templates

rebuild:
	DOCKER_BUILDKIT=1 docker compose build --no-cache

clean:
	docker compose down

purge:
	docker compose down -v
