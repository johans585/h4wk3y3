# h4wk3y3 container — make helpers
.PHONY: help build up down ps logs shell scan scan-fast update-templates rebuild clean purge tunnel
.DEFAULT_GOAL := help

help:
	@echo "h4wk3y3 container — targets:"
	@echo "  make build               Bootstrap .env/volumes + build image"
	@echo "  make up                  Start postgres + dashboard (127.0.0.1:8000)"
	@echo "  make down                Stop containers"
	@echo "  make ps                  Container status"
	@echo "  make logs                Follow app logs"
	@echo "  make shell               Bash inside the running container"
	@echo "  make scan T=example.com  One-shot full scan"
	@echo "  make scan-fast T=...      Fast scan (m01..m05,m09)"
	@echo "  make update-templates    Refresh nuclei templates"
	@echo "  make rebuild             Force rebuild (no cache)"
	@echo "  make clean               Stop + remove containers (keep volumes)"
	@echo "  make purge               Stop + remove containers AND volumes (DATA LOSS)"
	@echo "  make tunnel              Print the SSH tunnel command for the dashboard"

build:
	./build.sh

up:
	docker compose up -d
	@echo "Dashboard (loopback): http://127.0.0.1:$$(grep -E '^H4_DASHBOARD_PORT=' .env 2>/dev/null | cut -d= -f2 || echo 8000)"
	@echo "From your laptop:  ssh -L 8000:127.0.0.1:8000 <user>@<this-host>  then open http://localhost:8000"

down:
	docker compose down

ps:
	docker compose ps

logs:
	docker compose logs -f h4wk3y3

shell:
	docker compose exec h4wk3y3 /bin/bash

scan:
	@test -n "$(T)" || (echo "Usage: make scan T=example.com"; exit 1)
	docker compose run --rm scan scan $(T) --full

scan-fast:
	@test -n "$(T)" || (echo "Usage: make scan-fast T=example.com"; exit 1)
	docker compose run --rm scan scan $(T) --fast

update-templates:
	docker compose run --rm h4wk3y3 update-templates

rebuild:
	DOCKER_BUILDKIT=1 docker compose build --no-cache

clean:
	docker compose down

purge:
	docker compose down -v

tunnel:
	@echo "ssh -L 8000:127.0.0.1:$$(grep -E '^H4_DASHBOARD_PORT=' .env 2>/dev/null | cut -d= -f2 || echo 8000) <user>@<this-host>"
