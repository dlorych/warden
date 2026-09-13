SHELL := /bin/sh
COMPOSE := docker compose --env-file .dev/compose.env -f compose.yaml

.PHONY: dev devinit up down logs demo-request test web-build cli-build config

devinit:
	@./devinit

dev: devinit
	@$(COMPOSE) up -d --build
	@i=0; while [ $$i -lt 60 ]; do if curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; then echo "Warden is ready: http://localhost:8080"; exit 0; fi; i=$$(($$i + 1)); sleep 2; done; $(COMPOSE) ps; exit 1

up: dev

down:
	@$(COMPOSE) down

logs:
	@$(COMPOSE) logs -f --tail=100

demo-request:
	@response=$$(curl -fsS -X POST http://localhost:8090/mock/requests -H 'Content-Type: application/json' -d '{"repository":"acme/example","environment":"production","commit_sha":"0123456789abcdef0123456789abcdef01234567","requester":"requester@example.test","reason":"Demo approval"}'); echo "$$response"; id=$$(printf '%s' "$$response" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'); test -n "$$id"; echo "Review: http://localhost:8080/requests/$$id"

web-build:
	@node -e "require('node:fs').rmSync('web/node_modules', { recursive: true, force: true })"
	@npm --prefix web ci --ignore-scripts --no-audit --no-fund
	@npm --prefix web run build

cli-build:
	@mkdir -p bin
	@go build -o bin/warden ./cmd/warden

test: devinit web-build
	@go test ./...
	@$(COMPOSE) config --quiet

config: devinit
	@$(COMPOSE) config
