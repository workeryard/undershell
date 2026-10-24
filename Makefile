# The commands this repo is worked with, so none has to be typed twice.
# `make` alone lists them.
#
#   make check                 typecheck, lint and tests
#   make matrix                every algorithm, key and login against OpenSSH and Dropbear in Docker
#   make routeros              MikroTik RouterOS 7 and 6 under QEMU
#   make consumer-check        typecheck the packed package as an installing Worker would
#   make deploy && make live   the live check from a deployed Worker

PORT ?= 8813
LIVE_URL   ?= https://undershell-probe.workeryard.workers.dev
TOKEN_FILE ?= .probe-token

.DEFAULT_GOAL := help
.PHONY: help install check test typecheck typecheck-workers lint format matrix consumer-check \
        routeros terminal-check blowfish dev deploy probe-token live clean

help: ## list the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

install: ## install the node dependencies
	pnpm install

# After typecheck-workers, which fetches the Workers types that the example
# in examples/terminal is linted against; on a fresh checkout, as in CI,
# lint would otherwise not know them.
check: typecheck-workers ## typecheck, lint and test, as before any commit
	pnpm check

test: ## the tests alone
	pnpm test

typecheck: ## tsc alone
	pnpm typecheck

lint: ## eslint alone
	pnpm lint

format: ## prettier over everything
	pnpm format

# A Worker compiles src/ against @cloudflare/workers-types, whose DOM-like
# types differ (TextEncoder hands back ArrayBufferLike; clearTimeout takes no
# undefined). The types are fetched once into .cache/ rather than depended on.
WORKERS_TYPES = .cache/workers-types/node_modules/@cloudflare/workers-types
typecheck-workers: ## typecheck src/ the way a Worker project compiles it
	@if [ ! -d $(WORKERS_TYPES) ]; then \
	  mkdir -p .cache/workers-types && cd .cache/workers-types && \
	  npm pack @cloudflare/workers-types --silent >/dev/null && \
	  mkdir -p node_modules/@cloudflare && tar -xzf cloudflare-workers-types-*.tgz && \
	  mv package node_modules/@cloudflare/workers-types && rm -f cloudflare-workers-types-*.tgz; \
	fi
	npx tsc -p tsconfig.workers.json
	npx tsc -p examples/terminal/tsconfig.json
	@echo "src/ typechecks under @cloudflare/workers-types $$(node -p "require('./$(WORKERS_TYPES)/package.json').version")"

consumer-check: typecheck-workers ## typecheck the packed package as an installing Worker project would
	@bash scripts/consumer-check.sh

# Needs Docker. Builds the three images, runs them on a private network,
# and removes them after; --keep leaves them up, --only <server> runs one.
matrix: ## the Docker matrix: OpenSSH latest and 8.2, Dropbear, a bastion
	pnpm -s tsx scripts/matrix.ts $(ARGS)

# Needs /dev/kvm: RouterOS's CHR image boots under QEMU. RouterOS 7 is
# checked to work, RouterOS 6 to be refused in words that say why.
routeros: ## MikroTik RouterOS 7 and 6, as the CHR image runs them
	pnpm -s tsx scripts/routeros.ts

# The browser terminal example, driven in Chromium. Needs the page running
# (cd examples/terminal && npx wrangler dev --port 8820) and a Chrome.
terminal-check: ## drive examples/terminal in Chromium [TERMINAL_URL= TERMINAL_TOKEN= CHROME=]
	pnpm -s tsx examples/terminal/check.ts

blowfish: ## regenerate Blowfish's constants from π
	pnpm -s tsx scripts/blowfish-constants.ts

dev: ## the probe Worker locally; it cannot show the platform's socket limits
	npx wrangler dev --port $(PORT)

deploy: ## deploy the probe Worker; every endpoint demands the PROBE_TOKEN secret
	npx wrangler whoami
	npx wrangler deploy

probe-token: ## make a new token, keep it in .probe-token, and set it as the Worker's secret
	@(umask 077; openssl rand -hex 32 > $(TOKEN_FILE))
	npx wrangler secret put PROBE_TOKEN < $(TOKEN_FILE)

live: ## the live check against the deployed probe Worker
	PROBE_URL=$(LIVE_URL) PROBE_TOKEN=$$(cat $(TOKEN_FILE)) pnpm -s tsx scripts/live.ts

clean: ## remove caches and the matrix's leftovers
	rm -rf .wrangler .cache/matrix
