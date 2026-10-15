# guard-agent-php Makefile, harmonized with the guard-agent (Python) family.
# This host has no php/composer binaries: every target falls back to the
# documented Docker runners (php:8.3-cli, composer:2) when the local
# binary is missing. Host Redis on 6379 is reachable from containers as
# host.docker.internal (see AGENTS.md). REDIS_HOST=0 skips the real-Redis
# integration leg (unit-only).

PHP_IMAGE ?= php:8.3-cli
COMPOSER_IMAGE ?= composer:2
REDIS_HOST ?= host.docker.internal
RUNNER = bin/test_agent.php

.PHONY: install test test-unit lint bump-version clean

install:
	@if command -v composer > /dev/null 2>&1; then \
		composer install --no-interaction --no-progress; \
	else \
		echo "composer not found locally, using $(COMPOSER_IMAGE)"; \
		docker run --rm -v "$$PWD":/app -w /app $(COMPOSER_IMAGE) composer install --no-interaction --no-progress; \
	fi

test:
	@if [ "$(REDIS_HOST)" = "0" ]; then \
		echo "REDIS_HOST=0: running unit-only (real-Redis integration skipped)"; \
	else \
		echo "Running full suite with REDIS_HOST=$(REDIS_HOST)"; \
	fi; \
	if command -v php > /dev/null 2>&1; then \
		REDIS_HOST="$(REDIS_HOST)" php $(RUNNER) && REDIS_HOST="$(REDIS_HOST)" php bin/test_shutdown.php; \
	else \
		echo "php not found locally, using $(PHP_IMAGE)"; \
		docker run --rm -v "$$PWD":/app -w /app -e REDIS_HOST=$(REDIS_HOST) $(PHP_IMAGE) php $(RUNNER); \
	fi

# Unit-only: skips the real-Redis integration leg (the fake-Redis handshake
# tests still run).
test-unit:
	@$(MAKE) test REDIS_HOST=0

lint:
	@if command -v php > /dev/null 2>&1; then \
		php_lint="php -l"; \
		composer_cmd="composer validate --strict"; \
	else \
		echo "php not found locally, using $(PHP_IMAGE)"; \
		php_lint="docker run --rm -v \"$$PWD\":/app -w /app $(PHP_IMAGE) php -l"; \
		composer_cmd="docker run --rm -v \"$$PWD\":/app -w /app $(COMPOSER_IMAGE) composer validate --strict"; \
	fi; \
	status=0; \
	for f in $$(find src bin -name '*.php'); do \
		$$php_lint "$$f" > /dev/null || status=1; \
	done; \
	if [ $$status -eq 0 ]; then echo "LINT_OK"; else echo "LINT_FAILED"; fi; \
	$$composer_cmd || status=1; \
	exit $$status

bump-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make bump-version VERSION=x.y.z"; \
		exit 1; \
	fi; \
	python3 .github/scripts/bump_version.py $(VERSION)

clean:
	@rm -rf vendor 2>/dev/null; \
	find . -name '*.cache' -delete 2>/dev/null; \
	echo "cleaned vendor/ and cache files"
