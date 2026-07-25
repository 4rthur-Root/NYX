.PHONY: help build test test-unit test-parsers lint typecheck shell clean

IMAGE_NAME := nyxsoc-engine

# Auto-detect container engine: docker first, then podman
CONTAINER_ENGINE ?= $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)

ifeq ($(CONTAINER_ENGINE),)
$(error No container engine found. Install docker or podman.)
endif

help:
	@echo "NyxSOC Engine — Makefile"
	@echo ""
	@echo "Container engine: $(CONTAINER_ENGINE)"
	@echo ""
	@echo "Targets:"
	@echo "  make build           Build the test image"
	@echo "  make test            Run all tests"
	@echo "  make test-unit       Run unit tests"
	@echo "  make test-parsers    Run parser tests"
	@echo "  make lint            Run flake8"
	@echo "  make typecheck       Run mypy --strict"
	@echo "  make shell           Open a shell in the test container"
	@echo "  make clean           Remove caches"

build:
	@echo "=> Building image $(IMAGE_NAME) with $(CONTAINER_ENGINE)..."
	$(CONTAINER_ENGINE) build -t $(IMAGE_NAME) -f Dockerfile .

test: build
	@echo "=> Running all tests..."
	$(CONTAINER_ENGINE) run --rm $(IMAGE_NAME) pytest tests/ -v

test-unit: build
	@echo "=> Running unit tests..."
	$(CONTAINER_ENGINE) run --rm $(IMAGE_NAME) pytest tests/unit/ -v

test-parsers: build
	@echo "=> Running parser tests..."
	$(CONTAINER_ENGINE) run --rm $(IMAGE_NAME) pytest tests/unit/test_syslog_parser.py tests/unit/test_filterlog_parser.py tests/unit/test_windows_parser.py tests/unit/test_web_parser.py -v

lint: build
	@echo "=> Running flake8..."
	$(CONTAINER_ENGINE) run --rm $(IMAGE_NAME) flake8 . tests/

typecheck: build
	@echo "=> Running mypy --strict..."
	$(CONTAINER_ENGINE) run --rm $(IMAGE_NAME) mypy --strict .

shell: build
	@echo "=> Opening shell in $(IMAGE_NAME)..."
	$(CONTAINER_ENGINE) run --rm -it $(IMAGE_NAME) /bin/bash

clean:
	rm -rf .pytest_cache __pycache__ .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
