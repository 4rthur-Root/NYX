.PHONY: help build run run-workday run-web run-samba run-auth run-local shell clean

IMAGE_NAME := nyxsoc-traffic

# Auto-detect container engine: docker first, then podman
CONTAINER_ENGINE ?= $(shell command -v docker 2>/dev/null || command -v podman 2>/dev/null)

ifeq ($(CONTAINER_ENGINE),)
$(error No container engine found. Install docker or podman.)
endif

help:
	@echo "NyxSOC Traffic Generator — Makefile"
	@echo ""
	@echo "Container engine: $(CONTAINER_ENGINE)"
	@echo ""
	@echo "Targets:"
	@echo "  make build            Build the container image ($(IMAGE_NAME))"
	@echo "  make run              Build & Run traffic generator (all modes, standard jitter)"
	@echo "  make run-workday      Build & Run traffic generator (forced daytime density)"
	@echo "  make run-web          Build & Run Web simulator only"
	@echo "  make run-samba        Build & Run Samba simulator only"
	@echo "  make run-auth         Build & Run Auth simulator only"
	@echo "  make run-local        Run locally without container"
	@echo "  make shell            Open an interactive shell in the container"
	@echo "  make clean            Remove Python caches"

build:
	@echo "=> Building image $(IMAGE_NAME) with $(CONTAINER_ENGINE)..."
	$(CONTAINER_ENGINE) build -t $(IMAGE_NAME) -f Dockerfile .

run: build
	@echo "=> Running traffic generator (mode: all)..."
	$(CONTAINER_ENGINE) run --rm -it --network host $(IMAGE_NAME) python3 -m traffic.orchestrator --mode all

run-workday: build
	@echo "=> Running traffic generator (mode: all, forced workday density)..."
	$(CONTAINER_ENGINE) run --rm -it --network host $(IMAGE_NAME) python3 -m traffic.orchestrator --mode all --force-workday

run-web: build
	@echo "=> Running Web traffic simulator..."
	$(CONTAINER_ENGINE) run --rm -it --network host $(IMAGE_NAME) python3 -m traffic.orchestrator --mode web

run-samba: build
	@echo "=> Running Samba traffic simulator..."
	$(CONTAINER_ENGINE) run --rm -it --network host $(IMAGE_NAME) python3 -m traffic.orchestrator --mode samba

run-auth: build
	@echo "=> Running Auth traffic simulator..."
	$(CONTAINER_ENGINE) run --rm -it --network host $(IMAGE_NAME) python3 -m traffic.orchestrator --mode auth

run-local:
	@echo "=> Running traffic generator locally..."
	PYTHONPATH=.. python3 -m traffic.orchestrator --mode all

shell: build
	@echo "=> Opening interactive shell in $(IMAGE_NAME)..."
	$(CONTAINER_ENGINE) run --rm -it --network host $(IMAGE_NAME) /bin/bash

clean:
	rm -rf __pycache__ 
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
