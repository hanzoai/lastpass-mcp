SHELL := /bin/bash
PKG_CONFIG ?= pkg-config
CMAKE ?= cmake
NPM ?= npm

C_DEPS := libcurl openssl libxml-2.0

.PHONY: all build build-c build-ts test clean

all: build

build-c:
	@if command -v $(PKG_CONFIG) >/dev/null 2>&1 && $(PKG_CONFIG) --exists $(C_DEPS) && command -v $(CMAKE) >/dev/null 2>&1; then \
		echo "==> Building upstream lastpass-cli (c-cli) -> bin/lpass"; \
		$(CMAKE) -S c-cli -B c-cli/build -DCMAKE_BUILD_TYPE=Release >/dev/null; \
		$(CMAKE) --build c-cli/build --target lpass -j4; \
		mkdir -p bin; \
		cp c-cli/build/lpass bin/lpass; \
		chmod +x bin/lpass; \
		echo "==> Built bin/lpass ($$(bin/lpass --version))"; \
	else \
		echo "==> Skipping optional C build (missing cmake or pkg-config headers for: $(C_DEPS)); pure Node/TS vault-protocol remains active."; \
	fi

build-ts:
	$(NPM) run build

build: build-c build-ts

test:
	$(NPM) test

clean:
	rm -rf bin dist c-cli/build c-cli/version.h
