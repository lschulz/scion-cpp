PYTHON ?= python3
PANDOC ?= pandoc
SCION_ROOT ?= $(HOME)/scionproto-scion

SRC_ROOT := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR := $(SRC_ROOT)/build
PKG_DIR := $(SRC_ROOT)/out
PYTHONPATH := $(PYTHONPATH):$(SRC_ROOT)/python

DOCKER_TAG := 0.0.1
HOST_UID := $(shell id -u):$(shell id -g)

TEST_DATA=$(addsuffix .bin,$(basename $(shell find tests scitra/tests -name '*.py')))
MAN_PAGES=$(addsuffix .gz,$(basename $(shell find scitra interposer -name '*.*.md')))


# Build library and examples

.PHONY: release-shared
release-shared:
	@mkdir -p "$(BUILD_DIR)"
	cmake -G 'Ninja Multi-Config' -DBUILD_SHARED_LIBS=ON -B build
	cmake --build "$(BUILD_DIR)" --config Release

.PHONY: release
release:
	cmake --build "$(BUILD_DIR)" --config Release

.PHONY: debug
debug:
	cmake --build "$(BUILD_DIR)" --config Debug

# Run tests

.PHONY: test
test:
	TEST_BASE_PATH=$(realpath tests) "$(BUILD_DIR)/Debug/unit-tests"

.PHONY: test-scitra
test-scitra:
	TEST_BASE_PATH=$(realpath scitra/tests) "$(BUILD_DIR)/scitra/Debug/scitra-tests"

.PHONY: test-interposer
test-interposer:
	SCION_CONFIG="$(SRC_ROOT)/interposer/integration/config/scion_interposer.toml" \
	"$(BUILD_DIR)/interposer/Debug/interposer-tests"

# Integration tests

.PHONY: test-integration
test-integration:
	$(PYTHON) integration-tests/all_tests.py -b "$(BUILD_DIR)" -s "$(SCION_ROOT)"

# Make test data

.PHONY: test-data clean-test-data
test-data: $(TEST_DATA)

clean-test-data: $(TEST_DATA)
	rm $^

$(TEST_DATA): %.bin: %.py
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) $<

# Manual Pages

.PHONY: man clean-man
man: $(MAN_PAGES)

$(MAN_PAGES): %.gz: %.md
	$(PANDOC) --standalone --to man $< | gzip > $@

clean-man: $(MAN_PAGES)
	rm $^

# Debian Packages

.PHONY: deb
deb: release man
	@mkdir -p "$(PKG_DIR)"
	cd "$(PKG_DIR)" && cpack -G DEB --config "$(BUILD_DIR)/CPackConfig.cmake"

# Docker build

.PHONY: deb-docker
deb-docker: man
	@mkdir -p "$(PKG_DIR)"
	docker build -t scion-cpp-builder:$(DOCKER_TAG) "$(SRC_ROOT)/docker/package"
	docker run -e HOST_UID=$(HOST_UID) -v "$(SRC_ROOT)":/scion-cpp:ro -v "$(PKG_DIR)":/out --rm \
		scion-cpp-builder:$(DOCKER_TAG)
