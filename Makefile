PYTHON ?= python3
SCION_ROOT ?= $(HOME)/scionproto-scion

SRC_ROOT := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
BUILD_DIR := $(SRC_ROOT)/build
PYTHONPATH := $(PYTHONPATH):$(SRC_ROOT)/python

TEST_DATA=$(addsuffix .bin,$(basename $(shell find tests -name '*.py')))

# Build library and examples

.PHONY: release
release:
	cmake --build build --config Release

.PHONY: debug
debug:
	cmake --build build --config Debug

# Run tests

.PHONY: test
test:
	TEST_BASE_PATH=$(realpath tests) "$(BUILD_DIR)/Debug/unit-tests"

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
test-data : $(TEST_DATA)

clean-test-data : $(TEST_DATA)
	rm $^

$(TEST_DATA): %.bin: %.py
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) $<
