# FileSigner Makefile (wraps CMake)

BUILD_DIR = build
CONFIG = Release

.PHONY: all configure build clean install help

all: build

configure:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(CONFIG)

build: configure
	cmake --build $(BUILD_DIR) --config $(CONFIG)

clean:
	cmake --build $(BUILD_DIR) --config $(CONFIG) --clean-first 2>/dev/null || rm -rf $(BUILD_DIR)

install: build
	cmake --install $(BUILD_DIR) --config $(CONFIG)

help:
	@echo "Targets:"
	@echo "  all/build   - Build the project"
	@echo "  configure   - Run CMake configure"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install to system"
	@echo ""
	@echo "Variables:"
	@echo "  CONFIG=Debug|Release  (default: Release)"
