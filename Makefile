PORT ?= /dev/ttyUSB0
BUILDDIR ?= build
IDF_PATH ?= $(shell pwd)/esp-idf
IDF_BRANCH ?= master
IDF_EXPORT_QUIET ?= 0
SHELL := /usr/bin/env bash

# General targets

.PHONY: all
all: build flash

.PHONY: install
install: flash

# Preparation

.PHONY: prepare
prepare: submodules sdk

.PHONY: submodules
submodules:
	git submodule update --init --recursive

.PHONY: sdk
sdk:
	rm -rf "$(IDF_PATH)"
	git clone --recursive --branch "$(IDF_BRANCH)" https://github.com/espressif/esp-idf.git
	cd "$(IDF_PATH)"; bash install.sh all
	source "$(IDF_PATH)/export.sh" && idf.py --preview set-target esp32c6

.PHONY: menuconfig
menuconfig:
	source "$(IDF_PATH)/export.sh" && idf.py menuconfig

# Cleaning

.PHONY: clean
clean:
	rm -rf "$(BUILDDIR)"

.PHONY: fullclean
fullclean:
	source "$(IDF_PATH)/export.sh" && idf.py fullclean

# Building

.PHONY: build
build:
	source "$(IDF_PATH)/export.sh" && idf.py build

.PHONY: image
image:
	cd "$(BUILDDIR)"; dd if=/dev/zero bs=1M count=16 of=flash.bin
	cd "$(BUILDDIR)"; dd if=bootloader/bootloader.bin bs=1 seek=4096 of=flash.bin conv=notrunc
	cd "$(BUILDDIR)"; dd if=partition_table/partition-table.bin bs=1 seek=36864 of=flash.bin conv=notrunc
	cd "$(BUILDDIR)"; dd if=main.bin bs=1 seek=65536 of=flash.bin conv=notrunc

# Hardware

.PHONY: flash
flash: build
	source "$(IDF_PATH)/export.sh" && idf.py flash -p $(PORT)

.PHONY: erase
erase:
	source "$(IDF_PATH)/export.sh" && idf.py erase-flash -p $(PORT)

.PHONY: monitor
monitor:
	source "$(IDF_PATH)/export.sh" && idf.py monitor -p $(PORT)

# Emulation

.PHONY: qemu
qemu: image
	cd "$(BUILDDIR)"; qemu-system-xtensa -nographic -machine esp32 -drive 'file=flash.bin,if=mtd,format=raw'

# Tools

.PHONY: size
size:
	source "$(IDF_PATH)/export.sh" && idf.py size

.PHONY: size-components
size-components:
	source "$(IDF_PATH)/export.sh" && idf.py size-components

.PHONY: size-files
size-files:
	source "$(IDF_PATH)/export.sh" && idf.py size-files

# Formatting

.PHONY: format
format:
	find main/ -iname '*.h' -o -iname '*.c' -o -iname '*.cpp' | xargs clang-format -i
