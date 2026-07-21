SHELL := /bin/bash

include app.mk

ROOT := $(CURDIR)
REPO := $(abspath $(ROOT)/../..)
TOOLCHAIN_ROOT := $(if $(PALM_TOOLCHAIN_ROOT),$(PALM_TOOLCHAIN_ROOT),$(abspath $(REPO)/../palm-toolchain))
PREFIX := $(if $(PALM_TOOLCHAIN_PREFIX),$(PALM_TOOLCHAIN_PREFIX),$(TOOLCHAIN_ROOT)/.toolchain/prefix)
SDK := $(PREFIX)/palmdev/sdk-5r3/include
TLS_LIB := $(REPO)/libs/palm-tls
HTTP_LIB := $(REPO)/libs/palm-http
CC := $(PREFIX)/bin/m68k-none-elf-gcc
OBJCOPY := $(PREFIX)/bin/m68k-none-elf-objcopy
SIZE := $(PREFIX)/bin/m68k-none-elf-size
PILRC := $(PREFIX)/bin/pilrc
BUILD_PRC := $(PREFIX)/bin/build-prc
PROFILE ?= debug
STARTUP_SELF_TEST ?= 0
HOST_CC ?= cc
MAGICK ?= magick
BUILD_DIR := $(ROOT)/build/$(PROFILE)
ELF := $(BUILD_DIR)/code0001.68k.elf
CODE := $(BUILD_DIR)/code0001.bin
PRC := $(BUILD_DIR)/$(APP_ID).prc
BASE_RO := $(BUILD_DIR)/$(APP_ID)-base.ro
MAP := $(BUILD_DIR)/$(APP_ID).map
OBJECTS := $(BUILD_DIR)/main.o $(BUILD_DIR)/download_store.o \
	$(BUILD_DIR)/download_client.o \
	$(BUILD_DIR)/startup.o
DEPS := $(OBJECTS:.o=.d)
HOST_TEST := $(ROOT)/build/host/http_download_test
SDK_INCLUDES := -isystem$(SDK) -isystem$(SDK)/Core -isystem$(SDK)/Core/Hardware \
	-isystem$(SDK)/Core/System -isystem$(SDK)/Core/UI -isystem$(SDK)/Dynamic \
	-isystem$(SDK)/Libraries -isystem$(SDK)/Libraries/PalmOSGlue
ABI_FLAGS := -Wno-multichar -m68000 -mno-align-int -mpcrel -fpic -fshort-enums -mshort
WARN_FLAGS := -Wall -Wextra -Wsign-compare -Wno-unused-parameter -Wno-old-style-declaration
COMMON_FLAGS := $(ABI_FLAGS) $(WARN_FLAGS) -MMD -MP -ffunction-sections -fdata-sections \
	-DPALMOS -I$(ROOT)/src -I$(ROOT)/resources -I$(BUILD_DIR) \
	-I$(TLS_LIB)/include -I$(HTTP_LIB)/include $(SDK_INCLUDES)
PROFILE_FLAGS := $(if $(filter release,$(PROFILE)),-Os,-O1 -g -ggdb)
LDFLAGS := $(ABI_FLAGS) $(PROFILE_FLAGS) -nostartfiles -Wl,--gc-sections \
	-Wl,-T,$(ROOT)/toolchain/linker.lkr -Wl,-Map,$(MAP)

.PHONY: all library debug release benchmark test test-prc clean

all: debug
library:
	@$(MAKE) -C $(REPO) bootstrap
	@$(MAKE) -C $(TLS_LIB) TLS_PROFILE=full test-prc
	@$(MAKE) -C $(HTTP_LIB) test
debug: library
	@$(MAKE) PROFILE=debug $(ROOT)/build/debug/$(APP_ID).prc
release: library
	@$(MAKE) PROFILE=release $(ROOT)/build/release/$(APP_ID).prc
benchmark: library
	@$(MAKE) PROFILE=benchmark STARTUP_SELF_TEST=1 \
		$(ROOT)/build/benchmark/$(APP_ID).prc

$(BUILD_DIR):
	@mkdir -p $@
$(BUILD_DIR)/%.o: src/%.c app.mk | $(BUILD_DIR)
	$(CC) $(COMMON_FLAGS) $(PROFILE_FLAGS) -DAPP_VERSION='"$(APP_VERSION)"' \
		-DMIN_OS_MAJOR=$(MIN_OS_MAJOR) -DMIN_OS_MINOR=$(MIN_OS_MINOR) \
		-DPALM_TLS_STARTUP_SELF_TEST=$(STARTUP_SELF_TEST) -c $< -o $@

$(ELF): $(OBJECTS) toolchain/linker.lkr
	$(CC) -o $@.stage1 $(LDFLAGS) -Wl,--emit-relocs $(OBJECTS)
	node $(TOOLCHAIN_ROOT)/tools/generate-m68k-relocs.mjs $@.stage1 $(BUILD_DIR)/reloc_offsets.s $(PREFIX)/bin/m68k-none-elf-readelf
	$(CC) $(ABI_FLAGS) -c $(BUILD_DIR)/reloc_offsets.s -o $(BUILD_DIR)/reloc_offsets.o
	$(CC) -o $@ $(LDFLAGS) -Wl,--emit-relocs $(OBJECTS) $(BUILD_DIR)/reloc_offsets.o
	rm -f $@.stage1
$(CODE): $(ELF)
	$(OBJCOPY) -O binary $< $@ -j .vec -j .text

$(BUILD_DIR)/icon-mono.bmp: resources/icon.svg | $(BUILD_DIR)
	@command -v $(MAGICK) >/dev/null || { echo "ImageMagick is required; run brew bundle." >&2; exit 1; }
	$(MAGICK) resources/icon.svg -transparent '#ff00ff' -background white -alpha remove \
		-colorspace gray -threshold 55% -type bilevel -compress none BMP3:$@
$(BUILD_DIR)/icon-color.bmp: resources/icon.svg | $(BUILD_DIR)
	@command -v $(MAGICK) >/dev/null || { echo "ImageMagick is required; run brew bundle." >&2; exit 1; }
	$(MAGICK) resources/icon.svg -background '#ff00ff' -alpha remove -colors 256 \
		-compress none BMP3:$@

$(PRC): $(CODE) $(BUILD_DIR)/icon-mono.bmp $(BUILD_DIR)/icon-color.bmp resources/app.rcp resources/resource.h \
	certs/gts-wr2.der certs/gts-we1.der certs/letsencrypt-yr2.der app.mk
	cd $(BUILD_DIR) && $(PILRC) -ro -o $(BASE_RO) -creator $(APP_CREATOR) \
		-type $(APP_TYPE) -name '$(APP_NAME)' -I $(ROOT)/resources $(ROOT)/resources/app.rcp
	$(BUILD_PRC) --no-check -o $(PRC) -n '$(APP_NAME)' -c $(APP_CREATOR) \
		-t $(APP_TYPE) $(BASE_RO)
	$(SIZE) $(ELF)
	@echo "Built $(PRC)"

test-prc: debug
	node $(TOOLCHAIN_ROOT)/tools/validate-prc.mjs $(PRC) '$(APP_NAME)' $(APP_TYPE) $(APP_CREATOR)
$(HOST_TEST): tests/http_download_test.c $(HTTP_LIB)/src/http_core.c \
		$(HTTP_LIB)/src/http_core.h $(HTTP_LIB)/include/palm_http.h
	@mkdir -p $(dir $@)
	$(HOST_CC) -std=c99 -Wall -Wextra -Werror \
		-Itests/palmos_shim -I$(HTTP_LIB)/src -I$(HTTP_LIB)/include \
		tests/http_download_test.c \
		$(HTTP_LIB)/src/http_core.c -o $@

test: test-prc $(HOST_TEST)
	$(HOST_TEST)

clean:
	rm -rf build

-include $(DEPS)
