SHELL := /bin/bash

ROOT := $(CURDIR)
REPO := $(abspath $(ROOT)/../..)
PREFIX := $(if $(PALM_TOOLCHAIN_PREFIX),$(PALM_TOOLCHAIN_PREFIX),$(abspath $(REPO)/../palm-toolchain/.toolchain/prefix))
SDK := $(PREFIX)/palmdev/sdk/include
CC := $(PREFIX)/bin/m68k-none-elf-gcc
HOST_CC ?= cc
BUILD := $(ROOT)/build
PALM_OBJECT := $(BUILD)/palm/http.o
HOST_TEST := $(BUILD)/host/http_test
SDK_INCLUDES := -isystem$(SDK) -isystem$(SDK)/Core \
	-isystem$(SDK)/Core/Hardware -isystem$(SDK)/Core/System \
	-isystem$(SDK)/Core/UI -isystem$(SDK)/Dynamic -isystem$(SDK)/Libraries
PALM_FLAGS := -std=gnu17 -Wno-multichar -m68000 -mno-align-int -mpcrel -fpic \
	-fshort-enums -mshort -Wall -Wextra -Werror -Os -DPALMOS \
	-Iinclude $(SDK_INCLUDES)

.PHONY: test host-test palm-test clean

test: host-test palm-test

host-test: $(HOST_TEST)
	$(HOST_TEST)

palm-test: $(PALM_OBJECT)
	@echo "Compiled HTTP component for Palm OS"

$(BUILD)/host $(BUILD)/palm:
	@mkdir -p $@

$(HOST_TEST): tests/http_test.c src/http.c include/http.h \
		tests/palmos_shim/PalmOS.h | $(BUILD)/host
	$(HOST_CC) -std=c99 -Wall -Wextra -Werror \
		-Itests/palmos_shim -Iinclude tests/http_test.c src/http.c -o $@

$(PALM_OBJECT): src/http.c include/http.h | $(BUILD)/palm
	$(CC) $(PALM_FLAGS) -c src/http.c -o $@

clean:
	rm -rf $(BUILD)
