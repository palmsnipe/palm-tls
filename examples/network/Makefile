SHELL := /bin/bash
ROOT := $(abspath ../..)
PREFIX := $(if $(PALM_TOOLCHAIN_PREFIX),$(PALM_TOOLCHAIN_PREFIX),$(abspath $(ROOT)/../palm-toolchain/.toolchain/prefix))
SDK := $(PREFIX)/palmdev/sdk-5r3/include
CC := $(PREFIX)/bin/m68k-none-elf-gcc
BUILD := build
SOURCES := library_lifecycle.c cooperative_tls.c http_stream.c
OBJECTS := $(SOURCES:%.c=$(BUILD)/%.o)
SDK_INCLUDES := -isystem$(SDK) -isystem$(SDK)/Core \
	-isystem$(SDK)/Core/Hardware -isystem$(SDK)/Core/System \
	-isystem$(SDK)/Core/UI -isystem$(SDK)/Dynamic -isystem$(SDK)/Libraries \
	-isystem$(SDK)/Extensions
CFLAGS := -Wno-multichar -m68000 -mno-align-int -mpcrel -fpic \
	-fshort-enums -mshort -Wall -Wextra -Werror -Os -DPALMOS \
	-I$(ROOT)/libs/palm-tls/include -I$(ROOT)/libs/palm-http/include \
	$(SDK_INCLUDES)

.PHONY: test clean
test: $(OBJECTS)
	@echo "Compiled PalmTLS and PalmHTTP integration examples"
$(BUILD):
	@mkdir -p $@
$(BUILD)/%.o: %.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -rf $(BUILD)
