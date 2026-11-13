ROOT := $(abspath ../..)
PALM_TOOLCHAIN_ROOT ?= $(ROOT)/../palm-toolchain
PALM_TOOLCHAIN_PREFIX ?= $(PALM_TOOLCHAIN_ROOT)/.toolchain/prefix
BIN := $(PALM_TOOLCHAIN_PREFIX)/bin
SDK := $(PALM_TOOLCHAIN_PREFIX)/palmdev/sdk/include
BUILD := build
CC := $(BIN)/m68k-none-elf-gcc
ABI := -m68000 -mno-align-int -mpcrel -fpic -fshort-enums -mshort
CFLAGS := $(ABI) -std=gnu17 -Os -Wall -Wextra -Wno-multichar -Wno-old-style-declaration \
	-ffunction-sections -fdata-sections -isystem$(SDK) -isystem$(SDK)/Core \
	-isystem$(SDK)/Core/System -isystem$(SDK)/Core/UI \
	-isystem$(SDK)/Core/Hardware -isystem$(SDK)/Dynamic -isystem$(SDK)/Libraries
OBJECTS := $(BUILD)/main.o $(BUILD)/startup.o
LINKER := ../tls-tester/toolchain/linker.lkr
LDFLAGS := $(ABI) -nostartfiles -Wl,--gc-sections -Wl,-T,$(LINKER)

.PHONY: all test
all: $(BUILD)/PalmRandomProbe.prc

$(BUILD):
	mkdir -p $@

$(BUILD)/main.o: main.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/startup.o: ../tls-tester/src/startup.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/probe.elf: $(OBJECTS) $(LINKER)
	$(CC) $(LDFLAGS) -Wl,--emit-relocs $(OBJECTS) -o $@.stage1
	node $(PALM_TOOLCHAIN_ROOT)/tools/generate-m68k-relocs.mjs $@.stage1 \
		$(BUILD)/reloc.s $(BIN)/m68k-none-elf-readelf
	$(CC) $(ABI) -c $(BUILD)/reloc.s -o $(BUILD)/reloc.o
	$(CC) $(LDFLAGS) $(OBJECTS) $(BUILD)/reloc.o -o $@
	rm -f $@.stage1

$(BUILD)/code0001.bin: $(BUILD)/probe.elf
	$(BIN)/m68k-none-elf-objcopy -O binary -j .vec -j .text $< $@

$(BUILD)/PalmRandomProbe.prc: $(BUILD)/code0001.bin app.rcp
	cd $(BUILD) && $(abspath $(BIN))/pilrc -ro -o probe.ro -creator PtRP \
		-type appl -name 'Palm Random Probe' ../app.rcp
	$(BIN)/build-prc --no-check -o $@ -n 'Palm Random Probe' -c PtRP -t appl $(BUILD)/probe.ro

test: all
	node $(PALM_TOOLCHAIN_ROOT)/tools/validate-prc.mjs \
		$(BUILD)/PalmRandomProbe.prc 'Palm Random Probe' appl PtRP
