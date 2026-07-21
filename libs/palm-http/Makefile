SHELL := /bin/bash
include app.mk

ROOT := $(CURDIR)
REPO := $(abspath $(ROOT)/../..)
PREFIX := $(if $(PALM_TOOLCHAIN_PREFIX),$(PALM_TOOLCHAIN_PREFIX),$(abspath $(REPO)/../palm-toolchain/.toolchain/prefix))
SDK := $(PREFIX)/palmdev/sdk-5r3/include
CC := $(PREFIX)/bin/m68k-none-elf-gcc
OBJCOPY := $(PREFIX)/bin/m68k-none-elf-objcopy
SIZE := $(PREFIX)/bin/m68k-none-elf-size
PILRC := $(PREFIX)/bin/pilrc
BUILD_PRC := $(PREFIX)/bin/build-prc
STUBGEN := $(PREFIX)/bin/m68k-palmos-stubgen
BUILD := $(ROOT)/build
GENERATED := $(BUILD)/generated
PALM_BUILD := $(BUILD)/palm
DISPATCH := $(GENERATED)/library-dispatch.s
ELF := $(PALM_BUILD)/library.elf
CODE := $(PALM_BUILD)/library.bin
BASE_RO := $(PALM_BUILD)/$(LIB_ID)-base.ro
PRC := $(PALM_BUILD)/$(LIB_ID).prc
OBJECTS := $(PALM_BUILD)/palm_library.o $(PALM_BUILD)/http_download.o \
	$(PALM_BUILD)/dispatch.o
SDK_INCLUDES := -isystem$(SDK) -isystem$(SDK)/Core \
	-isystem$(SDK)/Core/Hardware -isystem$(SDK)/Core/System \
	-isystem$(SDK)/Core/UI -isystem$(SDK)/Dynamic -isystem$(SDK)/Libraries
ABI_FLAGS := -Wno-multichar -m68000 -mno-align-int -mpcrel -fpic \
	-fshort-enums -mshort
CFLAGS := $(ABI_FLAGS) -Wall -Wextra -Wsign-compare -Os \
	-ffunction-sections -fdata-sections -DPALMOS -DPALM_HTTP_LIB_BUILD \
	-Iinclude -Isrc $(SDK_INCLUDES)
LDFLAGS := $(ABI_FLAGS) -Os -nostartfiles -Wl,--gc-sections \
	-Wl,-T,toolchain/linker.lkr

.PHONY: all test test-prc clean
all: test-prc

$(GENERATED) $(PALM_BUILD):
	@mkdir -p $@
$(DISPATCH): library.def | $(GENERATED)
	$(STUBGEN) -b $(GENERATED)/library library.def
$(PALM_BUILD)/palm_library.o: src/palm_library.c include/palm_http.h | $(PALM_BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(PALM_BUILD)/http_download.o: src/http_core.c src/http_core.h \
		include/palm_http.h | $(PALM_BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(PALM_BUILD)/dispatch.o: $(DISPATCH) | $(PALM_BUILD)
	$(CC) $(ABI_FLAGS) -c $< -o $@
$(ELF): $(OBJECTS) toolchain/linker.lkr
	$(CC) -o $@ $(LDFLAGS) -Wl,-Map,$(PALM_BUILD)/$(LIB_ID).map $(OBJECTS)
$(CODE): $(ELF)
	$(OBJCOPY) -O binary $< $@ -j .text
	@test "$$(stat -f %z $@)" -lt 65000
$(PRC): $(CODE) resources/library.rcp app.mk
	cd $(PALM_BUILD) && $(PILRC) -ro -o $(BASE_RO) -creator $(LIB_CREATOR) \
		-type $(LIB_TYPE) -name '$(LIB_NAME)' $(ROOT)/resources/library.rcp
	$(BUILD_PRC) --no-check -o $@ -n '$(LIB_NAME)' -c $(LIB_CREATOR) \
		-t $(LIB_TYPE) $(BASE_RO)
	$(SIZE) $(ELF)
	@echo "Built $@"
test-prc: $(PRC)
	node tools/validate_library.mjs $(PRC)
test: test-prc
clean:
	rm -rf build
