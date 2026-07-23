SHELL := /bin/bash

include app.mk

ROOT := $(CURDIR)
REPO := $(abspath $(ROOT)/..)
PREFIX := $(if $(PALM_TOOLCHAIN_PREFIX),$(PALM_TOOLCHAIN_PREFIX),$(abspath $(REPO)/../palm-toolchain/.toolchain/prefix))
DEPS_PREFIX := $(if $(PALM_TLS_DEPS_PREFIX),$(PALM_TLS_DEPS_PREFIX),$(REPO)/.palm-tls/prefix)
SDK := $(PREFIX)/palmdev/sdk/include
WOLFSSL_SETTINGS := $(REPO)/wolfssl/user_settings.h
CC := $(PREFIX)/bin/m68k-none-elf-gcc
ARM_CC ?= clang
ARM_CPU_FLAGS ?= -mcpu=arm926ej-s
ARM_OPT_FLAGS ?= -Os
HOST_CC ?= cc
OBJCOPY := $(PREFIX)/bin/m68k-none-elf-objcopy
SIZE := $(PREFIX)/bin/m68k-none-elf-size
PILRC := $(PREFIX)/bin/pilrc
BUILD_PRC := $(PREFIX)/bin/build-prc
STUBGEN := $(PREFIX)/bin/m68k-palmos-stubgen
BUILD := $(ROOT)/build
GENERATED := $(BUILD)/generated
PALM_BUILD := $(BUILD)/palm
PALM_68K_BUILD := $(PALM_BUILD)/68k
PALM_ARM_BUILD := $(PALM_BUILD)/arm
DISPATCH := $(GENERATED)/library-dispatch.s
ELF_11_68K := $(PALM_68K_BUILD)/library-tls11.elf
ELF_12_68K := $(PALM_68K_BUILD)/library.elf
ELF_13_68K := $(PALM_68K_BUILD)/library-tls13.elf
ELF_11_ARM := $(PALM_ARM_BUILD)/library-tls11.elf
ELF_12_ARM := $(PALM_ARM_BUILD)/library.elf
ELF_13_ARM := $(PALM_ARM_BUILD)/library-tls13.elf
LIBRARY_CODE := $(PALM_BUILD)/library.bin
BASE_RO := $(PALM_BUILD)/$(LIB_ID)-base.ro
ARMLET_OBJECT := $(PALM_BUILD)/armlet.o
ARMLET_CODE := $(PALM_BUILD)/armc0001.bin
P256_COMB := $(GENERATED)/p256_comb8.inc
ARMLET_HOST_TEST := $(BUILD)/host/armlet_math_test
COMMON_OBJECTS := $(PALM_BUILD)/palm_library.o $(PALM_BUILD)/tls_loader.o \
	$(PALM_BUILD)/tls_palm.o $(PALM_BUILD)/dispatch.o
COMMON_OBJECTS_68K := $(COMMON_OBJECTS) $(PALM_BUILD)/tls_armlet_68k.o
COMMON_OBJECTS_ARM := $(COMMON_OBJECTS) $(PALM_BUILD)/tls_armlet.o
OBJECTS_12_68K := $(COMMON_OBJECTS_68K) $(PALM_BUILD)/tls_engine_12.o
OBJECTS_13_68K := $(COMMON_OBJECTS_68K) $(PALM_BUILD)/tls_engine_13.o
OBJECTS_11_68K := $(COMMON_OBJECTS_68K) $(PALM_BUILD)/tls_engine_11.o
OBJECTS_12_ARM := $(COMMON_OBJECTS_ARM) $(PALM_BUILD)/tls_engine_12.o
OBJECTS_13_ARM := $(COMMON_OBJECTS_ARM) $(PALM_BUILD)/tls_engine_13.o
OBJECTS_11_ARM := $(COMMON_OBJECTS_ARM) $(PALM_BUILD)/tls_engine_11.o
SDK_INCLUDES := -isystem$(SDK) -isystem$(SDK)/Core -isystem$(SDK)/Core/Hardware \
	-isystem$(SDK)/Core/System -isystem$(SDK)/Core/UI -isystem$(SDK)/Dynamic \
	-isystem$(SDK)/Libraries -isystem$(SDK)/Libraries/PalmOSGlue
ABI_FLAGS := -Wno-multichar -m68000 -mno-align-int -mpcrel -fpic -fshort-enums -mshort
WARN_FLAGS := -Wall -Wextra -Wsign-compare -Wno-unused-parameter -Wno-old-style-declaration -Wno-error=cpp
COMMON_FLAGS := $(ABI_FLAGS) $(WARN_FLAGS) -std=gnu17 -Os -ffunction-sections -fdata-sections \
	-DPALMOS -DPALM_TLS_LIB_BUILD -DWOLFSSL_USER_SETTINGS -Iinclude -Isrc \
	-I$(REPO)/wolfssl -I$(DEPS_PREFIX)/include $(SDK_INCLUDES)
LDFLAGS := $(ABI_FLAGS) -Os -nostartfiles -Wl,--gc-sections \
	-Wl,-T,toolchain/linker.lkr -L$(DEPS_PREFIX)/lib
TLS12_ARCHIVE_68K := -Wl,-l:libwolfssl.a
TLS13_ARCHIVE_68K := -Wl,-l:libwolfssl-tls13.a
TLS11_ARCHIVE_68K := -Wl,-l:libwolfssl-tls11.a
TLS12_ARCHIVE_ARM := -Wl,-l:libwolfssl-armlet.a
TLS13_ARCHIVE_ARM := -Wl,-l:libwolfssl-tls13-armlet.a
TLS11_ARCHIVE_ARM := -Wl,-l:libwolfssl-tls11-armlet.a
TLS12_ARCHIVE_FILE_68K := $(DEPS_PREFIX)/lib/libwolfssl.a
TLS13_ARCHIVE_FILE_68K := $(DEPS_PREFIX)/lib/libwolfssl-tls13.a
TLS11_ARCHIVE_FILE_68K := $(DEPS_PREFIX)/lib/libwolfssl-tls11.a
TLS12_ARCHIVE_FILE_ARM := $(DEPS_PREFIX)/lib/libwolfssl-armlet.a
TLS13_ARCHIVE_FILE_ARM := $(DEPS_PREFIX)/lib/libwolfssl-tls13-armlet.a
TLS11_ARCHIVE_FILE_ARM := $(DEPS_PREFIX)/lib/libwolfssl-tls11-armlet.a

TLS_PROFILE ?= full
ifeq ($(TLS_PROFILE),tls13)
PROFILE_SUFFIX := -TLS13
PROFILE_PROTOCOLS := 13
else ifeq ($(TLS_PROFILE),modern)
PROFILE_SUFFIX := -Modern
PROFILE_PROTOCOLS := 12 13
else ifeq ($(TLS_PROFILE),full)
PROFILE_SUFFIX :=
PROFILE_PROTOCOLS := 11 12 13
else
$(error Unknown TLS_PROFILE '$(TLS_PROFILE)'; choose tls13, modern, or full)
endif

TLS11_RESOURCES_68K := $(addprefix $(PALM_68K_BUILD)/,TlsC0015.bin TlsC0016.bin TlsC0017.bin TlsC0018.bin TlsR0003.bin)
TLS12_RESOURCES_68K := $(addprefix $(PALM_68K_BUILD)/,TlsC0001.bin TlsC0002.bin TlsC0003.bin TlsC0004.bin TlsR0001.bin)
TLS13_RESOURCES_68K := $(addprefix $(PALM_68K_BUILD)/,TlsC000b.bin TlsC000c.bin TlsC000d.bin TlsC000e.bin TlsR0002.bin)
TLS11_RESOURCES_ARM := $(addprefix $(PALM_ARM_BUILD)/,TlsC0015.bin TlsC0016.bin TlsC0017.bin TlsC0018.bin TlsR0003.bin)
TLS12_RESOURCES_ARM := $(addprefix $(PALM_ARM_BUILD)/,TlsC0001.bin TlsC0002.bin TlsC0003.bin TlsC0004.bin TlsR0001.bin)
TLS13_RESOURCES_ARM := $(addprefix $(PALM_ARM_BUILD)/,TlsC000b.bin TlsC000c.bin TlsC000d.bin TlsC000e.bin TlsR0002.bin)
PROFILE_RESOURCES_68K := $(foreach protocol,$(PROFILE_PROTOCOLS),$(TLS$(protocol)_RESOURCES_68K))
PROFILE_RESOURCES_ARM := $(foreach protocol,$(PROFILE_PROTOCOLS),$(TLS$(protocol)_RESOURCES_ARM))
PROFILE_ELFS_68K := $(foreach protocol,$(PROFILE_PROTOCOLS),$(ELF_$(protocol)_68K))
PROFILE_ELFS_ARM := $(foreach protocol,$(PROFILE_PROTOCOLS),$(ELF_$(protocol)_ARM))
BASE_ELF_68K := $(firstword $(PROFILE_ELFS_68K))
PRC_68K := $(PALM_BUILD)/$(LIB_ID)68K$(PROFILE_SUFFIX).prc
PRC_ARM := $(PALM_BUILD)/$(LIB_ID)Arm$(PROFILE_SUFFIX).prc
ARMLET_PAD := $(PALM_BUILD)/PadR0001-$(TLS_PROFILE).bin

.PHONY: all test test-prc profiles profile-tls13 profile-modern profile-full clean

all: test

$(GENERATED) $(PALM_BUILD) $(PALM_68K_BUILD) $(PALM_ARM_BUILD):
	@mkdir -p $@

$(DISPATCH): library.def | $(GENERATED)
	$(STUBGEN) -b $(GENERATED)/library library.def

$(PALM_BUILD)/palm_library.o: src/palm_library.c include/palm_tls.h src/tls_internal.h | $(PALM_BUILD)
	$(CC) $(COMMON_FLAGS) -c $< -o $@
$(PALM_BUILD)/tls_loader.o: src/tls_loader.c include/palm_tls.h src/tls_segments.h src/tls_internal.h | $(PALM_BUILD)
	$(CC) $(COMMON_FLAGS) -fno-builtin-memset \
		-fno-tree-loop-distribute-patterns -c $< -o $@
$(PALM_BUILD)/tls_engine_12.o: src/tls_engine.c include/palm_tls.h src/tls_palm.h src/tls_internal.h $(WOLFSSL_SETTINGS) | $(PALM_BUILD)
	$(CC) $(filter-out -mpcrel -fpic,$(COMMON_FLAGS)) -DPALM_TLS_ENGINE_PROTOCOL=12 \
		-DPALM_WOLFSSL_TLS12_ONLY -c $< -o $@
$(PALM_BUILD)/tls_engine_13.o: src/tls_engine.c include/palm_tls.h src/tls_palm.h src/tls_internal.h $(WOLFSSL_SETTINGS) | $(PALM_BUILD)
	$(CC) $(filter-out -mpcrel -fpic,$(COMMON_FLAGS)) -DPALM_TLS_ENGINE_PROTOCOL=13 \
		-DWOLFSSL_NO_TLS12 -c $< -o $@
$(PALM_BUILD)/tls_engine_11.o: src/tls_engine.c include/palm_tls.h src/tls_palm.h src/tls_internal.h $(WOLFSSL_SETTINGS) | $(PALM_BUILD)
	$(CC) $(filter-out -mpcrel -fpic,$(COMMON_FLAGS)) -DPALM_TLS_ENGINE_PROTOCOL=11 \
		-DPALM_WOLFSSL_TLS11_ONLY -c $< -o $@
$(PALM_BUILD)/tls_palm.o: src/tls_palm.c src/tls_palm.h $(WOLFSSL_SETTINGS) | $(PALM_BUILD)
	$(CC) $(filter-out -mpcrel -fpic,$(COMMON_FLAGS)) -c $< -o $@
$(PALM_BUILD)/tls_armlet.o: src/tls_armlet.c src/tls_armlet.h arm/armlet_abi.h include/palm_tls.h $(WOLFSSL_SETTINGS) | $(PALM_BUILD)
	$(CC) $(filter-out -mpcrel -fpic,$(COMMON_FLAGS)) -c $< -o $@
$(PALM_BUILD)/tls_armlet_68k.o: src/tls_armlet_68k.c include/palm_tls.h | $(PALM_BUILD)
	$(CC) $(filter-out -mpcrel -fpic,$(COMMON_FLAGS)) -c $< -o $@
$(PALM_BUILD)/dispatch.o: $(DISPATCH) | $(PALM_BUILD)
	$(CC) $(ABI_FLAGS) -c $< -o $@

$(ELF_12_68K): $(OBJECTS_12_68K) toolchain/linker.lkr $(TLS12_ARCHIVE_FILE_68K) | $(PALM_68K_BUILD)
	$(CC) -o $@ $(LDFLAGS) -Wl,-Map,$(PALM_68K_BUILD)/$(LIB_ID)-tls12.map \
		-Wl,--emit-relocs $(OBJECTS_12_68K) $(TLS12_ARCHIVE_68K)
$(ELF_11_68K): $(OBJECTS_11_68K) toolchain/linker.lkr $(TLS11_ARCHIVE_FILE_68K) | $(PALM_68K_BUILD)
	$(CC) -o $@ $(LDFLAGS) -Wl,-Map,$(PALM_68K_BUILD)/$(LIB_ID)-tls11.map \
		-Wl,--emit-relocs $(OBJECTS_11_68K) $(TLS11_ARCHIVE_68K)
$(ELF_13_68K): $(OBJECTS_13_68K) toolchain/linker.lkr $(TLS13_ARCHIVE_FILE_68K) | $(PALM_68K_BUILD)
	$(CC) -o $@ $(LDFLAGS) -Wl,-Map,$(PALM_68K_BUILD)/$(LIB_ID)-tls13.map \
		-Wl,--emit-relocs $(OBJECTS_13_68K) $(TLS13_ARCHIVE_68K)

$(ELF_12_ARM): $(OBJECTS_12_ARM) toolchain/linker.lkr $(TLS12_ARCHIVE_FILE_ARM) | $(PALM_ARM_BUILD)
	$(CC) -o $@ $(LDFLAGS) -Wl,-Map,$(PALM_ARM_BUILD)/$(LIB_ID)-tls12.map \
		-Wl,--emit-relocs $(OBJECTS_12_ARM) $(TLS12_ARCHIVE_ARM)
$(ELF_11_ARM): $(OBJECTS_11_ARM) toolchain/linker.lkr $(TLS11_ARCHIVE_FILE_ARM) | $(PALM_ARM_BUILD)
	$(CC) -o $@ $(LDFLAGS) -Wl,-Map,$(PALM_ARM_BUILD)/$(LIB_ID)-tls11.map \
		-Wl,--emit-relocs $(OBJECTS_11_ARM) $(TLS11_ARCHIVE_ARM)
$(ELF_13_ARM): $(OBJECTS_13_ARM) toolchain/linker.lkr $(TLS13_ARCHIVE_FILE_ARM) | $(PALM_ARM_BUILD)
	$(CC) -o $@ $(LDFLAGS) -Wl,-Map,$(PALM_ARM_BUILD)/$(LIB_ID)-tls13.map \
		-Wl,--emit-relocs $(OBJECTS_13_ARM) $(TLS13_ARCHIVE_ARM)

$(LIBRARY_CODE): $(BASE_ELF_68K)
	$(OBJCOPY) -O binary $< $@ -j .text
	@test "$$(wc -c < $@)" -lt 65000

define ENGINE_RESOURCES
$(2)/TlsC$(3).bin: $(1) | $(2)
	$$(OBJCOPY) -O binary $$< $$@ -j .tls2
$(2)/TlsC$(4).bin: $(1) | $(2)
	$$(OBJCOPY) -O binary $$< $$@ -j .tls3
$(2)/TlsC$(5).bin: $(1) | $(2)
	$$(OBJCOPY) -O binary $$< $$@ -j .tls4a
$(2)/TlsC$(6).bin: $(1) | $(2)
	$$(OBJCOPY) -O binary $$< $$@ -j .tls5
$(2)/TlsR$(7).bin: $(1) $$(REPO)/tools/generate-tls-segments.mjs | $(2)
	node $$(REPO)/tools/generate-tls-segments.mjs $$< $$@ $$(PREFIX)/bin/m68k-none-elf-readelf
endef

$(eval $(call ENGINE_RESOURCES,$(ELF_12_68K),$(PALM_68K_BUILD),0001,0002,0003,0004,0001))
$(eval $(call ENGINE_RESOURCES,$(ELF_13_68K),$(PALM_68K_BUILD),000b,000c,000d,000e,0002))
$(eval $(call ENGINE_RESOURCES,$(ELF_11_68K),$(PALM_68K_BUILD),0015,0016,0017,0018,0003))
$(eval $(call ENGINE_RESOURCES,$(ELF_12_ARM),$(PALM_ARM_BUILD),0001,0002,0003,0004,0001))
$(eval $(call ENGINE_RESOURCES,$(ELF_13_ARM),$(PALM_ARM_BUILD),000b,000c,000d,000e,0002))
$(eval $(call ENGINE_RESOURCES,$(ELF_11_ARM),$(PALM_ARM_BUILD),0015,0016,0017,0018,0003))

$(P256_COMB): tools/generate-p256-comb.mjs | $(GENERATED)
	node $< $@

$(ARMLET_OBJECT): arm/multiply.c arm/armlet_abi.h $(P256_COMB) | $(PALM_BUILD)
	$(ARM_CC) --target=armv5te-none-eabi $(ARM_CPU_FLAGS) -marm $(ARM_OPT_FLAGS) \
		-ffreestanding -fno-builtin -fno-stack-protector -fomit-frame-pointer \
		-fpic -ffunction-sections -fdata-sections -I$(GENERATED) \
		-Wall -Wextra -Werror -c $< -o $@
$(ARMLET_CODE): $(ARMLET_OBJECT) tools/extract-armlet.mjs
	node tools/extract-armlet.mjs $< $@
$(ARMLET_PAD): $(PROFILE_RESOURCES_ARM) tools/generate-armlet-pad.mjs | $(PALM_BUILD)
	node tools/generate-armlet-pad.mjs $@ $(PROFILE_RESOURCES_ARM)
$(ARMLET_HOST_TEST): tests/armlet_math_test.c arm/multiply.c arm/armlet_abi.h $(P256_COMB)
	@mkdir -p $(dir $@)
	$(HOST_CC) -std=c99 -O2 -Wall -Wextra -Werror \
		-DPALM_ARMLET_HOST_TEST -I$(GENERATED) $(filter %.c,$^) -o $@

$(BASE_RO): resources/library.rcp app.mk $(LIBRARY_CODE) | $(PALM_BUILD)
	cd $(PALM_BUILD) && $(PILRC) -ro -o $(BASE_RO) -creator $(LIB_CREATOR) \
		-type $(LIB_TYPE) -name '$(LIB_NAME)' $(ROOT)/resources/library.rcp

$(PRC_68K): $(LIBRARY_CODE) $(PROFILE_RESOURCES_68K) resources/library.rcp app.mk $(BASE_RO)
	$(BUILD_PRC) --no-check -o $@ -n '$(LIB_NAME)' -c $(LIB_CREATOR) -t $(LIB_TYPE) \
		$(BASE_RO) $(PROFILE_RESOURCES_68K)
	@echo "Built $@"

$(PRC_ARM): $(LIBRARY_CODE) $(PROFILE_RESOURCES_ARM) resources/library.rcp app.mk \
		$(BASE_RO) $(ARMLET_CODE) $(ARMLET_PAD)
	$(BUILD_PRC) --no-check -o $@ -n '$(LIB_NAME)' -c $(LIB_CREATOR) -t $(LIB_TYPE) \
		$(BASE_RO) $(PROFILE_RESOURCES_ARM) $(ARMLET_PAD) $(ARMLET_CODE)
	@echo "Built $@"

test-prc: $(PRC_68K) $(PRC_ARM)
	node tools/validate_library.mjs $(PRC_68K) 68k $(TLS_PROFILE)
	node tools/validate_library.mjs $(PRC_ARM) arm $(TLS_PROFILE)
	$(SIZE) $(PROFILE_ELFS_68K) $(PROFILE_ELFS_ARM)

test: profiles $(ARMLET_HOST_TEST)
	$(ARMLET_HOST_TEST)

profiles:
	$(MAKE) TLS_PROFILE=tls13 test-prc
	$(MAKE) TLS_PROFILE=modern test-prc
	$(MAKE) TLS_PROFILE=full test-prc

profile-tls13 profile-modern profile-full:
	$(MAKE) TLS_PROFILE=$(patsubst profile-%,%,$@) test-prc

clean:
	rm -rf build
