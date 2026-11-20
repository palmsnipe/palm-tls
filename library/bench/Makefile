SHELL := /bin/bash
ROOT := $(abspath ..)
REPO := $(abspath ../..)
PREFIX := $(if $(PALM_TOOLCHAIN_PREFIX),$(PALM_TOOLCHAIN_PREFIX),$(REPO)/../palm-toolchain/.toolchain/prefix)
TOOLCHAIN_ROOT := $(if $(PALM_TOOLCHAIN_ROOT),$(PALM_TOOLCHAIN_ROOT),$(REPO)/../palm-toolchain)
BUILD := $(ROOT)/build/bench
HOST_CC ?= cc
HOST_OPT_FLAGS ?= -O2
CC := $(PREFIX)/bin/m68k-none-elf-gcc
SDK := $(PREFIX)/palmdev/sdk/include
ABI := -Wno-multichar -m68000 -mno-align-int -mpcrel -fpic -fshort-enums -mshort
CFLAGS := $(ABI) -std=gnu17 -Os -Wall -Wextra -Werror -Wno-old-style-declaration \
    -ffunction-sections -fdata-sections -DPALMOS -I. -I$(BUILD) -I$(ROOT)/include \
    -isystem$(SDK) -isystem$(SDK)/Core -isystem$(SDK)/Core/Hardware \
    -isystem$(SDK)/Core/System -isystem$(SDK)/Core/UI -isystem$(SDK)/Dynamic \
    -isystem$(SDK)/Libraries -isystem$(SDK)/Libraries/PalmOSGlue
STARTUP := $(REPO)/apps/tls-tester/src/startup.c
LINKER := $(REPO)/apps/tls-tester/toolchain/linker.lkr
OBJECTS := $(BUILD)/palm.o $(BUILD)/bench.o $(BUILD)/startup.o
LDFLAGS := $(ABI) -Os -nostartfiles -Wl,--gc-sections -Wl,-T,$(LINKER)

.PHONY: host palm check test clean FORCE
host: $(BUILD)/host

$(BUILD):
	mkdir -p $@
$(BUILD)/bench_vectors.inc: generate-vectors.mjs | $(BUILD)
	node $< $@
$(BUILD)/host-config: FORCE | $(BUILD)
	@printf '%s\n' '$(HOST_CC) $(HOST_OPT_FLAGS)' > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@
$(BUILD)/host: host.c bench.c bench.h $(ROOT)/arm/multiply.c $(ROOT)/arm/armlet_abi.h \
        $(ROOT)/src/p256_inverse.inc $(ROOT)/build/generated/p256_comb.inc $(BUILD)/bench_vectors.inc $(BUILD)/host-config Makefile
	$(HOST_CC) -std=c99 $(HOST_OPT_FLAGS) -Wall -Wextra -Werror \
		-DPALM_ARMLET_HOST_TEST -I$(BUILD) -I$(ROOT)/build/generated \
		host.c bench.c $(ROOT)/arm/multiply.c -o $@
$(ROOT)/build/generated/p256_comb.inc:
	$(MAKE) -C $(ROOT) $@
$(BUILD)/%.o: %.c bench.h $(ROOT)/arm/armlet_abi.h $(ROOT)/src/tls_arm_compat.h $(ROOT)/include/palm_tls.h $(BUILD)/bench_vectors.inc
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/startup.o: $(STARTUP) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/code.elf: $(OBJECTS) $(LINKER)
	$(CC) $(LDFLAGS) -Wl,--emit-relocs $(OBJECTS) -o $@.stage1
	node $(TOOLCHAIN_ROOT)/tools/generate-m68k-relocs.mjs $@.stage1 $(BUILD)/relocs.s $(PREFIX)/bin/m68k-none-elf-readelf
	$(CC) $(ABI) -c $(BUILD)/relocs.s -o $(BUILD)/relocs.o
	$(CC) $(LDFLAGS) $(OBJECTS) $(BUILD)/relocs.o -o $@
	rm $@.stage1
$(BUILD)/code0001.bin: $(BUILD)/code.elf
	$(PREFIX)/bin/m68k-none-elf-objcopy -O binary $< $@ -j .vec -j .text
$(BUILD)/armc0001.bin: FORCE | $(BUILD)
	$(MAKE) -C $(ROOT) $(ROOT)/build/palm/armc0001.bin
	@cmp -s $(ROOT)/build/palm/armc0001.bin $@ || cp $(ROOT)/build/palm/armc0001.bin $@
$(BUILD)/PalmTLSBench.prc: $(BUILD)/code0001.bin $(BUILD)/armc0001.bin bench.rcp
	cd $(BUILD) && $(PREFIX)/bin/pilrc -ro -o bench.ro $(ROOT)/bench/bench.rcp
	$(PREFIX)/bin/build-prc --no-check -o $@ -n 'PalmTLS Bench' -c Tbch -t appl $(BUILD)/bench.ro
palm: $(BUILD)/PalmTLSBench.prc
	node $(TOOLCHAIN_ROOT)/tools/validate-prc.mjs $< 'PalmTLS Bench' appl Tbch
	node validate-armlet.mjs $< $(ROOT)/build/palm/armc0001.bin
check: host
	$(BUILD)/host > $(BUILD)/host.csv
	python3 results.py $(BUILD)/host.csv > $(BUILD)/host-summary.csv
test:
	python3 -m unittest discover -s . -p 'test_*.py'
clean:
	rm -rf $(BUILD)

# The fixture server generates this public trust/port include before building.
$(BUILD)/handshake.o: handshake.c $(BUILD)/handshake_vectors.inc $(ROOT)/include/palm_tls.h
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/handshake.elf: $(BUILD)/handshake.o $(BUILD)/startup.o $(LINKER)
	$(CC) $(LDFLAGS) -Wl,--emit-relocs $(BUILD)/handshake.o $(BUILD)/startup.o -o $@.stage1
	node $(TOOLCHAIN_ROOT)/tools/generate-m68k-relocs.mjs $@.stage1 $(BUILD)/handshake-relocs.s $(PREFIX)/bin/m68k-none-elf-readelf
	$(CC) $(ABI) -c $(BUILD)/handshake-relocs.s -o $(BUILD)/handshake-relocs.o
	$(CC) $(LDFLAGS) $(BUILD)/handshake.o $(BUILD)/startup.o $(BUILD)/handshake-relocs.o -o $@
	rm $@.stage1
$(BUILD)/handshake-code0001.bin: $(BUILD)/handshake.elf
	$(PREFIX)/bin/m68k-none-elf-objcopy -O binary $< $@ -j .vec -j .text
$(BUILD)/PalmTLSHandshakeBench.prc: $(BUILD)/handshake-code0001.bin $(BUILD)/armc0001.bin handshake.rcp
	cd $(BUILD) && $(PREFIX)/bin/pilrc -ro -o handshake.ro $(ROOT)/bench/handshake.rcp
	$(PREFIX)/bin/build-prc --no-check -o $@ -n 'PalmTLS HS Bench' -c Thsb -t appl $(BUILD)/handshake.ro
handshake: $(BUILD)/PalmTLSHandshakeBench.prc
	node $(TOOLCHAIN_ROOT)/tools/validate-prc.mjs $< 'PalmTLS HS Bench' appl Thsb
	node validate-armlet.mjs $< $(ROOT)/build/palm/armc0001.bin

# Common-ABI comparison against published library binaries.
$(BUILD)/release.o: release.c $(BUILD)/handshake_vectors.inc $(ROOT)/include/palm_tls.h
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/release.elf: $(BUILD)/release.o $(BUILD)/startup.o $(LINKER)
	$(CC) $(LDFLAGS) -Wl,--emit-relocs $(BUILD)/release.o $(BUILD)/startup.o -o $@.stage1
	node $(TOOLCHAIN_ROOT)/tools/generate-m68k-relocs.mjs $@.stage1 $(BUILD)/release-relocs.s $(PREFIX)/bin/m68k-none-elf-readelf
	$(CC) $(ABI) -c $(BUILD)/release-relocs.s -o $(BUILD)/release-relocs.o
	$(CC) $(LDFLAGS) $(BUILD)/release.o $(BUILD)/startup.o $(BUILD)/release-relocs.o -o $@
	rm $@.stage1
$(BUILD)/release-code0001.bin: $(BUILD)/release.elf
	$(PREFIX)/bin/m68k-none-elf-objcopy -O binary $< $@ -j .vec -j .text
$(BUILD)/PalmTLSReleaseBench.prc: $(BUILD)/release-code0001.bin $(BUILD)/armc0001.bin release.rcp
	cd $(BUILD) && $(PREFIX)/bin/pilrc -ro -o release.ro $(ROOT)/bench/release.rcp
	$(PREFIX)/bin/build-prc --no-check -o $@ -n 'PalmTLS HS Bench' -c Thsb -t appl $(BUILD)/release.ro
release-bench: $(BUILD)/PalmTLSReleaseBench.prc
	node $(TOOLCHAIN_ROOT)/tools/validate-prc.mjs $< 'PalmTLS HS Bench' appl Thsb
	node validate-armlet.mjs $< $(ROOT)/build/palm/armc0001.bin

# Standalone 68K comparison using production P-256 and two X25519 backends.
# The X25519 objects only go into this PRC.
DEPS_PREFIX := $(if $(PALM_TLS_DEPS_PREFIX),$(PALM_TLS_DEPS_PREFIX),$(REPO)/.palm-tls/prefix)
WOLFSSL_SRC ?= $(REPO)/.palm-tls/src/wolfssl
KX_FLAGS := $(filter-out -mpcrel -fpic,$(CFLAGS)) -DWOLFSSL_USER_SETTINGS \
    -DWOLFSSL_NO_TLS12 -DHAVE_CURVE25519 -I$(REPO)/wolfssl -I$(DEPS_PREFIX)/include
P256_68K := $(ROOT)/build/palm/tls_p256_68k.o
KX_ARCHIVE := $(DEPS_PREFIX)/lib/libwolfssl-tls13.a
KX_OBJECTS := $(BUILD)/key-exchange.o $(BUILD)/x25519-portable.o $(BUILD)/x25519-68k.o \
    $(P256_68K) $(BUILD)/startup.o

.PHONY: key-exchange
$(P256_68K): FORCE
	$(MAKE) -C $(ROOT) $@
$(BUILD)/key_exchange_vectors.inc: generate-key-exchange-vectors.mjs | $(BUILD)
	node $< $@
$(BUILD)/key-exchange.o: key-exchange.c $(BUILD)/key_exchange_vectors.inc $(ROOT)/src/tls_x25519_68k.h \
        $(ROOT)/src/tls_handshake_profile.h $(REPO)/wolfssl/user_settings.h Makefile
	$(CC) $(KX_FLAGS) -c $< -o $@
$(BUILD)/x25519_comb.inc: $(ROOT)/tools/generate-x25519-comb.mjs | $(BUILD)
	node $< $@
$(BUILD)/x25519-68k.o: $(ROOT)/src/tls_x25519_68k.c $(ROOT)/src/tls_x25519_68k.h $(BUILD)/x25519_comb.inc Makefile
	$(CC) $(filter-out -mpcrel -fpic,$(CFLAGS)) -c $< -o $@
$(BUILD)/x25519-portable.o: $(WOLFSSL_SRC)/wolfcrypt/src/fe_operations.c \
        $(REPO)/wolfssl/user_settings.h $(KX_ARCHIVE) Makefile | $(BUILD)
	$(CC) $(KX_FLAGS) -Wno-sign-compare -Wno-unused-parameter -I$(WOLFSSL_SRC) -c $< -o $@
$(BUILD)/key-exchange.elf: $(KX_OBJECTS) $(KX_ARCHIVE) $(LINKER)
	$(CC) $(LDFLAGS) -Wl,--emit-relocs $(KX_OBJECTS) $(KX_ARCHIVE) -o $@.stage1
	node $(TOOLCHAIN_ROOT)/tools/generate-m68k-relocs.mjs $@.stage1 $(BUILD)/kx-relocs.s $(PREFIX)/bin/m68k-none-elf-readelf
	$(CC) $(ABI) -c $(BUILD)/kx-relocs.s -o $(BUILD)/kx-relocs.o
	$(CC) $(LDFLAGS) $(KX_OBJECTS) $(BUILD)/kx-relocs.o $(KX_ARCHIVE) -o $@
	rm $@.stage1
$(BUILD)/key-exchange-code0001.bin: $(BUILD)/key-exchange.elf
	$(PREFIX)/bin/m68k-none-elf-objcopy -O binary $< $@ -j .vec -j .text
$(BUILD)/PalmTLSKeyExchangeBench.prc: $(BUILD)/key-exchange-code0001.bin key-exchange.rcp
	cd $(BUILD) && $(PREFIX)/bin/pilrc -ro -o key-exchange.ro $(ROOT)/bench/key-exchange.rcp
	$(PREFIX)/bin/build-prc --no-check -o $@ -n 'PalmTLS KX Bench' -c Tkxb -t appl $(BUILD)/key-exchange.ro
key-exchange: $(BUILD)/PalmTLSKeyExchangeBench.prc
	node $(TOOLCHAIN_ROOT)/tools/validate-prc.mjs $< 'PalmTLS KX Bench' appl Tkxb
