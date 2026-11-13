APP_ID := PalmPenProbe
APP_NAME := Palm Pen Probe
APP_CREATOR := PtPP
APP_HEADERS := resource.h
APP_RESOURCES := build/raw-pen.bin
include ../probe.mk

$(BUILD)/raw-pen.o: raw-pen.S | $(BUILD)
	$(BIN)/arm-none-eabi-as -march=armv5te $< -o $@

$(BUILD)/raw-pen.bin: $(BUILD)/raw-pen.o
	$(BIN)/arm-none-eabi-objcopy -O binary -j .text $< $@
