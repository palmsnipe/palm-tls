# Tungsten E2 CPM seeding

PalmTLS must keep production pairing disabled for the stock random provider in
the examined Tungsten E2 ROM. Its initial state depends on the device clock at
one-second resolution.

## Firmware trace

The image is Palm OS Garnet 5.4.7, ROM header build `3/04/05 19:50:03`.
The NOR SHA-256 is
`9537b1caa0d657e376cb68a4056f45057b41e09140c24873e7cf0fa781752c71`.
It matches the NOR image used for CloudpilotEmu's E2. The `libr/cpml` resource
`amdc` ID 0 starts at NOR offset `0x525220` and is `0x82c0` bytes long.
The code names its provider **Base Cryptographic Provider**, from RSA Security.

Offsets below are relative to that resource. The Palm OS Garnet SDK defines
`CPMLibGenerateRandomBytes` and `CPMLibAddRandomSeed` as library traps
`0xA80A` and `0xA80B`, respectively.

| Path | ROM evidence |
| --- | --- |
| First open | The library allocates and clears its random state. The Thumb code at `0xda–0xee` calls the ARM system table through slot `0x924` and passes the four-byte return value to the initializer at `0x27e8`. CloudpilotEmu's native system call map identifies this slot as `TimGetSeconds`. |
| Generate bytes | The trap reaches `0x2da`, then the generator at `0x2864`. It derives output from its current state using SHA-1 compression and advances that state. This path has no clock or hardware entropy read. |
| Add seed | The trap reaches `0x2fc`, then `0x2832`, which mixes caller-supplied bytes into the state. This is a separate API call. |
| Lifecycle | The final close path at `0x1d8–0x1ea` frees the random state. The sleep and wake handlers at `0x1f6` and `0x1fa` return immediately. |

The [Palm OS Time Manager reference](https://palm.wiki/development/docs/601/PalmOSReference/DateAndTimeManager.html)
defines `TimGetSeconds` as the wall clock in whole seconds since January 1,
1904. [NIST certificate 576](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/576)
covers a separate PalmSource CPM and FIPS Provider configuration on a Tungsten C
running Palm OS 5.2.1.

## Emulator check

A temporary diagnostic on a disposable CloudpilotEmu E2 session set the device
clock before each fresh load/open, requested 32 bytes, then closed and unloaded
CPM. It retained the blocks only long enough to compare them. All four calls
succeeded and returned 32 bytes.

| Comparison | First 32 bytes |
| --- | --- |
| Two opens with the same clock second | Matched |
| Open one second later | Differed |
| Same second with a call to `CPMLibAddRandomSeed` before requesting bytes | Differed |

These observations cover the specified ROM and the stock CPM call path in
CloudpilotEmu. Other ROM revisions and physical hardware were outside the test.
