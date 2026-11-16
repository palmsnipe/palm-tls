# Palm TX CPM seeding

The stock Cryptography Provider Manager (CPM) in the examined Palm TX image
does not provide a qualified entropy source for PalmTLS pairing. Its base
provider initializes the generator from the wall clock in whole seconds.

The examined CloudpilotEmu session reports OS version feature `05493028`
(Garnet 5.4.9) and model `D050`. Its embedded NOR SHA-256 is
`deab283c926d1f68d599b0f42bab7d84d2ff7dd7bb8ae41ec0dc381e6d7db530`.
The CPM library comes from the session's installed system databases. The
comparison below uses the loaded ARM resource, since the standalone NOR
does not contain that resource in plain form.

The loaded code matches the corresponding [Tungsten E2 provider](tungsten-e2.md)
in the following paths. Offsets are relative to the ARM resource.

| Path | TX evidence |
| --- | --- |
| Initial seed | Thumb code at `0xda–0xf2` gets the return value from the veneer at `0x80a0`, then passes those four bytes into the initializer at `0x27e8`. The veneer reaches the native system table slot `0x924` (`TimGetSeconds`) through ARM code at `0x7e28`. |
| Generation | The entry at `0x2da` and generator at `0x2864` match the E2 code that advances its state without collecting fresh entropy. |
| Additional input | The separate Add Random Seed entry can mix caller input. The ordinary generation path does not invoke it. |

In a disposable TX session, Palm Random Probe received two different
32-byte blocks successfully. This checks availability, not their
unpredictability. A separate attempt to compare fresh opens at the same
clock time returned `cpmErrAlreadyOpen` on this session, so it did not
measure a fresh-open comparison. The seed path above is established by code
inspection.

Palm Random Probe 0.2.0 reported `Code 33456 7883D58E` on the Garnet 5.4.9
TX emulator. The fields are the length in bytes and CRC-32 of `amdc` ID 0
from the installed CPM library database. The probe reported
`Open 3801 (already open)` and skipped fresh opens.

A physical Palm TX reported the same ROM feature (`05493028`), device ID
(`44303530`, ASCII `D050`), and code fingerprint (`33456 7883D58E`).
It also reported `Open 3801 (already open)`, so the run did not measure
random output or determine how the already-open instance was seeded. The
matching firmware fingerprint supports applying the code trace to this
handheld. It does not qualify stock CPM as a standalone source of entropy
for PalmTLS.
