# Palm Pen Probe

Build and validate the diagnostic PRC from the PalmTLS checkout.

```sh
make -C apps/pen-probe test
```

Install `apps/pen-probe/build/PalmPenProbe.prc` on a Tungsten E2.
Insert one writable FAT SD card, launch **Palm Pen Probe**, tap **Start**,
draw several separate strokes in the box, then tap **Stop**. The probe saves
to the first available name from `PEN0001.CSV` through `PEN9999.CSV` in the
card's root and closes the file. It also saves automatically at 1,024 samples.
If saving fails, insert a writable card and tap **Retry** before leaving
the app. Unsaved samples are held in RAM for the current launch.

Each row records:

- `phase` as `D` (down), `M` (move), or `U` (up).
- `ticks` elapsed since the first event, measured with `TimGetTicks` immediately
  after dequeuing the event. Divide by `ticks_per_second` for seconds. The
  emulated E2 reports 100 ticks per second.
- `screen_x` and `screen_y` from the Palm OS event. `raw_x` and `raw_y` are a
  separate digitizer reading taken immediately afterward on down and move.
  Queued event coordinates can therefore describe an earlier point than the
  raw reading. Raw fields are blank on pen-up or on a HAL error, whose hex
  code is in `raw_error`.
- `rom` and `device_id` as Palm OS feature values in hex. The device ID
  identifies the model.

The SDK declares `PenGetRawPen`, but the E2 ROM in CloudpilotEmu rejects its
68K trap. A small ARM resource reads the native `HALPenGetPosition` entry
used by the E2 ROM's pen path. The call is restricted to the E2 device
feature ID. The timing is Palm OS event timing at OS tick resolution.

For a physical capture, record the handheld model and firmware revision
with the CSVs. Repeat across fresh starts, including a cold power cycle if
available. Collect both freehand strokes and repeated strokes or taps in
roughly the same location so the raw readings can be compared under different
conditions. The files are diagnostic samples for assessing the source.
PalmTLS production pairing continues to require a qualified source.

In CloudpilotEmu, use a copied E2 session and disposable FAT card. Install the
PRC and launch `"Palm Pen Probe"`. On its 320×320 screen, `tap 50 294` toggles
recording and `stroke 50 80 100 105 140 88 204 124` supplies a stroke inside the
box. After stopping, use `save-sd` to export the card. The emulator can verify
event sequencing, timestamp capture, native-call results, and CSV writing.
The simulated digitizer derives its readings from supplied coordinates.
