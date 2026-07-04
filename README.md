# GLD09 Control — a standalone Bluetooth controller

An independent tool to keep controlling a Fisher-Price Lumalou (model GLD09) you
already own, over Bluetooth, after Mattel discontinued the Smart Connect app and its
cloud. No app, no login, no cloud: the desired state is declared in `lumalou.yaml`
and applied to the lamp directly. It interoperates with the lamp's own BLE protocol -
see the [disclaimer](#disclaimer) at the end.

Applying a config is silent by design — `volume 0` is sent first — so reconfiguring
the lamp near a sleeping child never makes noise. Your own settings go in `lumalou.yaml`
(gitignored); `lumalou.yaml.example` is the template.

The green "OK to wake" star only lights with an audible alarm, so for a *silent* morning
cue the controller can use the lamp's own `routine` instead: a task-icon sequence shown
at the start time (per weekday), where a single `[heart]` reads as "OK to wake" and a
longer list steps through tasks. The lamp blanks the icon on its own later in the day.
The companion **IR remote** (a round "button") toggles the soother outside a routine and
checks off the current task during one, optionally with a celebration sound
(`reward_sound`).

## What the lamp does

Fisher-Price **[Lumalou - Better Bedtime Routine System][manual]** (GLD09) is a
wall-mounted cloud night light with a smiley star. It is more than a lamp: the
cloud face lights up a sequence of **routine icons** to walk a child through a
bedtime or morning routine, and the star is a **sleep trainer** (red = stay in
bed, green = OK to wake). It also has a clock, a colour night light, music, and
nap/soothing modes. All of this was originally driven by the Fisher-Price Smart
Connect app and cloud, which Mattel shut down (the manual itself reserves the
right to "terminate digital applications after April 30, 2022"). This controller
drives the lamp directly instead.

> The lamp keeps time in a volatile RTC. Per the manual, on any power loss it
> forgets the time and **the routine and sleep-trainer functions are disabled
> until the clock is re-synced** - which the app did over the cloud and this
> controller now does on apply via `sync_time` (`setCurrentDate`).

[manual]: https://service.mattel.com//instruction_sheets/GLD09-0970-1102345604-DOM.pdf

### Feature coverage

**Implemented here:**

- **Clock** - show, 12h/24h, backlight brightness, RTC time-sync, test fast-forward
- **Night light** - on/off, brightness, 11 colours, sleep timer
- **Sound** - volume, mute, 18 songs, SFX loops (rain/ocean/noise/nature), custom
  playlists, sleep timer
- **Sleep trainer** - red "stay in bed" / green "OK to wake" star; bedtime + wake
  schedule with alarm modes (silent / sound / +N min)
- **Nap & soothing** - nap timer, start/stop soothing (light + sound)
- **Routine** - a task-icon sequence (the 8 fixed tasks + 3 custom icons) shown
  autonomously at the start time (per weekday); a single `[heart]` is the "OK to wake"
  cue, the lamp auto-blanks it later in the day, and `--show-icon <name>` previews any
  icon. The companion IR button checks off tasks in order; `reward_sound` plays a
  celebration on each check-off (off by default for a silent nursery)
- **Read-back** - `--status` (full state, clock, wake status/times); `--scan` lists lamps
  in range with their connection state and firmware from a passive advertisement (no connection);
  `--watch` prints device pushes live (the lamp streams its clock ~1/s and pushes state changes,
  e.g. a routine task checked off on the lamp, over the notify characteristic)

The persistent settings are declared in `lumalou.yaml`; the one-shot actions
(soothe / nap / play / stop) are CLI flags. One config can drive several lamps: list
them under `devices:` and the same `settings` are applied to each (keeping multiple
units in sync); a device out of range is skipped and the rest still run.

**Not wired**: `setGlobalState` 0x01 (unused by the lamp) and `setNapTimeAlarm` 0x4f
(inert on this firmware). OTA firmware update is intentionally left out.

**Hidden features** (not surfaced in the manual):

- **Clock fast-forward** - `setTimePreScaler` 0x52 runs the lamp's internal clock at
  1x / 10x / 60x / 3600x, so the wake/sleep/routine transitions fire in seconds instead
  of real hours. Exposed via `clock.time_scale` (set `60x` to watch the wake heart fire
  in minutes); apply resets it to real time.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install bleak pyyaml cryptography
.venv/bin/python lumalou.py lumalou.yaml              # apply the config
.venv/bin/python lumalou.py lumalou.yaml --dry-run    # print command frames, no BLE
.venv/bin/python lumalou.py --scan                    # list lamps in range: connection state + fw (no connect)
.venv/bin/python lumalou.py --status                  # read + print the lamp's state
.venv/bin/python lumalou.py --watch elin              # live-print device pushes (button/state changes); Ctrl-C to stop
.venv/bin/python lumalou.py --soothe                  # start soothing (light + sound)
.venv/bin/python lumalou.py --stop                    # stop soothing + audio
.venv/bin/python lumalou.py --nap 60min               # start a nap timer
.venv/bin/python lumalou.py --play rain               # play a sound (rain/ocean/...)
.venv/bin/python lumalou.py --show-icon heart         # preview a routine icon on the lamp
.venv/bin/python lumalou.py --sync-time               # silent RTC re-sync to host time
.venv/bin/pip install pytest && .venv/bin/pytest      # offline regression tests
```

The controller must run on a machine with Bluetooth **within range of the lamp**.
For a permanent "set and forget" setup, a Raspberry Pi parked near the nursery is
ideal (see Handshake below for why arm64 helps).

## BLE contract (verified live)

- Device advertises name `1102184718` (APN), manufacturer id `0xB603`.
- Service `4cea0001-c678-4202-b5d3-712dbb5e5b14`:
  - `4cea0002` tx       write / write-without-response  (commands -> lamp)
  - `4cea0003` rx       notify                          (responses <- lamp)
  - `4cea0004` factory  read
  - `4cea0005` session  write                           (handshake)
- Also exposes the Nordic Legacy DFU service `0x1530` (firmware).

## Protocol (mpid)

`ble_protocol: "mpid"`: an encrypted session. The lamp presents a factory
certificate (publicKey + serial, ~136-byte ASN.1); both sides do ECDH and derive
an AES-128-CTR key; every packet is then encrypted. The scheme uses:

- ECC/ECDH over secp256r1/P-256 (compressed 33-byte pubkeys)
- AES-128-CTR for packet payloads
- a `0x7E`-framed packet format with a per-session counter

The controller uses an ephemeral keypair; the lamp authenticates to us, so **no
Mattel-issued key is needed**. The full handshake and wire format are specified
below and implemented in `lumalou_mpid.py`.

### mpid protocol

Crypto: ECDH over **secp256r1/P-256** (compressed 33-byte pubkeys); **AES-128-CTR**
for payloads; the device cert is ECDSA P-256.

Handshake (write char `0005`, notify char `0003`):
- Each side has an ephemeral P-256 keypair + a 4-byte salt.
- We send our **33-byte compressed pubkey + 4-byte salt** (37 bytes).
- Device presents its **33-byte compressed pubkey** (cert pubkey at offset 0x19) + salt.
- ECDH(our_priv, device_pub) -> **32-byte shared secret** (the X coordinate).
- AES-128 key = a derivation over the 32-byte shared secret: 100 rounds of in-place
  AES-128-CTR, each keyed by the current first 16 bytes, counter block
  `00000000 | round(4B BE) | \x00mattel\x00`; key = final state[0:16].

Packet wire format, `0x7E`-framed:
```
0x7E | counter(4B big-endian) | len(2B BE, = payload_len+1) | crc8(7 header bytes)
     | AES128-CTR( payload || crc8(payload) )
```
- counter increments per packet; max payload 0x1ff.
- The header (`0x7E`..len) is **cleartext**; only `payload || crc8(payload)` is encrypted.
- AES-CTR IV (16B) = `counter(4B) || local_salt(4B) || peer_salt(4B) || 00000000`.
- crc8: poly 0x07, init 0xFF.

Session flow: write the 37-byte handshake payload to char `0005` -> device notifies
on `0003` -> decrypt; then commands encrypt to tx `0002`, responses decrypt from rx
`0003`.

The handshake is implemented in `lumalou_mpid.py` and validated live (key derivation
in `_derive_session_key`). The controller authenticates nothing: the lamp's cert is
read from char 0004 and only the lamp authenticates. CRC8 = poly 0x07 / init 0xFF;
dev pubkey = cert[25:58], dev salt = cert[188:192]. The crypto is implemented in Python
(`cryptography`), so the controller runs on any host in BLE range.

### Commands

Each command's plaintext body (before the AES-CTR packet wrapping) is:

    [0x01, 0x10] | 0xFE | n | opcode | args... | xor8

where `n = 1 + len(args)`, `xor8 = (n XOR opcode XOR args...) & 0xFF`, and `[0x01,0x10]`
is the write prefix. Opcodes: setVolume `0x37`, turnOffAudio `0x38`,
setLedBrightness `0x3a`, turnOffCloudBackLight `0x3e`, setClockSettings `0x79`,
setR2RTimes `0x46`, setR2RStatus `0x44`, requestGlobalState `0x53`. Notable encodings:

- `setClockSettings` args `[show, (brightness << 4) | format]` (format: 1 = 24h; show: 1 = on).
- **Sleep trainer** ("OK to wake" star) saves as one schedule, sent in this order:
  `setSleepyTimes 0x48` (bedtime) -> `setR2RTimes 0x46` (wake) -> `setR2RAlarms 0x4a`
  -> `setR2RStatus 0x44 [1]`. Each time command is seven `[BCD(hour), BCD(minute)]`
  pairs (one per weekday). `setR2RAlarms` packs seven per-day alarm indices two-per-byte:
  `active` = 0 arms the green-star wake (with an audible tone), `inactive` = 9 leaves
  no event; `1..8` / `10` fire the tone 15..120 / 1 minutes after the wake time. The
  lamp only runs the red->green cycle with both a bedtime window and a wake time set.
- **Routine** (`routine`) shows a task-icon sequence at the start time via
  `set<Day>Routine 0x5a..0x66` + `setRoutineModeStatus 0x58 [1]`. `setRoutineMusicStatus
  0x69` packs `[task_music, reward_music, _]` two-per-byte: `[0,0]` (`00 00`) is silent.
  the two nibbles are reversed from their apparent naming (observed live: `01 00` plays
  routine music but no check-off celebration), so `reward_sound` sets both nibbles with
  `[1,1,0]` (`11 00`) plus a non-zero `setRoutineModeVolume 0x77`. In routine mode the
  companion **IR button** checks off the current task (`routineControl`, complete-current-
  task), advancing the sequence and firing the reward sound; the same button toggles the
  soother outside a routine. The icon
  **auto-clears**: the firmware
  ends the morning routine on its own later in the day (the lamp leaves routine mode).
  There is **no firmware "clear after N minutes"** and no clear command to send - a sleepy
  time set shortly after the start does NOT clear it (verified: the icon was still up 10
  min past a 07:00 sleepy time). Observed timing: persists at least ~25 min, gone within a
  few hours (in the app, by evening); exact timing is firmware-determined.
- `requestGlobalState` returns a 13-byte nibble-packed state (volume, brightness, light,
  clock format/show, ...), decoded by `parse_global_state`.

`python3 lumalou.py lumalou.yaml --dry-run` prints every command frame without touching
the lamp.

## The Smart Connect app

The Smart Connect app (package `com.fisher_price.android`) was unpublished from
Google Play on 2025-03-19 and is gone from the App Store; the last release is
**10.0.0**. The protocol above is derived solely for interoperability, so owners
can keep using a device the vendor no longer supports - no vendor code or assets
are redistributed here.

## Disclaimer

This is an independent, unofficial project. It is **not** affiliated with, authorised
by, or endorsed by Mattel or Fisher-Price. "Fisher-Price", "Lumalou" and "Smart
Connect" are trademarks of their respective owners, used here only descriptively to
identify the device this software interoperates with.

It exists so that owners of the device can keep using hardware they already bought
after the manufacturer shut down the companion app and cloud. It was produced by
reverse engineering for interoperability, as permitted under the EU Software Directive
(2009/24/EC, art. 6) and the Dutch Auteurswet (art. 45k/45m).

This repository contains only original code and a factual description of the BLE
protocol (command identifiers and byte layouts, which are not themselves
copyrightable). It deliberately does **not** include - and you should not add - any of
the manufacturer's copyrighted material: decompiled source, disassembly, firmware, or
app assets. Provided as-is, without warranty; use at your own risk.

The original code in this repository is released under the **MIT licence** (see
[`LICENSE`](LICENSE)). That licence covers this project's own code only - not the
manufacturer's protocol, firmware, or trademarks.
