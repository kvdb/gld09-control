#!/usr/bin/env python3
"""Standalone controller for the Fisher-Price Lumalou (Smart Connect, GLD09).

Talks to the lamp directly over BLE using its `mpid` protocol, replacing the
discontinued Smart Connect app. Configuration is read from lumalou.yaml.

The encrypted mpid session and command encodings are documented in the README and
implemented in lumalou_mpid.py.

Safety: a child sleeps next to the lamp. apply_config() always sends volume 0
first, so configuration never makes noise.

Run:
    python3 lumalou.py [lumalou.yaml]            # configure the lamp over BLE
    python3 lumalou.py [lumalou.yaml] --dry-run  # print the command frames only
"""
from __future__ import annotations

import asyncio
import datetime
import sys
from pathlib import Path

import yaml

from lumalou_mpid import (
    SERVICE, MpidSession, Cmd, Resp, build_body, time_bcd, pack_low_nibbles,
    set_current_date_args, parse_current_date, parse_bcd_times, parse_global_state,
    decode_response, RESP_NAMES,
    LIGHT_COLORS, TIME_SCALES, R2R_ALARM_MODES, DAY_ROUTINE_OPCODE,
    AUDIO_COMMAND, AUDIO_DURATION, LIGHT_DURATION, NAP_DURATION, TASK, WEEKDAYS,
    music_playlist_args, encode_day_routine, parse_advertisement,
)

MANUFACTURER_ID = 0x03B6  # spec calls it "B603"; little-endian company id 0x03B6


def load_config(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text())


def pick_device(cfg: dict, selector) -> dict:
    """Return the config device matching a name or address (case-insensitive), else the first."""
    devices = cfg.get("devices") or [cfg.get("device", {})]
    if selector:
        sel = str(selector).strip().lower()
        for d in devices:
            if sel in (str(d.get("name", "")).lower(), str(d.get("address", "")).lower()):
                return d
    return devices[0]


def resolve_brightness(v) -> int:
    """Map a YAML brightness ('min'/'max'/0-9) to a device brightness index.

    'min' is level 1 (dimmest still-visible backlight); level 0 may read as off on
    the device, so it is not used for a clock that must stay shown.
    """
    if isinstance(v, bool):
        return 1
    if isinstance(v, int):
        return max(0, min(9, v))
    return {"min": 1, "max": 9, "off": 0}.get(str(v).strip().lower(), 1)


# Selectable routine icons (the 8 fixed tasks + 3 custom), in display order.
ICONS = [k for k in TASK if k != "none"]


def resolve_icon(name) -> str:
    """Validate a routine icon name against the task set; fail loudly on a typo."""
    icon = str(name).strip().lower()
    if icon not in TASK or icon == "none":
        raise SystemExit(f"unknown icon {icon!r}; choose one of: {', '.join(ICONS)}")
    return icon


def day_start_times(routine_cfg: dict) -> dict[str, str]:
    """Map each of the 7 WEEKDAYS to its routine start 'HH:MM'.

    `routine.start` is EITHER a single 'HH:MM' string (the same time on all 7 days)
    OR a per-day map {mon: '06:45', ..., sun: '07:00'}. In the map form, a missing
    weekday falls back to the first time given (map insertion order), so a partial map
    still yields a sensible start for every day rather than skipping one.
    """
    start = routine_cfg.get("start", "06:45")
    if isinstance(start, dict):
        per_day = {str(k).strip().lower(): str(v) for k, v in start.items()}
        default = next(iter(per_day.values()), "06:45")
        return {day: per_day.get(day, default) for day in WEEKDAYS}
    return {day: str(start) for day in WEEKDAYS}


def plan_commands(cfg: dict) -> list[tuple[str, int, bytes]]:
    """Build the ordered (label, opcode, args) list for the desired state.

    Order is fixed so configuration stays silent: volume 0 and audio-off go first.
    """
    s = cfg["settings"]
    sound = s.get("sound", {})
    light = s.get("light", {})
    clock = s.get("clock", {})

    brightness = resolve_brightness(light.get("brightness", "min"))
    fmt_24h = 1 if str(clock.get("format", "24h")).startswith("24") else 0
    show = 1 if clock.get("show", True) else 0
    volume = int(sound.get("volume", 0)) & 0xFF

    cmds: list[tuple[str, int, bytes]] = []
    # 1) sound. Volume goes first; silent default keeps volume 0 + audio off.
    cmds.append((f"volume={volume}", Cmd.SET_VOLUME, bytes([volume])))
    if sound.get("enabled", False):
        src = str(sound.get("play", "playlist")).strip().lower()
        if src in ("playlist", "custom") and sound.get("songs"):
            cmds.append((f"playlist {sound['songs']}", Cmd.SET_MUSIC_PLAYLIST,
                         music_playlist_args(sound["songs"])))
            audio = AUDIO_COMMAND["custom"]
        else:
            audio = AUDIO_COMMAND.get(src, 0)
        if sound.get("timer"):
            cmds.append((f"audio timer {sound['timer']}", Cmd.SET_PLAYLIST_DURATION,
                         bytes([AUDIO_DURATION.get(str(sound["timer"]).lower(), 5)])))
        cmds.append((f"play {src}", Cmd.PLAY_AUDIO, bytes([audio])))
    else:
        cmds.append(("sound off", Cmd.TURN_OFF_AUDIO, b""))
    # 2) night light: on with a colour, or off
    if light.get("enabled", False):
        color = LIGHT_COLORS.get(str(light.get("color", "warm")).strip().lower(), 0)
        cmds.append((f"light on color={light.get('color', 'warm')}",
                     Cmd.SET_LIGHT_COLOR, bytes([color])))
    else:
        cmds.append(("night light off", Cmd.TURN_OFF_BACKLIGHT, b""))
    cmds.append((f"brightness={brightness}", Cmd.SET_LED_BRIGHTNESS, bytes([brightness])))
    # soother light sleep-timer: how long the soother's light stays on when soothing is
    # triggered (button / --soothe). Opt-in; only sent when light.timer is set.
    if light.get("timer"):
        cmds.append((f"soother light timer {light['timer']}", Cmd.SET_SOOTHER_LIGHT_DURATION,
                     bytes([LIGHT_DURATION.get(str(light["timer"]).strip().lower(), 4)])))
    # 3) clock: show + format (carries the clock backlight brightness in the high nibble)
    cmds.append((
        f"clock show={show} 24h={fmt_24h} backlight={brightness}",
        Cmd.SET_CLOCK_SETTINGS, bytes([show, (brightness << 4) | fmt_24h]),
    ))
    # 3b) sync the lamp RTC to host time so the wake heart fires at the right wall time
    if clock.get("sync_time", True):
        now = datetime.datetime.now()
        cmds.append((f"sync clock {now:%a %H:%M}", Cmd.SET_CURRENT_DATE,
                     set_current_date_args(now)))
    # 3c) clock speed: real-time by default; test values fast-forward the lamp RTC
    scale_name = str(clock.get("time_scale", "normal")).strip().lower()
    cmds.append((f"clock speed={scale_name}", Cmd.SET_TIME_PRESCALER,
                 bytes([TIME_SCALES.get(scale_name, 0)])))
    # 4) sleep trainer (Ready-to-Rise): the star shows red ("stay in bed") during the
    #    bedtime window and green ("OK to wake") at the wake time. The lamp only runs the
    #    cycle with a COMPLETE schedule, so bedtime and wake are sent together in the
    #    app's order: sleepy -> times -> alarms -> status. The green-star transition is
    #    firmware-coupled to an audible alarm: alarm "sound" arms it (green + tone at the
    #    wake time); "silent" leaves no star event and no sound. This audible star is off
    #    by default; the SILENT wake indicator is the `routine` (a task icon) below.
    st = s.get("sleep_trainer", {})
    if st.get("enabled", False):
        bedtime = time_bcd(str(st.get("bedtime", "19:00")))
        wake = time_bcd(str(st.get("wake", "06:45")))
        alarm = R2R_ALARM_MODES.get(str(st.get("alarm", "silent")).strip().lower(), 9)
        cmds.append((f"bedtime {st.get('bedtime', '19:00')} (7 days)",
                     Cmd.SET_SLEEPY_TIMES, bedtime * 7))
        cmds.append((f"wake {st.get('wake', '06:45')} (7 days)",
                     Cmd.SET_R2R_TIMES, wake * 7))
        cmds.append((f"wake alarm {st.get('alarm', 'silent')}",
                     Cmd.SET_R2R_ALARMS, pack_low_nibbles([alarm] * 7)))
        cmds.append(("sleep trainer on", Cmd.SET_R2R_STATUS, bytes([1])))
    else:
        cmds.append(("sleep trainer off", Cmd.SET_R2R_STATUS, bytes([0])))
    # 5) routine: the lamp's own morning-routine feature — the task-icon sequence shows
    #    on the cloud face AUTONOMOUSLY at the start time, silently (verified live). A
    #    single [heart] is the silent "OK to wake" sign; a longer list is a full
    #    step-through routine. Each weekday gets its own start time (routine.start is a
    #    per-day map, or a single string for the same time on all 7 days).
    #
    #    AUTO-CLEAR: the lamp blanks the routine icon on its OWN later in the day — the
    #    firmware ends the morning routine after a while. There is NO firmware "clear
    #    after N minutes" and no clear command we can send, so the controller does not try
    #    to time it. Observed: the icon persists at least ~25 min after the start and is
    #    cleared within a few hours (in the official app it was gone by evening). Exact
    #    timing is firmware-determined and not precisely characterized.
    rt = s.get("routine", {})
    if rt.get("enabled", False):
        tasks_cfg = rt.get("tasks") or ["heart"]
        if isinstance(tasks_cfg, str):
            tasks_cfg = [tasks_cfg]
        tasks = [resolve_icon(t) for t in tasks_cfg]
        starts = day_start_times(rt)
        # reward_sound: play the lamp's celebration when a task is checked off with the
        # button. Off by default (silent nursery); on for a morning routine.
        # Observed live: `01 00` plays routine music but NO check-off celebration — the two
        # nibbles are reversed from their apparent naming, so both are set (`11 00`) to get
        # routine music AND the celebration.
        if rt.get("reward_sound", False):
            vol = int(rt.get("reward_volume", 5))
            cmds.append(("routine reward sound on", Cmd.SET_ROUTINE_MUSIC_STATUS, pack_low_nibbles([1, 1, 0])))
            cmds.append((f"routine volume {vol}", Cmd.SET_ROUTINE_MODE_VOLUME, bytes([vol])))
        else:
            cmds.append(("routine music off", Cmd.SET_ROUTINE_MUSIC_STATUS, bytes([0, 0])))
            cmds.append(("routine volume 0", Cmd.SET_ROUTINE_MODE_VOLUME, bytes([0])))
        for day in WEEKDAYS:
            start = starts[day]
            cmds.append((f"routine {day} @{start}: {tasks}", DAY_ROUTINE_OPCODE[day],
                         encode_day_routine(tasks, start)))
        cmds.append(("routine mode on", Cmd.SET_ROUTINE_MODE_STATUS, bytes([1])))
    else:
        cmds.append(("routine mode off", Cmd.SET_ROUTINE_MODE_STATUS, bytes([0])))
    return cmds


def dry_run(cfg: dict):
    """Print the exact command frames without connecting to the lamp."""
    print("Planned commands (plaintext body, before mpid AES-CTR wrapping):")
    for label, opcode, args in plan_commands(cfg):
        body = build_body(opcode, args)
        print(f"  {label:<34} op=0x{opcode:02x} args={args.hex() or '-':<14} body={body.hex()}")


async def resolve_address(dev: dict) -> str:
    """Resolve a device dict to a BLE address; scan by manufacturer id / apn if absent."""
    from bleak import BleakScanner
    if dev.get("address"):
        return dev["address"]
    apn = str(dev.get("apn", ""))
    print("Scanning for Lumalou...")
    found = await BleakScanner.discover(timeout=12.0, return_adv=True)
    for address, (d, adv) in found.items():
        if MANUFACTURER_ID in (adv.manufacturer_data or {}) or (d.name or "") == apn:
            print(f"  found {address} ({d.name})")
            return address
    raise SystemExit("Lumalou not found in range")


async def scan(cfg: dict):
    """Passively list Lumalou lamps in range with advertised connection state + firmware.

    Read-only: decodes each lamp's 0x03B6 manufacturer data without connecting, so it also
    shows whether a lamp is already bonded to a phone ('connected'), which would block us.
    """
    from bleak import BleakScanner
    names = {str(d.get("address", "")).upper(): d.get("name", "")
             for d in (cfg.get("devices") or [cfg.get("device", {})])}
    print("Scanning for Lumalou lamps (passive, no connection)...")
    found = await BleakScanner.discover(timeout=12.0, return_adv=True)
    lamps = 0
    for address, (d, adv) in found.items():
        mfg = (adv.manufacturer_data or {}).get(MANUFACTURER_ID)
        if mfg is None:
            continue
        info = parse_advertisement(bytes(mfg))
        label = names.get(address.upper()) or d.name or "?"
        print(f"  {address}  {label:<8}  connection={info.get('connection', '?'):<9}"
              f"  fw={info.get('fw', '?')}")
        lamps += 1
    if not lamps:
        print("  none in range")


async def apply_config(session: MpidSession, cfg: dict):
    """Apply the YAML state over the open mpid session."""
    for label, opcode, args in plan_commands(cfg):
        print(f"  -> {label}")
        await session.send_command(opcode, args)
        await asyncio.sleep(0.2)
    state = await session.request_global_state()
    if state is not None:
        print("lamp state:", {k: v for k, v in state.items() if k != "raw"})
    else:
        print("no global-state reply decoded (framing to confirm live)")


async def show_status(session: MpidSession):
    """Read and print the lamp's current state (read-only, silent)."""
    gs = await session.request_global_state()
    print("global state:", {k: v for k, v in gs.items() if k != "raw"} if gs else "no reply")

    cd = await session.request(Cmd.REQUEST_CURRENT_DATE, Resp.CURRENT_DATE)
    print("lamp clock:  ", parse_current_date(cd) if cd else "no reply")

    rs = await session.request(Cmd.REQUEST_R2R_STATUS, Resp.READY_TO_RISE_STATUS)
    print("wake heart:  ", ("on" if rs[0] else "off") if rs else "no reply")

    rt = await session.request(Cmd.REQUEST_R2R_TIMES, Resp.READY_TO_RISE_TIMES)
    print("wake times:  ", parse_bcd_times(rt) if rt else "no reply")


async def watch(session: MpidSession, seconds=None):
    """Print device-pushed frames live (read-only). Ctrl-C or an optional duration stops it.

    Once reads are armed the lamp streams currentDate ~1/s (shown as a collapsed tick count)
    and pushes globalState / routineTaskStatus etc. on device-side state changes - e.g. a
    physical button press advancing a routine surfaces here as a routineTaskStatus frame.
    """
    import time
    await session.arm_reads()
    print("  watching device pushes (Ctrl-C to stop). clock ticks are collapsed; "
          "state changes are printed:")
    end = None if seconds is None else time.monotonic() + float(seconds)
    ticks = 0
    while end is None or time.monotonic() < end:
        try:
            pkt = await asyncio.wait_for(session.rx.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        payload = session.decrypt_payload(pkt)
        if payload is None:
            continue
        dec = decode_response(payload)
        if dec is None:
            continue
        op, data = dec
        if op == Resp.CURRENT_DATE:            # the ~1/s clock heartbeat
            ticks += 1
            if ticks % 10 == 0:                # periodic liveness line with the lamp clock
                print(f"    .. alive, lamp clock {parse_current_date(data)['time']} ({ticks} ticks)")
            continue
        name = RESP_NAMES.get(op, f"op0x{op:02x}")
        if op == Resp.GLOBAL_STATE:
            gs = parse_global_state(data)
            print(f"    {name}: mode={gs['operation_mode']} on={gs['global_status']} "
                  f"song={gs['song']} vol={gs['volume']} light={gs['light_on']} "
                  f"color={gs['light_color']}")
        else:
            print(f"    {name}: {data.hex()}")
    print(f"  ({ticks} clock ticks seen)")


async def show_icon(session: MpidSession, name):
    """Display one routine icon on the cloud face for inspection (silent).

    A routine icon only appears when the lamp clock crosses a scheduled start time,
    so this sets a near-future routine and fast-forwards the clock across it. The
    clock is left advanced so the icon stays shown; run --sync-time or apply to
    restore real time.
    """
    icon = resolve_icon(name)
    now = datetime.datetime.now()
    op = DAY_ROUTINE_OPCODE[WEEKDAYS[now.weekday()]]
    for label, o, a in [
        ("volume 0 (silent)", Cmd.SET_VOLUME, b"\x00"),
        ("routine music off", Cmd.SET_ROUTINE_MUSIC_STATUS, bytes([0, 0])),
        ("routine volume 0", Cmd.SET_ROUTINE_MODE_VOLUME, bytes([0])),
        ("clock show 24h", Cmd.SET_CLOCK_SETTINGS, bytes([1, (1 << 4) | 1])),
        ("routine off", Cmd.SET_ROUTINE_MODE_STATUS, b"\x00"),
        ("clock 11:58", Cmd.SET_CURRENT_DATE, set_current_date_args(now.replace(hour=11, minute=58, second=0))),
        (f"routine [{icon}] @12:00", op, encode_day_routine([icon], "12:00")),
        ("routine mode on", Cmd.SET_ROUTINE_MODE_STATUS, bytes([1])),
        ("speed normal", Cmd.SET_TIME_PRESCALER, bytes([TIME_SCALES["normal"]])),
    ]:
        print(f"  -> {label}")
        await session.send_command(o, a)
        await asyncio.sleep(0.3)
    print(f"  fast-forwarding the clock across 12:00 to show '{icon}' ...")
    await session.send_command(Cmd.SET_TIME_PRESCALER, bytes([TIME_SCALES["60x"]]))
    await asyncio.sleep(4)
    await session.send_command(Cmd.SET_TIME_PRESCALER, bytes([TIME_SCALES["normal"]]))
    print(f"  '{icon}' should be on the cloud face now "
          "(clock left advanced for the preview; run --sync-time or apply to restore)")


async def run_on_device(dev: dict, cfg: dict, action):
    """Connect to one device and run the action (apply / status / show-icon / commands)."""
    from bleak import BleakClient
    name = dev.get("name") or dev.get("address", "?")
    address = await resolve_address(dev)
    print(f"=== {name} ({address}) ===")
    async with BleakClient(address, timeout=25) as client:
        if client.services.get_service(SERVICE) is None:
            print("  control service 4cea0001 not found; skipping")
            return
        session = MpidSession(client)
        await session.handshake()
        print("  session established")
        if action == "status":
            await show_status(session)
        elif isinstance(action, tuple) and action[0] == "watch":
            await watch(session, action[1])
        elif action == "apply":
            await apply_config(session, cfg)
            print("  configuration applied")
        elif isinstance(action, tuple) and action[0] == "show-icon":
            await show_icon(session, action[1])
        else:
            for label, op, args in action:
                print(f"  -> {label}")
                await session.send_command(op, args)
                await asyncio.sleep(0.2)


async def main(cfg_path: str, action):
    """Run the action on every device in the config (cfg['devices'], or a single cfg['device']).

    The same `settings` are applied to each device, so a multi-device config keeps them in
    sync. A device that is out of range is reported and skipped; the rest still run.
    """
    cfg = load_config(cfg_path)
    devices = cfg.get("devices") or [cfg.get("device", {})]
    for dev in devices:
        try:
            await run_on_device(dev, cfg, action)
        except Exception as e:
            print(f"  {dev.get('name') or dev.get('address', '?')}: {type(e).__name__}: {e}")


# Transient one-shot actions (not part of the declarative config).
ACTIONS = {
    "--soothe":   lambda v: [("start soothing", Cmd.SET_GLOBAL_ON, b"\x01")],
    "--stop":     lambda v: [("stop soothing", Cmd.SET_GLOBAL_ON, b"\x00"),
                             ("audio off", Cmd.TURN_OFF_AUDIO, b"")],
    "--nap":      lambda v: [(f"start nap {v or '60min'}", Cmd.START_NAP_TIME,
                              bytes([NAP_DURATION.get((v or "60min").lower(), 4)]))],
    "--stop-nap": lambda v: [("stop nap", Cmd.START_NAP_TIME, b"\x00")],
    "--play":     lambda v: [(f"play {v or 'rain'}", Cmd.PLAY_AUDIO,
                              bytes([AUDIO_COMMAND.get((v or "rain").lower(), 4)]))],
    "--sync-time": lambda v: [("volume 0 (silent)", Cmd.SET_VOLUME, b"\x00"),
                              (f"sync clock {datetime.datetime.now():%a %H:%M:%S}",
                               Cmd.SET_CURRENT_DATE, set_current_date_args(datetime.datetime.now()))],
    # Routine completion "happy" celebration. routineControl 0x6b values verified live:
    # 0 = complete current task / advance (fires the reward sound), 2 = previous, 3 = finish,
    # 4 = cancel. The reward sound needs reward_music enabled (0x69) and a non-zero routine
    # volume, and only fires while the lamp is in routine mode with a task showing (set one via
    # --show-icon or a live routine first).
    "--celebrate": lambda v: [
        ("reward music on", Cmd.SET_ROUTINE_MUSIC_STATUS, pack_low_nibbles([1, 1, 0])),
        (f"routine volume {v or '5'}", Cmd.SET_ROUTINE_MODE_VOLUME, bytes([int(v or 5)])),
        ("routine complete (happy)", Cmd.ROUTINE_CONTROL, b"\x00"),
    ],
    "--routine-cancel": lambda v: [("routine cancel", Cmd.ROUTINE_CONTROL, b"\x04")],
    "--routine-prev":   lambda v: [("routine previous task", Cmd.ROUTINE_CONTROL, b"\x02")],
    "--routine-finish": lambda v: [("routine finish", Cmd.ROUTINE_CONTROL, b"\x03")],
}


if __name__ == "__main__":
    argv = sys.argv[1:]
    cfg_path = next((a for a in argv if a.endswith((".yaml", ".yml"))), "lumalou.yaml")

    def value_after(flag):
        i = argv.index(flag)
        return argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("-") else None

    if "--dry-run" in argv:
        dry_run(load_config(cfg_path))
    elif "--scan" in argv:
        asyncio.run(scan(load_config(cfg_path)))
    elif "--watch" in argv:
        wcfg = load_config(cfg_path)
        warg = value_after("--watch")                       # device name/address, or seconds
        wsecs = int(warg) if warg and warg.isdigit() else None
        wsel = warg if wsecs is None else None
        asyncio.run(run_on_device(pick_device(wcfg, wsel), wcfg, ("watch", wsecs)))
    elif "--status" in argv:
        asyncio.run(main(cfg_path, "status"))
    elif "--show-icon" in argv:
        asyncio.run(main(cfg_path, ("show-icon", value_after("--show-icon"))))
    elif any(f in argv for f in ACTIONS):
        flag = next(f for f in ACTIONS if f in argv)
        asyncio.run(main(cfg_path, ACTIONS[flag](value_after(flag))))
    else:
        asyncio.run(main(cfg_path, "apply"))
