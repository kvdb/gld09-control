"""Offline regression tests for the Lumalou controller.

Covers the wire format end to end: packet framing, the command opcode table, every
command/response encoder and decoder, and the config planner. The golden byte-vectors
are the expected encodings - a change that breaks them is a regression. No Bluetooth or
lamp is needed.

Run:  .venv/bin/pip install pytest && .venv/bin/pytest
"""
import datetime

import pytest

import lumalou_mpid as m
import lumalou


# --- framing -----------------------------------------------------------------

def test_fp_encode_known_frames():
    assert m.fp_encode(b"\x38") == bytes.fromhex("fe013839")
    assert m.fp_encode(bytes([0x79, 0x01, 0x11])) == bytes.fromhex("fe037901116a")


def test_fp_encode_decode_roundtrip():
    for inner in (b"\x53", b"\x37\x00", bytes(range(20)), b"\x46" + bytes.fromhex("0645") * 7):
        assert m.fp_decode(m.fp_encode(inner)) == inner


def test_fp_decode_rejects_bad_frames():
    good = m.fp_encode(b"\x11\x22")
    assert m.fp_decode(b"\x00" + good[1:]) is None          # wrong marker
    assert m.fp_decode(good[:-1] + b"\x00") is None          # wrong crc
    assert m.fp_decode(good + b"\x00") is None               # wrong length
    assert m.fp_decode(b"\xfe\x01") is None                  # too short


def test_build_body_prefix_and_crc():
    body = m.build_body(0x37, b"\x00")
    assert body[:2] == b"\x01\x10"                           # SPI write header
    assert m.fp_decode(body[2:]) == b"\x37\x00"


# --- session key derivation --------------------------------------------------

def test_derive_session_key_matches_tiny_aes_c():
    # The 100-round AES-128-CTR key derivation. This golden value is pinned so any
    # change to the derivation is caught by the test.
    shared = bytes.fromhex(
        "ab44f123a48aca3c28a138a339c3642f97a2ecddd9a411677cd948119b31b007")
    assert m._derive_session_key(shared).hex() == "49f636065a21f27226ea7e1761c20aef"


# --- opcode table (the /2-corrected real values) -----------------------------

def test_real_opcodes():
    assert (m.Cmd.SET_VOLUME, m.Cmd.SET_LED_BRIGHTNESS, m.Cmd.SET_LIGHT_COLOR) == (0x37, 0x3a, 0x3c)
    assert (m.Cmd.SET_CLOCK_SETTINGS, m.Cmd.REQUEST_GLOBAL_STATE) == (0x79, 0x53)
    assert (m.Cmd.SET_R2R_TIMES, m.Cmd.SET_R2R_STATUS, m.Cmd.SET_SLEEPY_TIMES) == (0x46, 0x44, 0x48)
    assert m.DAY_ROUTINE_OPCODE == {"sun": 0x5a, "mon": 0x5c, "tue": 0x5e, "wed": 0x60,
                                    "thu": 0x62, "fri": 0x64, "sat": 0x66}


# --- golden command frames ---------------------------------------------------

GOLDEN = {
    "volume 0":        (m.Cmd.SET_VOLUME, b"\x00", "0110fe02370035"),
    "sound off":       (m.Cmd.TURN_OFF_AUDIO, b"", "0110fe013839"),
    "light off":       (m.Cmd.TURN_OFF_BACKLIGHT, b"", "0110fe013e3f"),
    "light green":     (m.Cmd.SET_LIGHT_COLOR, b"\x04", "0110fe023c043a"),
    "brightness 1":    (m.Cmd.SET_LED_BRIGHTNESS, b"\x01", "0110fe023a0139"),
    "clock 24h shown": (m.Cmd.SET_CLOCK_SETTINGS, b"\x01\x11", "0110fe037901116a"),
    "clock speed 1x":  (m.Cmd.SET_TIME_PRESCALER, b"\x00", "0110fe02520050"),
    "trainer on":      (m.Cmd.SET_R2R_STATUS, b"\x01", "0110fe02440147"),
    "alarms silent":   (m.Cmd.SET_R2R_ALARMS, bytes.fromhex("99999990"), "0110fe054a9999999046"),
    "alarms sound":    (m.Cmd.SET_R2R_ALARMS, bytes.fromhex("00000000"), "0110fe054a000000004f"),
    "req global":      (m.Cmd.REQUEST_GLOBAL_STATE, b"", "0110fe015352"),
    "req date":        (m.Cmd.REQUEST_CURRENT_DATE, b"", "0110fe013130"),
    "play rain":       (m.Cmd.PLAY_AUDIO, b"\x04", "0110fe023f0439"),
    "audio timer 30":  (m.Cmd.SET_PLAYLIST_DURATION, b"\x01", "0110fe02420141"),
    "routine mode on": (m.Cmd.SET_ROUTINE_MODE_STATUS, b"\x01", "0110fe0258015b"),
}


def test_golden_frames():
    for name, (op, args, expect) in GOLDEN.items():
        assert m.build_body(op, args).hex() == expect, name


def test_wake_times_and_playlist_frames():
    assert m.build_body(m.Cmd.SET_R2R_TIMES, m.time_bcd("06:45") * 7).hex() == \
        "0110fe0f4606450645064506450645064506450a"
    assert m.build_body(m.Cmd.SET_MUSIC_PLAYLIST,
                        m.music_playlist_args(["sleep_baby_sleep", "suo_gan"])).hex() == \
        "0110fe0340010745"


# --- BCD / date --------------------------------------------------------------

def test_bcd():
    assert m.to_bcd(0) == 0x00 and m.to_bcd(45) == 0x45 and m.to_bcd(23) == 0x23
    for n in range(100):
        assert m.from_bcd(m.to_bcd(n)) == n


def test_time_bcd():
    assert m.time_bcd("06:45") == b"\x06\x45"


def test_set_current_date_weekday():
    # 2026-06-09 is a Tuesday -> weekday 2; bytes are [hour, minute, second, weekday]
    args = m.set_current_date_args(datetime.datetime(2026, 6, 9, 23, 5, 41))
    assert args == bytes([0x23, 0x05, 0x41, 0x02])
    assert m.set_current_date_args(datetime.datetime(2026, 6, 7, 9, 0))[3] == 0x00  # Sunday -> 0
    d = m.parse_current_date(args)
    assert d["weekday"] == "Tue" and d["time"] == "23:05:41"


def test_pack_low_nibbles_alarms():
    assert m.pack_low_nibbles([9] * 7) == bytes([0x99, 0x99, 0x99, 0x90])
    assert m.pack_low_nibbles([1, 2, 3]) == bytes([0x12, 0x30])


# --- routine encoding --------------------------------------------------------

def test_encode_day_routine_golden():
    r = m.encode_day_routine(["toilet", "wash", "teeth", "clothes", "eat"], "07:00")
    assert r.hex() == "0700" + "1422334156" + "60708090a0b0c0"
    assert len(r) == 14                                      # 2 time + 12 task slots


def test_encode_day_routine_no_time_and_padding():
    r = m.encode_day_routine(["read"], None)
    assert r[:2] == b"\xff\xff"                              # no-time sentinel
    assert len(r) == 14 and r[2] == (1 << 4) | m.TASK["read"]
    assert r[3] == (2 << 4) | 0                              # padded with noTask


def test_music_playlist_remap_and_cap():
    # names -> lamp lullaby wire ids 1..12 (device song order)
    assert m.music_playlist_args(["sleep_baby_sleep", "suo_gan", "frere_jacques"]) == bytes([1, 7, 3])
    assert len(m.music_playlist_args(["frere_jacques"] * 20)) == 12  # capped at 12
    with pytest.raises(SystemExit):
        m.music_playlist_args(["ocean"])           # SFX (id 14) is not a playlist song
    with pytest.raises(SystemExit):
        m.music_playlist_args(["not_a_song"])      # unknown name fails fast


# --- response decoders -------------------------------------------------------

def test_decode_response():
    state = bytes(range(13))
    # device->app response prefix is 0x01 0x50 (verified live), not 0x02 0x50
    body = bytes([0x01, 0x50]) + m.fp_encode(bytes([m.Resp.GLOBAL_STATE]) + state)
    assert m.decode_response(body) == (m.Resp.GLOBAL_STATE, state)
    # the send-side prefix must NOT decode as a response
    assert m.decode_response(bytes([0x01, 0x10]) + m.fp_encode(b"\x11\x00")) is None
    # heuristic fallback still locates the frame in a noisy buffer
    assert m.find_fp_frame(b"\xaa" + body + b"\xbb") == bytes([m.Resp.GLOBAL_STATE]) + state


def test_decode_response_real_capture():
    # real global-state frame captured live from Elin's lamp (plaintext body after decrypt)
    body = bytes.fromhex("0150fe0e02000005505004000012011145004a")
    op, payload = m.decode_response(body)
    assert op == m.Resp.GLOBAL_STATE == 0x02
    gs = m.parse_global_state(payload)
    assert gs["volume"] == 5 and gs["led_brightness"] == 5
    assert gs["clock_show"] == 1 and gs["clock_brightness"] == 2


def test_parse_global_state_nibbles():
    p = bytearray(13)
    p[2] = 0x07          # volume = 7
    p[3] = 0x01          # light on
    p[4] = 0x90          # brightness = 9
    p[8] = 0x11          # clock show=1, clock brightness=1
    p[9] = 0x10          # clock format 24h = 1
    gs = m.parse_global_state(bytes(p))
    assert (gs["volume"], gs["light_on"], gs["led_brightness"]) == (7, 1, 9)
    assert (gs["clock_show"], gs["clock_brightness"], gs["clock_format_24h"]) == (1, 1, 1)


def test_parse_bcd_times():
    assert m.parse_bcd_times(m.time_bcd("06:45") * 2) == ["06:45", "06:45"]
    assert m.parse_bcd_times(bytes([0xFF, 0xFF, 0x07, 0x30])) == [None, "07:30"]


def test_parse_advertisement():
    # Real capture from Elin/Oscar (fw 0.3.7, idle): "MB" + ver + status byte + ASCII fw.
    assert m.parse_advertisement(bytes.fromhex("4d420100302e332e37")) == {
        "connection": "idle", "fw": "0.3.7"}
    # Status byte is bit-flagged (bit7 connected, bit6 pairing).
    assert m.parse_advertisement(bytes.fromhex("4d420180302e332e37"))["connection"] == "connected"
    assert m.parse_advertisement(bytes.fromhex("4d420140302e332e37"))["connection"] == "pairing"
    assert m.parse_advertisement(b"\x00\x01\x02\x03") == {}   # not the MB format


# --- planner -----------------------------------------------------------------

DEFAULT_CFG = {
    "settings": {
        "sound": {"enabled": False, "volume": 0},
        "light": {"enabled": False, "brightness": "min"},
        "clock": {"show": True, "format": "24h", "sync_time": False, "time_scale": "normal"},
        "sleep_trainer": {"enabled": True, "bedtime": "19:00", "wake": "06:45", "alarm": "silent"},
    }
}


def test_plan_silent_default_order():
    cmds = lumalou.plan_commands(DEFAULT_CFG)
    # volume goes first so configuration never makes noise
    assert cmds[0][1] == m.Cmd.SET_VOLUME and cmds[0][2] == b"\x00"
    ops = [op for _, op, _ in cmds]
    assert m.Cmd.TURN_OFF_AUDIO in ops and m.Cmd.TURN_OFF_BACKLIGHT in ops
    # sleep trainer must save in this order: sleepy -> times -> alarms -> status
    seq = [op for op in ops if op in (m.Cmd.SET_SLEEPY_TIMES, m.Cmd.SET_R2R_TIMES,
                                      m.Cmd.SET_R2R_ALARMS, m.Cmd.SET_R2R_STATUS)]
    assert seq == [m.Cmd.SET_SLEEPY_TIMES, m.Cmd.SET_R2R_TIMES,
                   m.Cmd.SET_R2R_ALARMS, m.Cmd.SET_R2R_STATUS]


def test_plan_sleep_trainer_alarm_modes():
    def alarm_args(mode):
        cfg = {"settings": dict(DEFAULT_CFG["settings"],
                                sleep_trainer={"enabled": True, "bedtime": "19:00",
                                               "wake": "06:45", "alarm": mode})}
        cmds = lumalou.plan_commands(cfg)
        return next(a for _, op, a in cmds if op == m.Cmd.SET_R2R_ALARMS)
    assert alarm_args("silent") == bytes.fromhex("99999990")   # inactive: no sound, no green
    assert alarm_args("sound") == bytes.fromhex("00000000")    # active: green star + tone
    assert alarm_args("+30min") == bytes.fromhex("22222220")   # activeAfter30min
    # bedtime + wake carry through as BCD pairs x7
    cmds = lumalou.plan_commands(DEFAULT_CFG)
    bedtime = next(a for _, op, a in cmds if op == m.Cmd.SET_SLEEPY_TIMES)
    assert bedtime == m.time_bcd("19:00") * 7


def test_plan_sleep_trainer_off():
    cfg = {"settings": dict(DEFAULT_CFG["settings"], sleep_trainer={"enabled": False})}
    cmds = lumalou.plan_commands(cfg)
    ops = [op for _, op, _ in cmds]
    assert m.Cmd.SET_SLEEPY_TIMES not in ops and m.Cmd.SET_R2R_TIMES not in ops
    status = [a for _, op, a in cmds if op == m.Cmd.SET_R2R_STATUS]
    assert status == [b"\x00"]   # trainer disabled


def test_plan_soother_light_timer():
    # opt-in: light.timer emits SET_SOOTHER_LIGHT_DURATION with the mapped value
    cfg = {"settings": dict(DEFAULT_CFG["settings"],
                            light={"enabled": False, "brightness": "min", "timer": "30min"})}
    dur = [a for _, op, a in lumalou.plan_commands(cfg) if op == m.Cmd.SET_SOOTHER_LIGHT_DURATION]
    assert dur == [bytes([m.LIGHT_DURATION["30min"]])]
    # absent when not configured
    assert m.Cmd.SET_SOOTHER_LIGHT_DURATION not in [op for _, op, _ in lumalou.plan_commands(DEFAULT_CFG)]


def test_resolve_icon_validation():
    assert lumalou.resolve_icon("Heart") == "heart"   # case-normalized
    assert lumalou.resolve_icon("eat") == "eat"
    assert set(lumalou.ICONS) == set(m.TASK) - {"none"} and len(lumalou.ICONS) == 11
    with pytest.raises(SystemExit):
        lumalou.resolve_icon("sparkle")               # unknown icon fails loudly
    with pytest.raises(SystemExit):
        lumalou.resolve_icon("none")                  # noTask is not selectable


# mon-fri 06:45, sat-sun 07:00.
WEEKDAY_START = {"mon": "06:45", "tue": "06:45", "wed": "06:45", "thu": "06:45",
                 "fri": "06:45", "sat": "07:00", "sun": "07:00"}


def test_day_start_times_string_and_map():
    # a plain string applies to all 7 days
    assert lumalou.day_start_times({"start": "06:45"}) == {d: "06:45" for d in m.WEEKDAYS}
    # a per-day map keeps each day's own time; a missing day falls back to the first given
    partial = lumalou.day_start_times({"start": {"mon": "06:30", "sat": "08:00"}})
    assert partial["mon"] == "06:30" and partial["sat"] == "08:00"
    assert partial["tue"] == "06:30"   # missing -> first time given


def test_plan_routine_heart_per_day():
    cfg = {"settings": dict(DEFAULT_CFG["settings"], sleep_trainer={"enabled": False},
                            routine={"enabled": True, "tasks": ["heart"], "start": WEEKDAY_START})}
    by_op = {op: a for _, op, a in lumalou.plan_commands(cfg)}
    # silent: routine music off + routine volume 0
    assert by_op[m.Cmd.SET_ROUTINE_MUSIC_STATUS] == b"\x00\x00"
    assert by_op[m.Cmd.SET_ROUTINE_MODE_VOLUME] == b"\x00"
    # heart (task 9) at each day's own start; slot-1 byte = (1<<4)|9 = 0x19
    for day, start in WEEKDAY_START.items():
        assert by_op[m.DAY_ROUTINE_OPCODE[day]] == m.encode_day_routine(["heart"], start)
    assert by_op[m.DAY_ROUTINE_OPCODE["mon"]][:3].hex() == "064519"
    assert by_op[m.DAY_ROUTINE_OPCODE["sat"]][:3].hex() == "070019"
    assert by_op[m.Cmd.SET_ROUTINE_MODE_STATUS] == b"\x01"   # enabled last


def test_plan_routine_heart_string_start():
    # a single string start applies to all 7 days
    cfg = {"settings": dict(DEFAULT_CFG["settings"], sleep_trainer={"enabled": False},
                            routine={"enabled": True, "tasks": ["heart"], "start": "06:45"})}
    by_op = {op: a for _, op, a in lumalou.plan_commands(cfg)}
    for day in m.WEEKDAYS:
        assert by_op[m.DAY_ROUTINE_OPCODE[day]] == m.encode_day_routine(["heart"], "06:45")


def test_plan_routine_multi_task_sequence():
    # tasks list -> a real step-through routine (positions 1,2,3 in the slot high nibble)
    cfg = {"settings": dict(DEFAULT_CFG["settings"], sleep_trainer={"enabled": False},
                            routine={"enabled": True, "start": "07:00",
                                     "tasks": ["toilet", "wash", "teeth"]})}
    by_op = {op: a for _, op, a in lumalou.plan_commands(cfg)}
    assert by_op[m.DAY_ROUTINE_OPCODE["mon"]] == m.encode_day_routine(["toilet", "wash", "teeth"], "07:00")


def test_plan_music_and_routines_all_crc_valid():
    cfg = {"settings": dict(DEFAULT_CFG["settings"],
                            sound={"enabled": True, "volume": 2, "play": "playlist",
                                   "songs": ["suo_gan"], "timer": "60min"},
                            routines={"mon": {"start": "07:30", "tasks": ["wash", "teeth"]}})}
    cmds = lumalou.plan_commands(cfg)
    for _, op, args in cmds:
        body = m.build_body(op, args)
        assert body[:2] == b"\x01\x10"
        assert m.fp_decode(body[2:]) == bytes([op]) + bytes(args)
    ops = [op for _, op, _ in cmds]
    assert m.Cmd.SET_MUSIC_PLAYLIST in ops and m.Cmd.SET_ROUTINE_MODE_STATUS in ops


# --- CLI one-shot actions ----------------------------------------------------

def test_cli_actions():
    # bool polarity: true -> 1
    assert lumalou.ACTIONS["--soothe"](None)[0][1:] == (m.Cmd.SET_GLOBAL_ON, b"\x01")
    assert lumalou.ACTIONS["--nap"]("30min")[0][1:] == (m.Cmd.START_NAP_TIME, bytes([2]))
    assert lumalou.ACTIONS["--play"]("rain")[0][1:] == (m.Cmd.PLAY_AUDIO, bytes([4]))
    stop = lumalou.ACTIONS["--stop"](None)
    assert stop[0][1:] == (m.Cmd.SET_GLOBAL_ON, b"\x00")
    assert stop[1][1] == m.Cmd.TURN_OFF_AUDIO


def test_cli_sync_time_silent():
    cmds = lumalou.ACTIONS["--sync-time"](None)
    assert cmds[0][1:] == (m.Cmd.SET_VOLUME, b"\x00")        # volume 0 first: silent
    assert cmds[1][1] == m.Cmd.SET_CURRENT_DATE
    assert len(cmds[1][2]) == 4                              # 4 BCD bytes [h, m, s, weekday]
