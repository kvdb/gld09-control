"""mpid session + packet codec for the Fisher-Price Lumalou.

Crypto: P-256 ECDH -> 32-byte shared secret; the AES-128 session key is derived from
it via _derive_session_key; AES-128-CTR. CRC8 poly 0x07, init 0xFF.

Handshake:
  - read 192-byte device cert from `factory` char (0004):
      cert[25:58]  = device compressed P-256 pubkey
      cert[124:188]= ECDSA signature (we don't verify - we trust the lamp)
      cert[188:192]= device salt
  - generate ephemeral P-256 keypair + 4-byte salt
  - ECDH(our_priv, device_pub) -> shared; aes_key = _derive_session_key(shared)
  - write our_pubkey(33) + our_salt(4) to `session` char (0005)

Packet (0x7E framed), header cleartext, payload encrypted:
  0x7E | counter(4 BE) | len(2 BE, = payload_len+1) | crc8(7 header bytes)
       | AES128-CTR( payload || crc8(payload) )
  AES-CTR IV (16B) = counter(4 BE) || sender_salt(4) || receiver_salt(4) || 00000000
  (sending: sender=our_salt, receiver=device_salt; receiving: swapped)
"""
from __future__ import annotations
import os, asyncio
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVICE = "4cea0001-c678-4202-b5d3-712dbb5e5b14"
TX      = "4cea0002-c678-4202-b5d3-712dbb5e5b14"
RX      = "4cea0003-c678-4202-b5d3-712dbb5e5b14"
FACTORY = "4cea0004-c678-4202-b5d3-712dbb5e5b14"
SESSION = "4cea0005-c678-4202-b5d3-712dbb5e5b14"


def crc8(data: bytes, init: int = 0xFF) -> int:
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if (crc & 0x80) else (crc << 1) & 0xFF
    return crc


def _compress(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.CompressedPoint)


def _derive_session_key(shared: bytes) -> bytes:
    """Derive the AES-128 session key from the 32-byte ECDH shared secret.

    The raw shared secret is whitened by 100 rounds of in-place AES-128-CTR,
    each round keyed by the current first 16 bytes of the 32-byte state. The
    per-round counter block is 4 zero bytes, a 4-byte big-endian round index,
    then the constant b"\\x00mattel\\x00". The session key is the first 16 bytes
    of the final state.
    """
    state = bytearray(shared[:32])
    for i in range(100):
        iv = b"\x00\x00\x00\x00" + i.to_bytes(4, "big") + b"\x00mattel\x00"
        ctr = Cipher(algorithms.AES(bytes(state[:16])), modes.CTR(iv)).encryptor()
        state = bytearray(ctr.update(bytes(state)))
    return bytes(state[:16])


# --- Luma command layer (command encoding) ---
# A command (opcode + args) has plaintext body
#   [0x01, 0x10] + encode([opcode] + args)
#   encode(inner) = [0xFE, n, *inner, crc], n=len(inner),
#   crc = (n XOR inner[0] XOR ... XOR inner[-1]) & 0xFF
# That body is what build_packet() then AES-CTR wraps.
class Cmd:
    # global / mode
    SET_GLOBAL_STATE        = 0x01  # unused by the lamp (args unknown)
    SET_GLOBAL_ON           = 0x03  # soothing on/off toggle [1/0]
    # clock
    SET_CURRENT_DATE        = 0x30  # RTC sync: 4 BCD bytes [hour, minute, second, weekday]
    REQUEST_CURRENT_DATE    = 0x31
    SET_TIME_PRESCALER      = 0x52  # clock speed 0/1/2/3 = 1/10/60/3600x (test)
    SET_CLOCK_SETTINGS      = 0x79  # [show, (brightness<<4)|format]
    # sound
    SET_VOLUME              = 0x37  # [volume 0..9]
    TURN_OFF_AUDIO          = 0x38  # []
    PLAY_AUDIO              = 0x3f  # [audio command 0..7]
    SET_MUSIC_PLAYLIST      = 0x40  # [song id, ...] up to 12
    SET_PLAYLIST_DURATION   = 0x42  # [timer 0..6] (audio sleep timer)
    # light
    SET_LED_BRIGHTNESS      = 0x3a  # [brightness 0..9]
    SET_LIGHT_COLOR         = 0x3c  # [color 0..10]; turns the light on
    TURN_OFF_BACKLIGHT      = 0x3e  # turnOffCloudBackLight: night light off
    SET_SOOTHER_LIGHT_DURATION = 0x6c  # [duration 0..5] (light sleep timer)
    # sleep trainer / nap
    SET_R2R_STATUS          = 0x44  # ready-to-rise ("OK to wake" heart) on/off
    REQUEST_R2R_STATUS      = 0x45
    SET_R2R_TIMES           = 0x46  # 7 daily wake times
    REQUEST_R2R_TIMES       = 0x47
    SET_SLEEPY_TIMES        = 0x48  # 7 daily bedtimes ("stay in bed")
    SET_R2R_ALARMS          = 0x4a
    START_NAP_TIME          = 0x4d  # [nap 0..9]; 0 = stop
    # routines
    SET_ROUTINE_MODE_STATUS = 0x58  # [enabled]
    SET_ROUTINE_MUSIC_STATUS = 0x69  # reduceWithLowNibbles([task_music, reward_music, _])
    ROUTINE_CONTROL         = 0x6b  # [cmd]: 0 complete/advance, 2 previous, 3 finish, 4 cancel (live)
    SET_ROUTINE_MODE_VOLUME = 0x77  # [volume]
    START_ROUTINE_MODE      = 0x7b  # []
    # state
    REQUEST_GLOBAL_STATE    = 0x53


# Device->app response opcodes (measured live). Reads require enableReadTransmission first
# (ENABLE_READ below); responses arrive framed [0x01, 0x50] + FPEncoding([resp_opcode, *payload]).
class Resp:
    GLOBAL_STATE          = 0x02  # 13-byte nibble-packed payload
    CURRENT_DATE          = 0x13  # [BCD hour, minute, second, weekday]
    READY_TO_RISE_STATUS  = 0x21
    READY_TO_RISE_TIMES   = 0x22

# Measured device->app response opcode -> name (live-verified wire values). Used to label
# pushed frames in --watch.
RESP_NAMES = {
    0x02: "globalState", 0x12: "toyIcFwVersion", 0x13: "currentDate", 0x14: "songPlaying",
    0x15: "volume", 0x17: "ledBrightness", 0x18: "lightColor", 0x19: "musicPlaylist",
    0x1a: "playlistDuration", 0x1c: "napStatus", 0x1d: "transmissionMode",
    0x1e: "operationMode", 0x1f: "activityState", 0x20: "currentStage", 0x21: "r2rStatus",
    0x22: "r2rTimes", 0x23: "sleepyTimes", 0x26: "r2rAlarmStatus", 0x27: "r2rAlarms",
    0x28: "timePrescaler", 0x92: "routineModeStatus", 0x93: "routineMusicStatus",
    0x94: "routineTaskStatus", 0x95: "sootherLightDuration", 0x98: "routineModeVolume",
    0x99: "clockSettings",
}

# Raw transport command that arms the lamp to stream read/response frames. Without it, a
# request only gets ack'd (00 7f.. / 01 10 04..) and no data frame is sent. Verified live.
# Once armed the lamp also streams currentDate (0x13) ~1/s and pushes globalState (0x02) /
# routineTaskStatus (0x94) unsolicited on device-side state changes (verified live).
ENABLE_READ = bytes([0x01, 0x50, 0x01])


LIGHT_COLORS = {
    "warm": 0, "warm_spectrum": 0, "red": 1, "yellow": 2, "orange": 3,
    "green": 4, "blue": 5, "purple": 6, "night_light": 7, "nightlight": 7,
    "cool": 8, "cool_spectrum": 8, "rainbow": 9, "off": 10,
}
TIME_SCALES = {"normal": 0, "10x": 1, "60x": 2, "3600x": 3}

# setR2RAlarms per-day alarm index. The OK-to-wake star turns green only with
# an audible alarm armed (firmware-coupled): "sound" arms it at the wake time and
# "silent" (inactive) leaves the star with no event. The +Nmin variants fire N minutes
# after the wake time.
R2R_ALARM_MODES = {
    "silent": 9, "inactive": 9, "off": 9,
    "sound": 0, "active": 0, "now": 0,
    "+1min": 10, "+15min": 1, "+30min": 2, "+45min": 3,
    "+60min": 4, "+75min": 5, "+90min": 6, "+105min": 7, "+120min": 8,
}

# set<Day>Routine opcodes (request variant = +1).
DAY_ROUTINE_OPCODE = {
    "sun": 0x5a, "mon": 0x5c, "tue": 0x5e, "wed": 0x60,
    "thu": 0x62, "fri": 0x64, "sat": 0x66,
}
# datetime.weekday() index (Mon=0..Sun=6) -> DAY_ROUTINE_OPCODE key.
WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
# Routine task -> wire nibble; the 8 fixed icons + 3 custom.
TASK = {
    "none": 0x0, "clothes": 0x1, "wash": 0x2, "teeth": 0x3, "toilet": 0x4,
    "backpack": 0x5, "eat": 0x6, "read": 0x7, "cleanup": 0x8,
    "heart": 0x9, "burst": 0xa, "spiral": 0xb,
}
# playAudio arg (audio command): 0/1 = default/custom playlist, 2..7 = SFX loops.
AUDIO_COMMAND = {
    "playlist": 0, "ready_settle_sleep": 0, "custom": 1,
    "pink_noise": 2, "ocean": 3, "rain": 4, "brown_noise": 5,
    "nature": 6, "highway": 7,
}
# setMusicPlaylist song ids = the lamp's 12 built-in lullabies, wire id 1..12 (in device order).
# The device rejects ids > 12; the SFX (pink noise, ocean, rain, ...) are played via playAudio
# (AUDIO_COMMAND), not the playlist, so they are not song ids here.
SONG_ID = {
    "sleep_baby_sleep": 1, "hour_glass": 2, "frere_jacques": 3,
    "how_lovely_the_evening": 4, "tarrega_lagrima": 5, "whats_the_matter_dear": 6,
    "suo_gan": 7, "water_color_dreams": 8, "dance_of_the_jellyfish": 9,
    "inside_the_bubble": 10, "paper_kites": 11, "crickets_in_space": 12,
}
AUDIO_DURATION = {  # setPlaylistDuration
    "15min": 0, "30min": 1, "60min": 2, "90min": 3, "120min": 4,
    "continuous": 5, "1min": 6,
}
LIGHT_DURATION = {  # setSootherLightDuration
    "15min": 0, "30min": 1, "60min": 2, "90min": 3, "continuous": 4, "1min": 5,
}
NAP_DURATION = {  # startNapTime; 0 = stop
    "stop": 0, "15min": 1, "30min": 2, "45min": 3, "60min": 4,
    "75min": 5, "90min": 6, "105min": 7, "120min": 8, "1min": 9,
}


def music_playlist_args(songs) -> bytes:
    """setMusicPlaylist payload: up to 12 song ids. A name resolves via SONG_ID; an int is used
    as-is. Song ids must be 1..12 (the built-in lullabies); the lamp rejects anything else."""
    out = []
    for s in songs[:12]:
        if isinstance(s, str):
            if s not in SONG_ID:
                raise SystemExit(f"unknown song {s!r}; choose one of: {', '.join(SONG_ID)}")
            sid = SONG_ID[s]
        else:
            sid = int(s)
        if not 1 <= sid <= 12:
            raise SystemExit(f"song id {sid} out of range; playlist song ids are 1..12")
        out.append(sid)
    return bytes(out)


def encode_day_routine(tasks, start_time=None) -> bytes:
    """set<Day>Routine payload: [BCD hour, BCD min] (or FF FF for no time) + 12 task bytes.

    Each task byte = (1-based position << 4) | task nibble; the 12 slots are padded
    with noTask (0x0). The device reads the low nibble for task identity.
    """
    out = bytearray()
    if start_time:
        h, m = ((int(x) for x in start_time.split(":")) if isinstance(start_time, str)
                else start_time)
        out += bytes([to_bcd(h), to_bcd(m)])
    else:
        out += b"\xff\xff"
    nibs = [(TASK.get(t, 0) if isinstance(t, str) else t) for t in tasks][:12]
    nibs += [0x0] * (12 - len(nibs))
    for i, nib in enumerate(nibs):
        out.append((((i + 1) << 4) & 0xF0) | (nib & 0xF))
    return bytes(out)


def fp_encode(inner: bytes) -> bytes:
    """Frame inner bytes with 0xFE marker, length and XOR crc."""
    n = len(inner)
    crc = n
    for b in inner:
        crc ^= b
    return bytes([0xFE, n, *inner, crc & 0xFF])


def fp_decode(frame: bytes):
    """Inverse of fp_encode. Returns inner bytes, or None if the frame is invalid."""
    if len(frame) < 4 or frame[0] != 0xFE:
        return None
    n = frame[1]
    if len(frame) != n + 3:
        return None
    crc = n
    for b in frame[2:2 + n]:
        crc ^= b
    if (crc & 0xFF) != frame[n + 2]:
        return None
    return frame[2:2 + n]


def build_body(opcode: int, args: bytes = b"") -> bytes:
    """Plaintext command body = SPI write prefix + framed opcode/args."""
    return bytes([0x01, 0x10]) + fp_encode(bytes([opcode]) + bytes(args))


def find_fp_frame(payload: bytes):
    """Best-effort: locate and decode the first 0xFE frame in a blob.

    The device->app outer framing is not fully reversed, so scan the decrypted
    payload for a valid frame instead.
    """
    for i, b in enumerate(payload):
        if b != 0xFE:
            continue
        if i + 1 >= len(payload):
            break
        n = payload[i + 1]
        end = i + n + 3
        if end <= len(payload):
            inner = fp_decode(payload[i:end])
            if inner is not None:
                return inner
    return None


def decode_response(body: bytes):
    """Decode a decrypted device->app body into (resp_opcode, payload bytes).

    A command response is framed `[0x01, 0x50] + frame([resp_opcode, *payload])`
    (0x50 = read/response channel; the send side uses [0x01, 0x10] on the write channel).
    The response prefix 0x01 0x50 is verified live. Returns None for the other message
    types (fw-version string, ack/ready).
    """
    if len(body) < 2 or body[0] != 0x01 or body[1] != 0x50:
        return None
    inner = fp_decode(body[2:])
    if not inner:
        return None
    return inner[0], bytes(inner[1:])


def pack_low_nibbles(values) -> bytes:
    """ListIntExt.reduceWithLowNibbles: pack a list of 0-15 values two-per-byte.

    out[i] = (v[2i] << 4) | (v[2i+1] & 0xF); an odd-length input is padded with 0.
    """
    v = list(values)
    if len(v) % 2:
        v.append(0)
    return bytes(((v[i] & 0xF) << 4) | (v[i + 1] & 0xF) for i in range(0, len(v), 2))


def to_bcd(v: int) -> int:
    return ((v // 10) << 4) | (v % 10)


def from_bcd(b: int) -> int:
    return (b >> 4) * 10 + (b & 0xF)


def time_bcd(hhmm: str) -> bytes:
    """'06:45' -> bytes([0x06, 0x45]) (packed BCD hour, minute)."""
    h, m = (int(x) for x in hhmm.split(":"))
    return bytes([to_bcd(h), to_bcd(m)])


def set_current_date_args(dt) -> bytes:
    """4 BCD bytes for setCurrentDate (0x30): [hour, minute, second, weekday(0=Sun..6=Sat)].

    Emits hour, minute, second, then weekday (Sunday=0). The lamp shows hour:minute on
    its clock.
    """
    return bytes([to_bcd(dt.hour), to_bcd(dt.minute), to_bcd(dt.second),
                  to_bcd(dt.isoweekday() % 7)])


def parse_current_date(p: bytes) -> dict:
    if len(p) < 4:
        return {"error": "short current date", "raw": p.hex()}
    days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    wd = from_bcd(p[3])
    return {"weekday": days[wd] if wd < 7 else wd,
            "time": f"{from_bcd(p[0]):02d}:{from_bcd(p[1]):02d}:{from_bcd(p[2]):02d}",
            "raw": p.hex()}


def parse_bcd_times(p: bytes) -> list:
    """Decode a list of [BCD hour, BCD minute] pairs (0xFFFF = unset)."""
    out = []
    for i in range(0, len(p) - 1, 2):
        out.append(None if p[i] == 0xFF else f"{from_bcd(p[i]):02d}:{from_bcd(p[i + 1]):02d}")
    return out


def parse_global_state(p: bytes) -> dict:
    """Decode the 13-byte nibble-packed global-state response payload (opcode 0x11)."""
    if len(p) < 13:
        return {"error": "short global state", "raw": p.hex()}
    hi = lambda i: (p[i] >> 4) & 0xF
    lo = lambda i: p[i] & 0xF
    return {
        "operation_mode": hi(0),
        "global_status": lo(0),
        "song": (lo(1) << 4) | hi(2),
        "volume": lo(2),
        "audio_timer": hi(3),
        "light_on": lo(3),
        "led_brightness": hi(4),
        "light_color": lo(4),
        "time_prescaler": hi(7),
        "stage": lo(7),
        "clock_show": hi(8),
        "clock_brightness": lo(8),
        "clock_format_24h": hi(9),
        "light_duration": hi(11),
        "routine_volume": lo(11),
        "raw": p.hex(),
    }


# BLE advertisement manufacturer payload (company 0x03B6): [0:2]="MB", [2]=format ver,
#   [3]=connectionState, [4:]=ASCII firmware version. bleak returns this with the company
#   id already stripped, so byte 3 here is the connection state.
# The state byte is bit-flagged: bit7 connected to a phone, bit6 pairing, 0 idle.
# Verified live: idle lamps advertise 0x00 and the fw string ("0.3.7"). Both fields
# are readable from a passive scan without connecting.
def _adv_connection_state(b: int) -> str:
    if b & 0x80:
        return "connected"
    if b & 0x40:
        return "pairing"
    if b == 0x00:
        return "idle"
    return f"0x{b:02x}"


def parse_advertisement(mfg: bytes) -> dict:
    """Decode the lamp's 0x03B6 manufacturer data (company id stripped, as bleak gives it).

    Returns {"connection": idle/pairing/connected, "fw": version string}, or {} if the
    payload is not the expected "MB" format.
    """
    if len(mfg) < 4 or mfg[:2] != b"MB":
        return {}
    return {
        "connection": _adv_connection_state(mfg[3]),
        "fw": mfg[4:].split(b"\x00")[0].decode("ascii", "replace") or None,
    }


class MpidSession:
    def __init__(self, client):
        self.client = client
        self.aes_key = b""
        self.our_salt = b""
        self.dev_salt = b""
        self.tx_counter = 0
        self.rx = asyncio.Queue()
        self._reads_armed = False

    def _on_rx(self, _char, data: bytearray):
        self.rx.put_nowait(bytes(data))

    async def handshake(self):
        await self.client.start_notify(RX, self._on_rx)
        cert = bytes(await self.client.read_gatt_char(FACTORY))
        if len(cert) < 192:
            raise RuntimeError(f"unexpected cert length {len(cert)}")
        dev_pub_comp = cert[25:58]
        self.dev_salt = cert[188:192]
        dev_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dev_pub_comp)
        priv = ec.generate_private_key(ec.SECP256R1())
        our_pub = _compress(priv.public_key())
        self.our_salt = os.urandom(4)
        shared = priv.exchange(ec.ECDH(), dev_pub)
        self.aes_key = _derive_session_key(shared)
        await self.client.write_gatt_char(SESSION, our_pub + self.our_salt, response=True)
        return {"dev_pub": dev_pub_comp.hex(), "dev_salt": self.dev_salt.hex(),
                "our_salt": self.our_salt.hex(), "aes_key": self.aes_key.hex()}

    @staticmethod
    def _iv(counter: int, sender_salt: bytes, receiver_salt: bytes) -> bytes:
        return counter.to_bytes(4, "big") + sender_salt + receiver_salt + b"\x00\x00\x00\x00"

    def _ctr(self, iv: bytes, data: bytes) -> bytes:
        return Cipher(algorithms.AES(self.aes_key), modes.CTR(iv)).encryptor().update(data)

    def build_packet(self, payload: bytes) -> bytes:
        self.tx_counter += 1
        c = self.tx_counter
        body = payload + bytes([crc8(payload)])
        hdr7 = b"\x7e" + c.to_bytes(4, "big") + len(body).to_bytes(2, "big")
        hdr = hdr7 + bytes([crc8(hdr7)])
        enc = self._ctr(self._iv(c, self.our_salt, self.dev_salt), body)
        return hdr + enc

    def parse_packet(self, data: bytes):
        if not data or data[0] != 0x7E:
            return {"error": "no 0x7E", "raw": data.hex()}
        counter = int.from_bytes(data[1:5], "big")
        ln = int.from_bytes(data[5:7], "big")
        hdr_ok = data[7] == crc8(data[0:7])
        enc = data[8:8 + ln]
        body = self._ctr(self._iv(counter, self.dev_salt, self.our_salt), enc)
        payload, pcrc = body[:-1], body[-1]
        return {"counter": counter, "len": ln, "hdr_crc_ok": hdr_ok,
                "payload_crc_ok": pcrc == crc8(payload), "payload": payload.hex()}

    def decrypt_payload(self, data: bytes):
        """Decrypt an rx packet to its plaintext body (None on a bad packet)."""
        if not data or data[0] != 0x7E:
            return None
        counter = int.from_bytes(data[1:5], "big")
        ln = int.from_bytes(data[5:7], "big")
        body = self._ctr(self._iv(counter, self.dev_salt, self.our_salt), data[8:8 + ln])
        payload, pcrc = body[:-1], body[-1]
        if pcrc != crc8(payload):
            return None
        return payload

    async def send_command(self, opcode: int, args: bytes = b"", response: bool = False):
        """Encode, encrypt and write one Luma command to the tx characteristic."""
        pkt = self.build_packet(build_body(opcode, args))
        await self.client.write_gatt_char(TX, pkt, response=response)
        return pkt

    async def arm_reads(self):
        """Enable device->app read transmission (once per session). Silent, no side effects."""
        if self._reads_armed:
            return
        await self.client.write_gatt_char(TX, self.build_packet(ENABLE_READ))
        self._reads_armed = True
        await asyncio.sleep(0.2)

    async def request(self, cmd_opcode: int, want_resp: int, timeout: float = 4.0):
        """Send a request command and return the matching response payload bytes."""
        await self.arm_reads()
        while not self.rx.empty():
            self.rx.get_nowait()
        await self.send_command(cmd_opcode)
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                pkt = await asyncio.wait_for(self.rx.get(), timeout=deadline - loop.time())
            except asyncio.TimeoutError:
                break
            payload = self.decrypt_payload(pkt)
            if payload is None:
                continue
            dec = decode_response(payload)
            if dec is None:
                inner = find_fp_frame(payload)   # fallback if the live prefix differs
                dec = (inner[0], bytes(inner[1:])) if inner else None
            if dec and dec[0] == want_resp:
                return dec[1]
        return None

    async def request_global_state(self, timeout: float = 4.0):
        p = await self.request(Cmd.REQUEST_GLOBAL_STATE, Resp.GLOBAL_STATE, timeout)
        return parse_global_state(p) if p is not None else None


async def _selftest():
    import sys
    from bleak import BleakClient
    ADDR = sys.argv[1] if len(sys.argv) > 1 else "AA:BB:CC:DD:EE:01"
    async with BleakClient(ADDR, timeout=25) as c:
        s = MpidSession(c)
        info = await s.handshake()
        print("handshake:", info)
        print("listening 12s for the lamp's encrypted state push (silent, no commands)...")
        try:
            while True:
                pkt = await asyncio.wait_for(s.rx.get(), timeout=12)
                print("RX raw:", pkt.hex())
                print("RX decoded:", s.parse_packet(pkt))
        except asyncio.TimeoutError:
            print("no rx within window")


if __name__ == "__main__":
    asyncio.run(_selftest())
