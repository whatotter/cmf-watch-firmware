#!/usr/bin/env python3
"""
flash.py - direct BLE GATT OTA flasher for the CMF Watch Pro 2 (ATS3089C).

Pushes a rebuilt .bin (produced by repack.py; the full "AOTA" OTA container,
identified by the 4-byte 'AOTA' magic) to the watch over a direct BLE GATT
connection, using the CMF "0xF5" encrypted command/firmware protocol that the
official app uses (verified against Gadgetbridge gold source in CONTEXT.md B2).

No phone/app needed. The pairing secret is read from the watch's own debug
shell (`AT GETSECRET`), so no CMF/Nothing vendor servers are required.

Services / characteristics (all UUIDs verified):
  Command channel : 0000fff0-0000-1000-8000-00805f9b34fb
                     notify  fff1   write fff2
  Data channel    : 02f00000-0000-0000-0000-00000000ffe0
                     notify  ffe2   write ffe1
  FIRMWARE channel: 02f00000-0000-0000-0000-00000000fe00   (SEPARATE! OTA goes here)
                     notify  ff02   write ff01
  Shell channel   : 77d4e67c-2fe2-2334-0d35-9ccd078f529c
                     notify 77d4ff02   write 77d4ff01

Frame (11-byte header + chunk), cmd1=0xFFFF for command/firmware/agps:
  f5 | chunkLen:u16 BE | cmd1:u16 BE | chunkCount:u16 BE | chunkIndex:u16 BE (1-based)
     | cmd2:u16 BE | chunk bytes(chunkLen)
  encrypted chunk = AES-128-CBC/PKCS7(slice || crc32_LE(slice), session_key, IV)
  plaintext chunk = slice || crc32_LE(slice)
  fixed IV = 50 51 52 53 54 55 56 57 60 61 62 63 64 65 66 5A

Auth handshake (exact; verified against CmfWatchProSupport + live HCI capture):
  1. shell  AT GETSECRET          -> GETSECRET:<32hex>,OK   (secret = 16 bytes)
  2. rnd1=rand(16); 8047 (plain)  payload rnd1 || sha256(rnd1||secret)
     -> 0048 reply payload rnd2(16) || signed2(32)
     verify signed2 == sha256(rnd2||secret)
     authkey = sha256(rnd1 || rnd2 || secret)[0:16]
  3. 8049 (enc)  payload A5 || "phone-name"   -> 0049  AUTH_WATCH_MAC
  4. 804B (enc)  payload A5                   -> 004C  nonce (16B)
     session_key = sha256(nonce || authkey)[0:16]
  5. 804D (enc)  payload A5                   -> 0004  AUTHENTICATED_CONFIRM_REPLY

Firmware OTA (cmd1=FFFF for all):
  INIT1: 9052 (enc) payload A5        -> A052 [0]=01
  INIT2: 9040 (enc) payload 4-byte version
                                      -> A040 [0]=01
  LOOP (watch drives): A042 (enc) payload offset:i32 BE || length:i32 BE || progress:u8
        -> reply 9042 (PLAINTEXT) payload fw[offset:offset+length]  on FIRMWARE write chan
  FINISH: A041 -> reply 9041 (enc) payload A5

Usage:
    python3 flash.py --scan                    # list nearby BLE devices
    python3 flash.py --services MAC            # dump GATT services of the watch
    python3 flash.py MAC rebuilt.bin           # auth + flash the AOTA container
"""

import argparse
import asyncio
import hashlib
import os
import secrets
import struct
import sys
import zlib

try:
    from bleak import BleakClient, BleakError, BleakScanner
except ImportError:
    sys.exit("[!] install bleak:  pip install bleak")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
except ImportError:
    sys.exit("[!] install cryptography:  pip install cryptography")

# ---------------------------------------------------------------- constants
SVC_CMD = "0000fff0-0000-1000-8000-00805f9b34fb"
CHAR_CMD_READ = "0000fff1-0000-1000-8000-00805f9b34fb"
CHAR_CMD_WRITE = "0000fff2-0000-1000-8000-00805f9b34fb"

SVC_DATA = "02f00000-0000-0000-0000-00000000ffe0"
CHAR_DATA_WRITE = "02f00000-0000-0000-0000-00000000ffe1"
CHAR_DATA_READ = "02f00000-0000-0000-0000-00000000ffe2"

SVC_FW = "02f00000-0000-0000-0000-00000000fe00"
CHAR_FW_WRITE = "02f00000-0000-0000-0000-00000000ff01"
CHAR_FW_READ = "02f00000-0000-0000-0000-00000000ff02"

SVC_SHELL = "77d4e67c-2fe2-2334-0d35-9ccd078f529c"
CHAR_SHELL_WRITE = "77d4ff01-2fe2-2334-0d35-9ccd078f529c"
CHAR_SHELL_READ = "77d4ff02-2fe2-2334-0d35-9ccd078f529c"

AES_IV = bytes.fromhex("5051525354555657606162636465665a")

# opcodes (cmd2)
AUTH_PAIR_REQUEST = 0x8047
AUTH_PAIR_REPLY = 0x0048
AUTH_PHONE_NAME = 0x8049
AUTH_WATCH_MAC = 0x0049
AUTH_NONCE_REQUEST = 0x804B
AUTH_NONCE_REPLY = 0x004C
AUTHENTICATED_CONFIRM_REQUEST = 0x804D
AUTHENTICATED_CONFIRM_REPLY = 0x0004

FW_INIT_1_REQUEST = 0x9052
FW_INIT_1_REPLY = 0xA052
FW_INIT_2_REQUEST = 0x9040
FW_INIT_2_REPLY = 0xA040
FW_FINISH_ACK_1 = 0xA041
FW_FINISH_ACK_2 = 0x9041
FW_CHUNK_REQUEST = 0xA042
FW_CHUNK_WRITE = 0x9042

A5 = b"\xa5"

# commands sent as PLAINTEXT (never encrypted)
PLAINTEXT_CMDS = {
    AUTH_PAIR_REQUEST, AUTH_PAIR_REPLY,
    FW_CHUNK_WRITE,
}


# ---------------------------------------------------------------- crypto
def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def aes_cbc_encrypt(data, key):
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(AES_IV)).encryptor()
    return enc.update(padded) + enc.finalize()


def aes_cbc_decrypt(data, key):
    dec = Cipher(algorithms.AES(key), modes.CBC(AES_IV)).decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------------------------------------------------------------- framing
def max_write_chunk(mtu):
    return min(512, max(23, mtu) - 3)


def make_frames(payload, cmd, session_key, mtu, encrypted=None):
    """Return list of full wire frames (f5 header + chunk) for the payload."""
    if encrypted is None:
        encrypted = cmd not in PLAINTEXT_CMDS

    mwc = max_write_chunk(mtu)

    chunks = []
    if encrypted:
        block = ((mwc - 11) // 16) * 16
        max_payload = block - 4 - 1
        for i in range(0, len(payload), max_payload):
            piece = payload[i:i + max_payload]
            body = piece + struct.pack("<I", zlib.crc32(piece) & 0xFFFFFFFF)
            chunks.append(aes_cbc_encrypt(body, session_key))
    else:
        chunk_size = mwc - 11 - 4 - 2
        for i in range(0, len(payload), chunk_size):
            piece = payload[i:i + chunk_size]
            chunks.append(piece + struct.pack("<I", zlib.crc32(piece) & 0xFFFFFFFF))

    frames = []
    for idx, chunk in enumerate(chunks):
        frames.append(
            b"\xf5"
            + struct.pack(">H", len(chunk))
            + struct.pack(">H", 0xFFFF)
            + struct.pack(">H", len(chunks))
            + struct.pack(">H", idx + 1)
            + struct.pack(">H", cmd)
            + chunk
        )
    return frames


# ---------------------------------------------------------------- packet routing
class PacketRouter:
    """Collects incoming frames (single + multi-chunk) and delivers whole
    payloads keyed by cmd2 into per-command queues. Queue-based (never drops a
    payload that arrived before a waiter existed), unlike single futures."""

    def __init__(self):
        self._queues = {}    # cmd2 -> asyncio.Queue of payloads
        self._buffers = {}   # cmd2 -> (baos, expected)
        self._unknown = []

    async def get(self, cmd2, timeout=30.0):
        q = self._queues.setdefault(cmd2, asyncio.Queue())
        try:
            return await asyncio.wait_for(q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise

    def flush(self, cmd2):
        q = self._queues.get(cmd2)
        if q:
            while not q.empty():
                q.get_nowait()

    def peek(self, cmd2):
        """True if a payload for this cmd2 is already queued (without consuming)."""
        q = self._queues.get(cmd2)
        return bool(q is not None and not q.empty())

    def on_frame(self, data, session_key):
        if not data:
            return
        buf = data
        if buf[0] != 0xf5:
            print(f"    [RX unknown] non-f5: {data[:32].hex()}")
            self._unknown.append(buf)
            return
        chunk_len = struct.unpack(">H", buf[1:3])[0]
        cmd1 = struct.unpack(">H", buf[3:5])[0]
        chunk_count = struct.unpack(">H", buf[5:7])[0]
        chunk_index = struct.unpack(">H", buf[7:9])[0]
        cmd2 = struct.unpack(">H", buf[9:11])[0]
        chunk = buf[11:11 + chunk_len]

        encrypted = cmd2 not in PLAINTEXT_CMDS
        if encrypted and session_key:
            try:
                plain = aes_cbc_decrypt(chunk, session_key)
                payload = plain[:-4]
            except Exception:
                self._unknown.append(buf)
                return
        else:
            payload = chunk

        if cmd2 in (FW_CHUNK_REQUEST, FW_FINISH_ACK_1):
            print(f"    [RX {cmd2:04x}] chunk_count={chunk_count} chunk_index={chunk_index} "
                  f"chunk_len={chunk_len} payload_hex={payload.hex()} raw_frame={buf[:32].hex()}")

        if chunk_count == 1:
            self._deliver(cmd2, payload)
            return

        if chunk_index == 1 or cmd2 not in self._buffers:
            self._buffers[cmd2] = (bytearray(), 1)
        baos, expected = self._buffers[cmd2]
        if chunk_index != expected:
            self._buffers[cmd2] = (bytearray(), 1)
            baos, expected = self._buffers[cmd2]
        baos += payload
        self._buffers[cmd2] = (baos, chunk_index + 1)
        if chunk_index == chunk_count:
            full = bytes(baos)
            self._buffers.pop(cmd2, None)
            self._deliver(cmd2, full)

    def _deliver(self, cmd2, payload):
        q = self._queues.setdefault(cmd2, asyncio.Queue())
        q.put_nowait(payload)


class Client:
    def __init__(self, mac, mtu=247, phone_name="otterwrks.co"):
        self.mac = mac
        self.mtu = mtu
        self.phone_name = phone_name
        self.secret = None
        self.auth_key = None
        self.session_key = None
        self.router = PacketRouter()
        self.client = None
        self._chars = {}
        self._quiet = False

    # -- callbacks --
    def _on_cmd_notify(self, _, data):
        self.router.on_frame(data, self.session_key)

    def _on_fw_notify(self, _, data):
        if data and data[0] == 0xf5:
            cmd2 = struct.unpack(">H", data[9:11])[0] if len(data) >= 11 else 0
            print(f"    [RX fw] cmd2={cmd2:04x} len={len(data)} {data[:20].hex()}...")
        self.router.on_frame(data, self.session_key)

    def _on_data_notify(self, _, data):
        if data and data[0] == 0xf5:
            cmd2 = struct.unpack(">H", data[9:11])[0] if len(data) >= 11 else 0
            print(f"    [RX data] cmd2={cmd2:04x} len={len(data)} {data[:20].hex()}...")
        self.router.on_frame(data, self.session_key)

    def _on_shell_notify(self, _, data):
        pass  # handled in dedicated read wrapper for GETSECRET

    # -- low level --
    async def _char(self, uuid):
        # Cache resolved BleakGATTCharacteristic objects so writes never hit
        # "Service Discovery has not been performed yet".
        if uuid not in self._chars:
            for svc in self.client.services:
                for ch in svc.characteristics:
                    if str(ch.uuid).lower() == uuid.lower():
                        self._chars[uuid] = ch
                        break
                if uuid in self._chars:
                    break
        if uuid not in self._chars:
            raise BleakError(f"Characteristic {uuid} not found")
        return self._chars[uuid]

    async def send(self, chan, cmd, payload, encrypted=None, response=None):
        chobj = await self._char(chan)
        if response is None:
            response = chan in (CHAR_DATA_WRITE,)
        frames = make_frames(payload, cmd, self.session_key, self.mtu, encrypted)
        for i, frame in enumerate(frames):
            await self.client.write_gatt_char(chobj, frame, response=response)

    async def send_and_wait(self, chan, cmd, payload, reply_cmd, timeout=5.0,
                            encrypted=None, response=None):
        await self.send(chan, cmd, payload, encrypted, response)
        try:
            return await self.router.get(reply_cmd, timeout=timeout)
        finally:
            self.router.flush(reply_cmd)

    # -- auth --
    async def get_secret(self):
        fut = asyncio.get_event_loop().create_future()

        def on_shell(_, data):
            s = data.decode(errors="replace").strip()
            if s.startswith("GETSECRET:") and s.endswith(",OK"):
                if not fut.done():
                    fut.set_result(s)

        await self.client.start_notify(CHAR_SHELL_READ, on_shell)
        await self.client.write_gatt_char(CHAR_SHELL_WRITE, b"AT GETSECRET", response=False)
        resp = await asyncio.wait_for(fut, timeout=5.0)
        hexsecret = resp.split("GETSECRET:")[1].split(",")[0]
        self.secret = bytes.fromhex(hexsecret[:32])
        return self.secret

    async def _auth_step(self, cmd, payload, reply_cmd, attempts=5, timeout=6.0, encrypted=None):
        """Send an auth command and wait for its reply, retrying on flaky BLE
        notify delivery (the watch often drops the first reply on Linux/bluez)."""
        last = None
        for i in range(attempts):
            try:
                await self.send(CHAR_CMD_WRITE, cmd, payload, encrypted)
                return await self.router.get(reply_cmd, timeout=timeout)
            except Exception as e:
                last = e
                await asyncio.sleep(0.5)
        raise last or TimeoutError(f"auth step {cmd:04x} never replied")

    async def authenticate(self):
        await self.client.start_notify(CHAR_CMD_READ, self._on_cmd_notify)
        await self.client.start_notify(CHAR_FW_READ, self._on_fw_notify)
        await self.client.start_notify(CHAR_DATA_READ, self._on_data_notify)

        await self.get_secret()
        print(f"[+] secret: {self.secret.hex()}")

        rnd1 = secrets.token_bytes(16)
        signed1 = sha256(rnd1, self.secret)
        payload = rnd1 + signed1
        reply = await self._auth_step(AUTH_PAIR_REQUEST, payload, AUTH_PAIR_REPLY,
                                      encrypted=False)
        rnd2 = reply[:16]
        signed2 = reply[16:48]
        if not secrets.compare_digest(signed2, sha256(rnd2, self.secret)):
            raise RuntimeError("auth: signed2 signature mismatch")
        self.auth_key = sha256(rnd1, rnd2, self.secret)[:16]
        print(f"[+] authkey: {self.auth_key.hex()}")

        self.session_key = self.auth_key

        await self._auth_step(AUTH_PHONE_NAME,
                              A5 + self.phone_name.encode(), AUTH_WATCH_MAC)
        nonce = await self._auth_step(AUTH_NONCE_REQUEST, A5, AUTH_NONCE_REPLY)
        self.session_key = sha256(nonce, self.auth_key)[:16]
        print(f"[+] session key: {self.session_key.hex()}")
        await self._auth_step(AUTHENTICATED_CONFIRM_REQUEST, A5, AUTHENTICATED_CONFIRM_REPLY)
        print("[+] authenticated")

    # -- firmware OTA --
    async def upload_firmware(self, fw, version_bytes=None):
        if fw[:4] != b"AOTA":
            print("[-] warning: image does not start with 'AOTA' magic")
        total = len(fw)
        if version_bytes is None:
            version_bytes = b"\x01" + struct.pack(">I", total)

        # INIT1: send a5 on command channel
        await self.send(CHAR_CMD_WRITE, FW_INIT_1_REQUEST, A5)
        try:
            reply = await self.router.get(FW_INIT_1_REPLY, timeout=4.0)
        except asyncio.TimeoutError:
            print("[-] no A052 (init1 ack)")
            return False
        if reply[:1] != b"\x01":
            print(f"[-] A052 rejected: payload[0]={reply[:1].hex()}")
            return False
        print("[+] init1 ok (A052 [0]=01)")

        # INIT2: send on firmware channel (ff01) - same as Gadgetbridge sendFirmware()
        await self.send(CHAR_FW_WRITE, FW_INIT_2_REQUEST, version_bytes)
        accepted = False
        try:
            reply2 = await self.router.get(FW_INIT_2_REPLY, timeout=4.0)
            accepted = reply2[:1] == b"\x01"
            print(f"[+] init2 ack (A040 [0]={reply2[:1].hex()})" if accepted else
                  f"[-] A040 rejected [0]={reply2[:1].hex()}")
        except asyncio.TimeoutError:
            if self.router.peek(FW_CHUNK_REQUEST):
                accepted = True
                print("[+] init2 accepted (A042 arrived directly)")
        if not accepted:
            print("[-] no A040/A042 from init2")
            return False
        print("[+] init accepted - entering chunk loop")

        # Flush any stale A042/A041 queued before we enter the loop
        self.router.flush(FW_CHUNK_REQUEST)
        self.router.flush(FW_FINISH_ACK_1)

        written = 0
        chobj = await self._char(CHAR_FW_WRITE)
        sent_offsets = set()  # track what we've already responded to
        last_a041 = None

        while True:
            # Check for finish signal (A041) - may arrive mid-transfer as
            # a "transfer incomplete" signal; don't treat as fatal.
            try:
                finish_req = self.router._queues[FW_FINISH_ACK_1].get_nowait()
                payload_hex = finish_req[:8].hex() if finish_req else "empty"
                print(f"  [A041] payload={payload_hex}", flush=True)
                last_a041 = finish_req
            except (asyncio.QueueEmpty, KeyError):
                pass

            # Get next request (blocks if nothing pending)
            try:
                req = await self.router.get(FW_CHUNK_REQUEST, timeout=15.0)
            except asyncio.TimeoutError:
                print("\n[-] no more chunk requests from watch (timeout)")
                break

            if len(req) < 9:
                print(f"[-] short chunk request ({len(req)}B)")
                continue

            offset, length, progress = struct.unpack(">iIB", req[:9])
            if offset < 0 or offset + length > len(fw):
                print(f"[-] request out of range offset={offset:#x} len={length} (file {len(fw):#x})")
                break

            # Zero-length request = restart signal from watch
            if length == 0:
                print(f"  [restart] watch requested reset at offset {offset:#x}, clearing dedup set")
                sent_offsets.clear()
                continue

            # Skip if we already responded to this exact offset
            if offset in sent_offsets:
                continue
            sent_offsets.add(offset)
            # Limit set size to prevent memory growth
            if len(sent_offsets) > 1000:
                sent_offsets.clear()
                sent_offsets.add(offset)

            piece = fw[offset:offset + length]

            # Split into MTU-sized f5 frames (like Gadgetbridge sendCommand)
            frames = make_frames(piece, FW_CHUNK_WRITE, self.session_key, self.mtu,
                                 encrypted=False)

            for frame in frames:
                await self.client.write_gatt_char(chobj, frame, response=False)

            written += length

            pct = progress if progress else (offset + length) * 100 // total
            print(f"    chunk off={offset:#x} len={length} prog={pct}% "
                  f"written={written}/{total}", flush=True)

        print(f"\n[+] wrote {written}/{total} bytes")
        # FINISH: on A041 (finish ack1) send 9041 (a5) on DATA channel (GB handleAck1)
        if last_a041 is not None:
            print(f"[+] last A041 payload={last_a041[:8].hex() if last_a041 else 'empty'}")
        else:
            # Try to wait for a final A041
            try:
                last_a041 = await self.router.get(FW_FINISH_ACK_1, timeout=10.0)
                print(f"[+] got final A041, payload={last_a041[:8].hex() if last_a041 else 'empty'}")
            except asyncio.TimeoutError:
                print("[!] no A041 from watch")

        try:
            await self.send(CHAR_DATA_WRITE, FW_FINISH_ACK_2, A5)
            print("[+] finish ack (9041) sent on data channel")
        except Exception as e:
            print(f"[!] finish ack failed ({e})")
        return written == total

    async def phase2_setup(self):
        import time as _t
        now = int(_t.time())
        tz_off = _t.timezone
        off_ms = -tz_off * 1000
        payload = struct.pack(">ii", now, off_ms)
        await self.send(CHAR_CMD_WRITE, 0x8004, payload)          # TIME
        await self.send(CHAR_CMD_WRITE, 0x8006, A5)               # FIRMWARE_VERSION_GET
        # flush any version ret so it can't be mistaken for an OTA ack later
        self.router.flush(0x0006)
        self.router.flush(0xA040)
        print("[+] phase2 setup: TIME + FIRMWARE_VERSION_GET sent")

    async def resolve_all_chars(self):
        """Pre-resolve all characteristics to avoid 'Service Discovery not performed' errors."""
        for uuid in (CHAR_CMD_WRITE, CHAR_CMD_READ, CHAR_FW_WRITE, CHAR_FW_READ,
                     CHAR_DATA_WRITE, CHAR_DATA_READ, CHAR_SHELL_WRITE, CHAR_SHELL_READ):
            await self._char(uuid)

    async def run_flash(self, fw):
        await self.resolve_all_chars()

        # Acquire real MTU from BlueZ (default is 23 until this is called)
        try:
            backend = self.client._backend
            await backend._acquire_mtu()
            real_mtu = backend.mtu_size
            print(f"[+] negotiated MTU: {real_mtu}")
            self.mtu = real_mtu
        except Exception as e:
            print(f"[!] could not acquire MTU: {e} (using {self.mtu})")

        await self.authenticate()
        await self.phase2_setup()
        ok = await self.upload_firmware(fw)
        await asyncio.sleep(1.0)
        print("[*] done.")
        return ok


async def flash(mac, image_path, mtu=247, phone_name="otterwrks.co"):
    with open(image_path, "rb") as f:
        fw = f.read()
    print(f"[*] image: {image_path}  {len(fw)} bytes")

    async with BleakClient(mac) as client:
        cl = Client(mac, mtu=mtu, phone_name=phone_name)
        cl.client = client
        ok = await cl.run_flash(fw)
    return ok


async def scan():
    print("[*] scanning for BLE devices (10s)...")
    devices = await BleakScanner.discover(timeout=10.0)
    for d in sorted(devices, key=lambda x: x.name or ""):
        if d.name:
            print(f"  {d.address}  {d.name}")
    if not devices:
        print("  (none found)")


async def scan_services(mac):
    async with BleakClient(mac) as client:
        print(f"[+] connected {mac}; services:")
        for svc in client.services:
            print(f"\n  service {svc.uuid}")
            for ch in svc.characteristics:
                props = ",".join(str(p) for p in ch.properties)
                print(f"     char {ch.uuid}  handle {ch.handle}  props {props}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mac", nargs="?", help="watch MAC address")
    ap.add_argument("image", nargs="?", help="AOTA .bin to flash (repack.py output)")
    ap.add_argument("--scan", action="store_true", help="list BLE devices")
    ap.add_argument("--services", metavar="MAC", help="dump GATT services of a device")
    ap.add_argument("--mtu", type=int, default=247, help="BLE MTU (default 247)")
    ap.add_argument("--name", default="otterwrks.co", help="phone name sent in auth")
    ap.add_argument("--dry-run", action="store_true",
                    help="build frames / validate image without connecting")
    args = ap.parse_args()

    if args.dry_run:
        image = args.mac or args.image
        if not image:
            print("[dry-run] needs an <image.bin> argument")
            sys.exit(1)
        fw = open(image, "rb").read()
        print(f"[dry-run] image {image}: {len(fw)} bytes, "
              f"magic={fw[:4]!r}, version={fw[64:96].split(b'\\0')[0].decode(errors='replace')}")
        return

    if args.scan:
        asyncio.run(scan())
        return
    if args.services:
        asyncio.run(scan_services(args.services))
        return
    if not args.mac or not args.image:
        ap.print_help()
        sys.exit(1)
    if not os.path.exists(args.image):
        sys.exit(f"[!] image not found: {args.image}")

    ok = asyncio.run(flash(args.mac, args.image, mtu=args.mtu, phone_name=args.name))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
