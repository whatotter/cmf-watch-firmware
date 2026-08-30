#!/usr/bin/env python3
"""
btsnoop_decode.py - parse an Android Bluetooth HCI snoop log and print the GATT
(ATT) operations, correlating characteristic handles to our known CPF Watch Pro 2
service UUIDs.

Usage:
    python3 btsnoop_decode.py btsnoop_hci.log

Correlations (from `flash.py --services` on a live watch):
    handle 37 = e49a3002 (write-without-response/write)  -> OTA/app data (sent)
    handle 39 = e49a3003 (notify)                       -> OTA/app responses
    handle 49 = f48a24c1 (write)
    handle 51 = f48a25c2 (notify)
    handle 43 = 02f00000..ff01 (write)  debug/uart
    handle 45 = 02f00000..ff02 (notify)
    handle 55 = fff2 (write) ; handle 57 = fff1 (notify)
    handle 61 = 77d4ff01 (write); handle 63 = 77d4ff02 (notify)
    handle 28 = ffd1 (write); 30 = ffd2 (notify); 33=ffd3 (write+notify)
"""

import struct
import sys
import binascii

HANDLES = {
    37: "e49a3002:WRITE(OTA?)",
    39: "e49a3003:NOTIFY(OTA?)",
    49: "f48a24c1:WRITE",
    51: "f48a25c2:NOTIFY",
    43: "ff01:WRITE(uart)",
    45: "ff02:NOTIFY(uart)",
    55: "fff2:WRITE",
    57: "fff1:NOTIFY",
    61: "77d4ff01:WRITE",
    63: "77d4ff02:NOTIFY",
    67: "ffe1:WRITE",
    69: "ffe2:NOTIFY",
    28: "ffd1:WRITE",
    30: "ffd2:NOTIFY",
    33: "ffd3:W/N",
    10: "2a00:DEVNAME",
    17: "2a19:BATTERY",
}

ATT_OPS = {
    0x02: "ATTR_DISC_ALL", 0x04: "READ_REQ", 0x05: "READ_RSP",
    0x06: "READ_BLOB_REQ", 0x0B: "READ_MULTI", 0x10: "WRITE_REQ",
    0x0D: "WRITE_BY_GROUP", 0x12: "WRITE_REQ", 0x13: "WRITE_RSP",
    0x16: "PREP_WRITE", 0x18: "EXEC_WRITE", 0x1B: "NOTIFY(handle)",
    0x1E: "INDICATE", 0x52: "WRITE_CMD(norsp)",
}

def h4_payload(record_data, linktype):
    # Android btsnoop is usually HCI UART H4 (1002) => 1-byte hci type prefix.
    if linktype in (1002, 0x3ea):
        return record_data[1:], record_data[0] if record_data else None
    # 1001 = HCI, 1000 = legacy; assume raw hci
    return record_data, None

def parse_acl_att(hci):
    if len(hci) < 4:
        return None
    handle_flags = struct.unpack_from('<H', hci, 0)[0]
    l2len = struct.unpack_from('<H', hci, 2)[0]
    body = hci[4:4 + l2len]
    if len(body) < 4:
        return None
    pdu_len = struct.unpack_from('<H', body, 0)[0]
    cid = struct.unpack_from('<H', body, 2)[0]
    if cid != 0x0004:  # not ATT
        return None
    att = body[4:4 + pdu_len]
    if not att:
        return None
    op = att[0]
    if op in (0x10, 0x12, 0x52):  # write req / write cmd
        handle = struct.unpack_from('<H', att, 1)[0]
        value = att[3:]
        return ('WRITE', handle, value)
    if op in (0x1B, 0x1E):  # notification / indication
        handle = struct.unpack_from('<H', att, 1)[0]
        value = att[3:]
        return ('NOTIFY', handle, value)
    if op == 0x13:  # write response
        return ('WRITE_RSP', None, None)
    if op == 0x04:  # read request
        handle = struct.unpack_from('<H', att, 1)[0]
        return ('READ_REQ', handle, None)
    if op == 0x05:
        return ('READ_RSP', None, att[1:])
    if op == 0x02:  # MTU / discover
        return (f'P_0x{op:02x}', None, att[1:])
    return (f'P_0x{op:02x}', None, att[1:])

def first_length(body):
    """Read first record's included-length as standard 32B (8B BE lengths)."""
    if len(body) < 8:
        return None
    return struct.unpack_from('>Q', body, 0)[0]

def main(path):
    raw = open(path, 'rb').read()
    if raw[:8] == b'btsnoop\x00':
        ver, linktype = struct.unpack_from('>II', raw, 8)
        body = raw[16:]
    else:
        print("[!] not a btsnoop file")
        return
    print(f"# btsnoop version={ver} data_link={linktype} ({len(body)} payload bytes)")

    # Detect record header width: standard btsnoop uses 8-byte lengths (32B hdr);
    # Android's actual btsnoop_hci.log uses a 24-byte record header with 4-byte
    # lengths + 8-byte timestamp. Decide by sanity-checking the first length.
    hdr = 32
    o0 = first_length(body)
    if o0 is None or o0 < 0 or o0 > 100000:
        hdr = 24
    print(f"# record header width={hdr}")

    rec = 0
    off = 0
    ndata = 0
    while off + hdr <= len(body):
        if hdr == 32:
            orig_len = struct.unpack_from('>Q', body, off)[0]
            incl_len = struct.unpack_from('>Q', body, off + 8)[0]
            ts = struct.unpack_from('>Q', body, off + 24)[0]
        else:
            orig_len = struct.unpack_from('>I', body, off)[0]
            incl_len = struct.unpack_from('>I', body, off + 4)[0]
            ts = struct.unpack_from('>Q', body, off + 16)[0]
        start = off + hdr
        data = body[start:start + incl_len]
        rec += 1
        off = start + incl_len

        hci = data[1:] if (linktype in (1002, 0x3ea) and data) else data
        if not hci:
            continue
        r = parse_acl_att(hci)
        if r is None:
            continue
        kind, handle, value = r
        ndata += 1
        if value is not None and len(value) > 40:
            print(f"[rec {rec}] {kind:12} handle={handle} ({HANDLES.get(handle,'?')}): "
                  f"{value[:40].hex()} ... (+{len(value)-40}B)")
        elif handle is not None:
            print(f"[rec {rec}] {kind:12} handle={handle} ({HANDLES.get(handle,'?')}): "
                  f"{value.hex() if value else ''}")
        else:
            print(f"[rec {rec}] {kind:12}: {value.hex() if value else ''}")
    print(f"\n# total records={rec}, ATT payloads={ndata}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])
