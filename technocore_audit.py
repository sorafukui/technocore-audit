#!/usr/bin/env python3
"""technocore_audit — checks two things Technocore currently reports incorrectly.

1. mailbox liveness.  Setup Check derives `mailbox=pass` from the DID-note string
   alone.  An advertised mailbox that does not exist, or exists but has never been
   written to, is indistinguishable from a working one by that method:

       - GET  /r/<mb-room>              -> count 0 / first_seq null, whether or not
                                           the room exists
       - unsigned write to <mb-room>    -> 403 (mailbox: signed writes only) whether
                                           or not the room exists, because the class
                                           check runs before the existence check

   So neither a read nor an unsigned write proves existence.  What *is* provable is
   liveness: a mailbox whose first message is signed by the DID that advertises it.
   The reference deployment already does this (its mailbox seq 1 is a signed
   "Mailbox initialized" beacon) -- it just is not checked.

2. room capacity.  /rooms prints "<n> rooms (cap <max>)", but never enumerates the
   p- / mb-p- / e-p- classes, while `max_rooms` counts them ("service-wide and
   fail-closed").  The printed gauge therefore overstates headroom by the number of
   unlisted rooms -- and mailboxes are mb-p-, so the gauge is least accurate exactly
   during an onboarding surge.

Read-only apart from `capacity --probe`, which attempts one unlisted p- room.
"""
import argparse
import base64
import hashlib
import json
import re
import os
import sys
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE = "https://technocore.chat"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def did_pubkey(did: str) -> bytes:
    """Decode did:key:z... -> 32 raw Ed25519 bytes. Raises on anything else."""
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key multibase base58btc identifier")
    raw = b58decode(did[len("did:key:z"):])
    if raw[:2] != b"\xed\x01":
        raise ValueError("multicodec is not ed25519-pub (0xed01)")
    if len(raw) != 34:
        raise ValueError("expected 34 bytes after multibase, got %d" % len(raw))
    Ed25519PublicKey.from_public_bytes(raw[2:])  # rejects non-canonical points
    return raw[2:]


def note_paths(did: str):
    """Sharded path first, then the legacy path readers fall back to."""
    fp = hashlib.sha256(did.encode()).hexdigest()[:16]
    return ["did-%s/%s" % (fp[:2], fp[2:]), "did/%s" % fp]


def http(path: str):
    """Returns (status, body). Never raises on HTTP error status."""
    try:
        with urllib.request.urlopen(BASE + path, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


MAILBOX_RE = re.compile(r"mailbox:\s*(mb-[a-z0-9][a-z0-9_-]{0,45})")


def audit_mailbox(did: str) -> dict:
    out = {"did": did}
    try:
        did_pubkey(did)
        out["did_encoding"] = "pass"
    except Exception as e:
        return dict(out, did_encoding="fail", reason=str(e), mailbox="skip")

    note = None
    for p in note_paths(did):
        st, body = http("/kv/" + p)
        if st == 200:
            note, out["note"] = body, "/kv/" + p
            break
    if note is None:
        return dict(out, directory="fail", mailbox="skip",
                    reason="no DID note at either the sharded or the legacy path")
    out["directory"] = "pass"

    m = MAILBOX_RE.search(note)
    if not m:
        return dict(out, mailbox="warn", reason="no mailbox advertised in the note")
    room = m.group(1)
    out["mailbox_room"] = room

    st, body = http("/r/%s?format=json" % room)
    if st != 200:
        return dict(out, mailbox="fail", reason="cannot read the advertised room (HTTP %d)" % st)
    msgs = json.loads(body).get("messages", [])

    if not msgs:
        # Cannot distinguish "never created" from "created, never written". Either
        # way nothing proves a sender can reach it, so this is not a pass.
        return dict(out, mailbox="fail",
                    reason="advertised but empty: no message proves this room exists "
                           "or that its owner can receive; unsigned probes return 403 "
                           "either way")

    owner = [m for m in msgs if m.get("from") == did]
    if not owner:
        return dict(out, mailbox="warn", messages=len(msgs),
                    reason="room has traffic but no message signed by the advertising "
                           "DID; the owner has never attested control of it")
    return dict(out, mailbox="pass", messages=len(msgs),
                attested_at_seq=owner[0]["seq"],
                reason="first owner-signed message at seq %d attests the room is live"
                       % owner[0]["seq"])


def audit_capacity(probe: bool) -> dict:
    st, rooms = http("/rooms")
    m = re.search(r"of (\d+) rooms \(cap (\d+)", rooms)
    listed, cap = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    st, cfg = http("/config")
    conf_cap = json.loads(cfg).get("settings", {}).get("max_rooms")

    out = {"listed_rooms": listed, "cap": cap, "config_max_rooms": conf_cap,
           "apparent_headroom": (cap - listed) if (cap and listed) else None}
    if not probe:
        return out

    name = "p-" + os.urandom(12).hex()
    st, body = http("/r/%s/say/probe/x" % name)
    creatable = st == 200
    out["probe_room"] = name
    out["new_room_creatable"] = creatable
    if not creatable and "room limit" in body:
        out["actual_headroom"] = 0
        out["unlisted_rooms_at_least"] = out["apparent_headroom"]
        out["verdict"] = ("/rooms overstates headroom by at least %d rooms: no room of "
                          "any class can be created" % out["apparent_headroom"])
    elif creatable:
        out["verdict"] = "a new room was creatable; the printed gauge is consistent"
    else:
        out["verdict"] = "creation refused for another reason: HTTP %d %s" % (st, body[:120])
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    mb = sub.add_parser("mailbox", help="audit a DID's advertised mailbox")
    mb.add_argument("did", nargs="+")
    cp = sub.add_parser("capacity", help="compare the printed room gauge with reality")
    cp.add_argument("--probe", action="store_true",
                    help="attempt one unlisted p- room to measure true headroom")
    a = ap.parse_args()

    if a.cmd == "mailbox":
        res = [audit_mailbox(d) for d in a.did]
        print(json.dumps(res if len(res) > 1 else res[0], indent=2))
        sys.exit(0 if all(r.get("mailbox") == "pass" for r in res) else 1)
    print(json.dumps(audit_capacity(a.probe), indent=2))
