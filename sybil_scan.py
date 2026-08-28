#!/usr/bin/env python3
"""Measure coordinated-activity signatures in public Technocore rooms.

Read-only. Reports three signatures that distinguish manufactured participation
from organic conversation, none of which depend on judging message content:

  template reuse   one text emitted verbatim by several distinct did:keys
  sender churn     near-one-message-per-key windows (a farm spreads volume over
                   many keys so no single key looks busy)
  cadence lock     independent rooms sharing an identical median interval, and
                   posting in the same second more often than chance allows

These are signals, not verdicts: a shared text can be a quoted phrase, and a
fixed interval can be one honest agent on a timer. Weight is in the combination.

  python3 sybil_scan.py lobby --pages 13
  python3 sybil_scan.py --cadence swiftcomet wildglacier tidyotter
"""
import argparse
import collections
import datetime
import json
import statistics
import time
import urllib.request

BASE = "https://technocore.chat"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return json.load(r)


def collect(room, pages):
    """Walk backwards from the head, oldest-first, ~50 messages per page."""
    head = get("/r/%s?format=json" % room)["last_seq"]
    cur, out = max(0, head - pages * 50), []
    for _ in range(pages + 2):
        ms = get("/r/%s?format=json&since=%d" % (room, cur))["messages"]
        if not ms:
            break
        out += ms
        cur = ms[-1]["seq"]
        time.sleep(0.05)
    return out


def analyse(room, msgs):
    senders = {m.get("from", "~anon") for m in msgs}
    signed = [m for m in msgs if m.get("from", "").startswith("did:key")]

    by_text = collections.defaultdict(set)
    for m in msgs:
        by_text[m["text"].strip()].add(m.get("from", "~anon"))
    shared = {t: s for t, s in by_text.items() if len(s) > 1}
    keys_in_shared = len(set().union(*shared.values())) if shared else 0

    return {
        "room": room,
        "messages": len(msgs),
        "signed_pct": round(100.0 * len(signed) / len(msgs), 1) if msgs else 0,
        "unique_senders": len(senders),
        "unique_texts": len(by_text),
        "messages_per_sender": round(len(msgs) / len(senders), 2) if senders else 0,
        "shared_templates": len(shared),
        "keys_emitting_shared_text": keys_in_shared,
        "pct_keys_on_a_template": round(100.0 * keys_in_shared / len(senders), 1) if senders else 0,
        "top_templates": [
            {"distinct_keys": len(s), "text": t[:110]}
            for t, s in sorted(shared.items(), key=lambda kv: -len(kv[1]))[:8]
        ],
    }


def cadence(rooms):
    """Independent rooms should not share a median interval or a clock."""
    def ts(s):
        return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")

    per_second, out = collections.Counter(), []
    for r in rooms:
        ms = get("/r/%s?format=json" % r)["messages"]
        if len(ms) < 3:
            continue
        t = [ts(m["ts"]) for m in ms]
        gaps = [(t[i + 1] - t[i]).total_seconds() for i in range(len(t) - 1)]
        dom = collections.Counter(m.get("from", "?") for m in ms).most_common(1)[0]
        for x in t:
            per_second[x.replace(microsecond=0)] += 1
        out.append({
            "room": r,
            "median_interval_s": round(statistics.median(gaps), 1),
            "dominant_key_share": "%d/%d" % (dom[1], len(ms)),
            "dominant_key": dom[0][:46],
        })
        time.sleep(0.05)

    collisions = {s: c for s, c in per_second.items() if c > 1}
    medians = {r["median_interval_s"] for r in out}
    return {
        "rooms": out,
        "distinct_median_intervals": len(medians),
        "seconds_observed": len(per_second),
        "seconds_with_multiple_rooms_posting": len(collisions),
        "collision_rate_pct": round(100.0 * len(collisions) / len(per_second), 1) if per_second else 0,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rooms", nargs="+")
    ap.add_argument("--pages", type=int, default=3, help="~50 messages per page")
    ap.add_argument("--cadence", action="store_true",
                    help="cross-room timing test instead of per-room template test")
    a = ap.parse_args()

    if a.cadence:
        print(json.dumps(cadence(a.rooms), indent=2, ensure_ascii=False))
    else:
        for r in a.rooms:
            print(json.dumps(analyse(r, collect(r, a.pages)), indent=2, ensure_ascii=False))
