#!/usr/bin/env python3
"""Bounded population scan: how often is an advertised mailbox actually provable?

Also checks note-path integrity: /kv/ is world-writable, so a DID note only binds
to its subject if sha256(did)[:16] matches the path it sits at. Nothing on the
server enforces that.
"""
import json
import random
import re
import sys
import time
import hashlib

from technocore_audit import http, MAILBOX_RE, did_pubkey

DID_RE = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}")


def scan(shards, per_shard):
    rows = []
    for sh in shards:
        st, body = http("/kv/did-%s" % sh)
        if st != 200:
            continue
        keys = [l.strip() for l in body.splitlines() if l.strip().startswith("/kv/")]
        random.shuffle(keys)
        for path in keys[:per_shard]:
            st, note = http(path)
            if st != 200:
                continue
            m = DID_RE.search(note)
            if not m:
                rows.append({"path": path, "status": "no-did-in-note"})
                continue
            did = m.group(0)
            row = {"path": path, "did": did}

            try:
                did_pubkey(did)
                row["encoding"] = "ok"
            except Exception as e:
                row["encoding"] = "bad: %s" % e
                rows.append(row)
                continue

            fp = hashlib.sha256(did.encode()).hexdigest()[:16]
            row["path_binds"] = path.endswith("did-%s/%s" % (fp[:2], fp[2:]))

            mb = MAILBOX_RE.search(note)
            if not mb:
                row["mailbox"] = "none"
            else:
                room = mb.group(1)
                st, rb = http("/r/%s?format=json" % room)
                msgs = json.loads(rb).get("messages", []) if st == 200 else []
                if not msgs:
                    row["mailbox"] = "empty"          # unprovable / unreachable
                elif any(x.get("from") == did for x in msgs):
                    row["mailbox"] = "attested"       # owner-signed beacon present
                else:
                    row["mailbox"] = "unattested"     # traffic, but owner never signed
            rows.append(row)
            time.sleep(0.05)
    return rows


if __name__ == "__main__":
    random.seed(7)
    shards = sys.argv[1].split(",") if len(sys.argv) > 1 else ["a8", "0b", "c4", "3f"]
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    rows = scan(shards, per)

    total = len(rows)
    tally = {}
    for r in rows:
        tally[r.get("mailbox", "n/a")] = tally.get(r.get("mailbox", "n/a"), 0) + 1
    advertised = sum(v for k, v in tally.items() if k in ("empty", "attested", "unattested"))
    mismatched = [r for r in rows if r.get("path_binds") is False]
    badenc = [r for r in rows if str(r.get("encoding", "")).startswith("bad")]

    print(json.dumps({
        "notes_sampled": total,
        "mailbox_tally": tally,
        "advertised": advertised,
        "advertised_but_unprovable": tally.get("empty", 0),
        "pct_unprovable_of_advertised": round(100.0 * tally.get("empty", 0) / advertised, 1) if advertised else None,
        "note_path_mismatch": len(mismatched),
        "bad_did_encoding": len(badenc),
    }, indent=2))
