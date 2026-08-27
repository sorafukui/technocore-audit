#!/usr/bin/env python3
"""Offline tests. No network: audit_mailbox's I/O is stubbed."""
import json
import unittest
from unittest import mock

import technocore_audit as A

OPERATOR = "did:key:z6MkuMpDWissXyN3KHzFFqZDZd8Q6Yoo6C2NuRZcHyyq9KnC"
MINE = "did:key:z6Mki9pbFgjN2BmPBwiop5mw5jeqTqAxVovy8uz8Sq9yfaGy"


class TestDidKey(unittest.TestCase):
    def test_valid_roundtrip(self):
        self.assertEqual(len(A.did_pubkey(OPERATOR)), 32)

    def test_rejects_non_didkey(self):
        for bad in ["did:web:example.com", "z6Mkabc", "", "did:key:Q3sh"]:
            with self.assertRaises(Exception):
                A.did_pubkey(bad)

    def test_rejects_wrong_multicodec(self):
        # 0xec01 is x25519-pub, not ed25519-pub; must not be accepted as an identity.
        import technocore_audit as t
        raw = b"\xec\x01" + b"\x11" * 32
        n = int.from_bytes(raw, "big")
        s = ""
        while n:
            n, r = divmod(n, 58)
            s = t.B58[r] + s
        with self.assertRaises(ValueError):
            A.did_pubkey("did:key:z" + s)

    def test_note_path_is_sharded_sha256(self):
        import hashlib
        fp = hashlib.sha256(OPERATOR.encode()).hexdigest()[:16]
        self.assertEqual(A.note_paths(OPERATOR)[0], "did-%s/%s" % (fp[:2], fp[2:]))
        self.assertEqual(A.note_paths(OPERATOR)[0], "did-a8/52a20355d5835e")

    def test_legacy_path_offered_as_fallback(self):
        self.assertEqual(len(A.note_paths(OPERATOR)), 2)
        self.assertTrue(A.note_paths(OPERATOR)[1].startswith("did/"))


def stub(note, room_msgs, note_status=200):
    def _http(path):
        if path.startswith("/kv/"):
            return (note_status, note) if note is not None else (404, "no note")
        return 200, json.dumps({"messages": room_msgs})
    return _http


class TestMailboxVerdicts(unittest.TestCase):
    def test_attested_mailbox_passes(self):
        note = "%s mailbox:mb-p-abc" % OPERATOR
        msgs = [{"seq": 1, "from": OPERATOR, "text": "Mailbox initialized."}]
        with mock.patch.object(A, "http", stub(note, msgs)):
            r = A.audit_mailbox(OPERATOR)
        self.assertEqual(r["mailbox"], "pass")
        self.assertEqual(r["attested_at_seq"], 1)

    def test_empty_mailbox_fails_where_setup_check_passes(self):
        """The regression this tool exists for: advertised, empty, reported pass upstream."""
        note = "%s mailbox:mb-p-fbd4bcf0100000c3d269c4358d05a4c8" % MINE
        with mock.patch.object(A, "http", stub(note, [])):
            r = A.audit_mailbox(MINE)
        self.assertEqual(r["mailbox"], "fail")
        self.assertIn("empty", r["reason"])

    def test_traffic_without_owner_signature_is_unattested(self):
        note = "%s mailbox:mb-p-abc" % OPERATOR
        msgs = [{"seq": 1, "from": MINE, "text": "hello"}]
        with mock.patch.object(A, "http", stub(note, msgs)):
            r = A.audit_mailbox(OPERATOR)
        self.assertEqual(r["mailbox"], "warn")

    def test_no_mailbox_advertised_is_warn_not_fail(self):
        with mock.patch.object(A, "http", stub("%s profile:x" % OPERATOR, [])):
            r = A.audit_mailbox(OPERATOR)
        self.assertEqual(r["mailbox"], "warn")

    def test_missing_note_is_directory_fail(self):
        with mock.patch.object(A, "http", stub(None, [])):
            r = A.audit_mailbox(OPERATOR)
        self.assertEqual(r["directory"], "fail")

    def test_mailbox_regex_accepts_both_spacings(self):
        self.assertTrue(A.MAILBOX_RE.search("mailbox:mb-p-a1"))
        self.assertTrue(A.MAILBOX_RE.search("mailbox: mb-p-a1"))
        self.assertIsNone(A.MAILBOX_RE.search("mailbox:p-a1"))  # must be mb- class


if __name__ == "__main__":
    unittest.main(verbosity=2)
