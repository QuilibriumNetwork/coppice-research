from copy import deepcopy
from dataclasses import replace
import random
import unittest

from core import Client, Contribution, DeferredUpdate, Update, digest, MEMBERS, ERA
from wire import pack, unpack, Merkle, Proof
from ideal import IdealCrypto, Signer
from service import DeliveryService, Record, Meter
from envelopes import message_frame, receive_frame, seal_control, open_control, pad_body, unpad_body
from membership import Publication, ForkMonitor
from durability import DurableDevice, Crash
from costs import Workload, estimate, application_frame_bytes


class WireTests(unittest.TestCase):
    def test_canonical_roundtrip_and_map_order(self):
        values = (None, True, False, 0, 2**64 - 1, b"", "a☃", (b"x", 2), {"b": 1, "a": 2})
        for value in values:
            self.assertEqual(pack(unpack(pack(value))), pack(value))
        self.assertEqual(pack({"a": 2, "b": 1}), pack({"b": 1, "a": 2}))

    def test_truncation_trailing_bytes_unknown_types_and_limits(self):
        encoded = pack((b"x", {"a": 4}))
        for i in range(len(encoded)):
            with self.assertRaises(ValueError):
                unpack(encoded[:i])
        for data in (encoded + b"x", b"z", b"b\xff\xff\xff\xff", b"s\x00\x00\x00\x01\xff"):
            with self.assertRaises(ValueError):
                unpack(data)
        with self.assertRaises(ValueError):
            unpack(encoded, max_bytes=2)
        with self.assertRaises(ValueError):
            pack(-1)
        with self.assertRaises(ValueError):
            pack(2**64)

    def test_duplicate_unordered_ambiguous_maps_rejected(self):
        for keys in (("a", "a"), ("b", "a"), (1, True)):
            data = b"d\x00\x00\x00\x02" + b"".join(pack(k) + pack(0) for k in keys)
            with self.assertRaises(ValueError):
                unpack(data)

    def test_depth_bounded(self):
        data = b"l\x00\x00\x00\x01" * 30 + b"n"
        with self.assertRaises(ValueError):
            unpack(data)

    def test_merkle_paths_bind_index_count_context_and_content(self):
        for size in (1, 3, 5, 17, 78, 128):
            leaves = [pack(i) for i in range(size)]
            tree = Merkle(leaves, b"roster")
            for i in range(size):
                proof = tree.proof(i)
                self.assertTrue(Merkle.verify(leaves[i], proof, tree.root, b"roster"))
                self.assertFalse(Merkle.verify(b"modified", proof, tree.root, b"roster"))
                self.assertFalse(Merkle.verify(leaves[i], proof, tree.root, b"another group"))
                self.assertFalse(Merkle.verify(leaves[i], replace(proof, count=size + 1), tree.root, b"roster"))
                self.assertFalse(Merkle.verify(leaves[i], replace(proof, index=size), tree.root, b"roster"))


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.service = DeliveryService()
        self.route, self.cap = b"r" * 32, b"c" * 32
        self.service.register(self.route, self.cap)

    def test_rejects_sender_auth_and_missing_delivery_capability(self):
        record = Record(b"s" * 32, b"opaque")
        for headers in ({"Authorization": "account"}, {"sender": "alice"}, {"cookie": "tracking"}):
            with self.assertRaises(ValueError):
                self.service.put(self.route, self.cap, record, headers=headers)
        with self.assertRaises(ValueError):
            self.service.put(self.route, None, record)
        self.assertEqual(self.service.records, {})

    def test_shared_capability_has_aggregate_quota_and_rotates(self):
        self.service.quota = 1
        first = Record(b"a" * 32, b"ciphertext")
        self.service.put(self.route, self.cap, first)
        self.service.put(self.route, self.cap, first)  # Immutable retries idempotent.
        with self.assertRaises(ValueError):
            self.service.put(self.route, self.cap, Record(b"b" * 32, b"other"))
        self.service.register(self.route, b"new")
        with self.assertRaises(ValueError):
            self.service.get(self.route, self.cap, first.selector)

    def test_dependency_closure_survives_leaf_retention(self):
        old = Record(b"a" * 32, b"old dependency", expires=1)
        middle = Record(b"b" * 32, b"middle", (old.selector,), expires=2)
        fresh = Record(b"c" * 32, b"fresh", (middle.selector,), expires=10)
        unrelated = Record(b"d" * 32, b"expired", expires=2)
        for record in (old, middle, fresh, unrelated):
            self.service.put(self.route, self.cap, record)
        self.service.collect(5)
        self.assertEqual(self.service.closure(self.route, [fresh.selector]), {old.selector, middle.selector, fresh.selector})
        self.assertEqual(len(self.service.records), 3)
        self.service.collect(11)
        self.assertEqual(self.service.records, {})

    def test_missing_dependency_and_immutable_conflict_visible(self):
        record = Record(b"a" * 32, b"cipher", (b"b" * 32,))
        self.service.put(self.route, self.cap, record)
        with self.assertRaises(LookupError):
            self.service.closure(self.route, [record.selector])
        with self.assertRaises(ValueError):
            self.service.put(self.route, self.cap, replace(record, ciphertext=b"changed"))

    def test_device_meter_counts_request_response_and_padding(self):
        meter = Meter()
        record = Record(b"s" * 32, b"x" * 1000)
        self.service.put(self.route, self.cap, record, meter)
        self.service.get(self.route, self.cap, record.selector, meter)
        self.assertEqual(meter.round_trips, 2)
        self.assertGreater(meter.upload, 1000)
        self.assertGreater(meter.download, 1000)
        self.assertEqual(meter.upload % 128, 0)

    def test_invalid_record_encoding_does_not_commit_storage_or_quota(self):
        with self.assertRaises(ValueError):
            self.service.put(self.route, self.cap, Record(b"s" * 32, b"opaque", expires=-1))
        self.assertEqual(self.service.records, {})
        self.assertEqual(self.service.usage, {})


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.crypto = IdealCrypto()
        self.signer = self.crypto.signer()
        self.sender, self.receiver = Client(), Client()
        self.metadata = self.crypto.fresh()
        self.credentials = {"alice": self.signer.public}

    def test_sealed_message_authenticates_author_without_service_plaintext(self):
        payload = b"distinct secret payload must not appear"
        frame = message_frame(self.crypto, self.sender, "alice", self.signer, self.metadata, payload)
        self.assertNotIn(payload, frame)
        self.assertNotIn(b"alice", frame)
        self.assertNotIn(self.signer.public, frame)
        self.assertEqual(receive_frame(self.crypto, self.receiver, frame, self.metadata, self.credentials), ("alice", payload))
        with self.assertRaises(ValueError):
            receive_frame(self.crypto, self.receiver, frame, self.metadata, self.credentials)

    def test_reordered_frames_have_bounded_skipped_keys(self):
        frames = [message_frame(self.crypto, self.sender, "alice", self.signer, self.metadata, pack(i)) for i in range(6)]
        for i in (5, 0, 3, 2, 1, 4):
            self.assertEqual(receive_frame(self.crypto, self.receiver, frames[i], self.metadata, self.credentials)[1], pack(i))
        self.assertEqual(self.receiver.skipped, {})

    def test_corrupt_frame_or_signature_cannot_advance_ratchet(self):
        frame = message_frame(self.crypto, self.sender, "alice", self.signer, self.metadata, b"data")
        before = deepcopy(self.receiver.__dict__)
        for bad in (frame[:-1] + bytes([frame[-1] ^ 1]), pack((b"wrong", b"x", b"y"))):
            with self.assertRaises(ValueError):
                receive_frame(self.crypto, self.receiver, bad, self.metadata, self.credentials)
            self.assertEqual(self.receiver.lanes, before["lanes"])
            self.assertEqual(self.receiver.frontier.nodes, before["frontier"].nodes)
        attacker = self.crypto.signer()
        wrong_frame = message_frame(self.crypto, Client(), "alice", attacker, self.metadata, b"impersonation")
        with self.assertRaises(ValueError):
            receive_frame(self.crypto, self.receiver, wrong_frame, self.metadata, self.credentials)
        self.assertEqual(self.receiver.lanes, {})

    def test_all_control_kinds_hide_author_and_have_context_integrity(self):
        for kind in ("publication", "directory", "receipt", "attachment", "evidence", "update"):
            frame = seal_control(self.crypto, self.signer, self.metadata, b"group", ERA, kind, b"private record")
            self.assertNotIn(self.signer.public, frame)
            self.assertNotIn(b"private record", frame)
            self.assertEqual(open_control(self.crypto, frame, self.metadata, b"group", ERA,
                                          {self.signer.public}), (self.signer.public, kind, b"private record"))
            with self.assertRaises(ValueError):
                open_control(self.crypto, frame, self.metadata, b"other", ERA, {self.signer.public})

    def test_randomized_resigning_uses_distinct_control_envelopes(self):
        args = (self.crypto, self.signer, self.metadata, b"group", ERA, "publication", b"same body")
        self.assertNotEqual(seal_control(*args), seal_control(*args))

    def test_metadata_and_sender_update_dependencies_are_explicit(self):
        event = Contribution(ERA, b"fresh metadata", b"r" * 32)
        self.sender.add_contribution(event)
        update = self.sender.make_update("alice", [event.identifier])
        self.sender.receive_update(update)
        frame = message_frame(self.crypto, self.sender, "alice", self.signer,
                              self.metadata, b"healed", event.identifier)
        with self.assertRaisesRegex(LookupError, "metadata dependency"):
            receive_frame(self.crypto, self.receiver, frame, self.metadata, self.credentials)
        self.assertEqual(self.receiver.lanes, {})
        self.receiver.add_contribution(event)
        with self.assertRaisesRegex(LookupError, "sender update dependency"):
            receive_frame(self.crypto, self.receiver, frame, self.metadata, self.credentials)
        self.assertEqual(self.receiver.lanes, {})
        self.receiver.receive_update(update)
        self.assertEqual(receive_frame(self.crypto, self.receiver, frame, self.metadata,
                                      self.credentials), ("alice", b"healed"))

    def test_oracle_rejects_forged_signing_capability(self):
        with self.assertRaises(ValueError):
            self.crypto.sign(Signer(self.signer.public, b"fake"), b"forgery")

    def test_padding_rejects_nonzero_suffix_and_wrong_bucket(self):
        padded = pad_body((b"payload", b"signature"))
        self.assertEqual(unpad_body(padded), (b"payload", b"signature"))
        for invalid in (padded[:-1] + b"x", padded + bytes(128), padded[:2]):
            with self.assertRaises(ValueError):
                unpad_body(invalid)


class ResourceTests(unittest.TestCase):
    def test_cross_group_contributions_updates_messages_rejected(self):
        source, target = Client(), Client(group=b"other")
        event = Contribution(ERA, b"event", b"r" * 32)
        source.add_contribution(event)
        update = source.make_update("alice", [event.identifier])
        for action in (lambda: target.add_contribution(event), lambda: target.receive_update(update),
                       lambda: target.receive(source.send("alice"))):
            with self.assertRaises(ValueError):
                action()

    def test_frontier_growth_defers_without_consumption_and_can_resume(self):
        members = {f"member-{i}": i for i in range(16)}
        client = Client(members=members, max_frontier_bytes=256)
        event = Contribution(ERA, b"entropy", b"e" * 32)
        client.add_contribution(event)
        update = client.make_update("member-0", [event.identifier])
        client.max_frontier_bytes = client.frontier_bytes
        previous = deepcopy(client.entropy[event.identifier].nodes)
        client.receive_update(update)
        self.assertIn(("member-0", 1), client.pending)
        self.assertEqual(client.entropy[event.identifier].nodes, previous)
        self.assertEqual(client.frozen, set())
        client.max_frontier_bytes = 1024
        client.drain()
        self.assertEqual(client.pending, {})

    def test_initial_entropy_budget_failure_is_transactional(self):
        client = Client(max_frontier_bytes=32)
        with self.assertRaises(DeferredUpdate):
            client.add_contribution(Contribution(ERA, b"event", b"x" * 32))
        self.assertEqual(client.entropy, {})
        self.assertEqual(client.seen_entropy, set())

    def test_pending_bytes_bounded_before_acceptance(self):
        client = Client(max_pending_bytes=1)
        update = Client().make_update("alice", [b"x" * 32])
        with self.assertRaises(ValueError):
            client.receive_update(update)
        self.assertEqual(client.known_updates, {})

    def test_explicit_entropy_expiry_frees_budget_without_blame_or_resurrection(self):
        client = Client()
        event = Contribution(ERA, b"expiring", b"e" * 32)
        client.add_contribution(event)
        client.receive_update(client.make_update("alice", [event.identifier]))
        before = client.frontier_bytes
        client.abandon_entropy(event.identifier)
        self.assertLess(client.frontier_bytes, before)
        client.add_contribution(event)
        self.assertEqual(client.entropy[event.identifier].nodes, {})
        update = client.make_update("bob", [event.identifier])
        client.receive_update(update)
        self.assertIn(update.identifier, client.replay_gaps)
        self.assertNotIn("bob", client.frozen)
        self.assertEqual(client.send("alice").generation, 1)

    def test_skipped_ttl_starts_at_local_derivation_after_days_offline(self):
        sender, receiver = Client(), Client(skip_ttl=1800)
        frames = [sender.send("alice") for _ in range(3)]
        receiver.expire_skipped(7 * 86400)
        receiver.receive(frames[-1])
        receiver.expire_skipped(7 * 86400 + 1799)
        receiver.receive(frames[0])
        receiver.expire_skipped(7 * 86400 + 1800)
        with self.assertRaisesRegex(ValueError, "explicit replay gap"):
            receiver.receive(frames[1])

    def test_sender_skip_subquota_and_counter_exhaustion(self):
        sender, receiver = Client(), Client(max_skip=100, max_skip_sender=1)
        messages = [sender.send("alice") for _ in range(3)]
        with self.assertRaises(ValueError):
            receiver.receive(messages[-1])
        self.assertEqual(receiver.lanes, {})
        sender.lane("alice").counter = 2**64 - 1
        with self.assertRaises(ValueError):
            sender.send("alice")

    def test_seeded_adversarial_message_schedules_converge(self):
        for seed in range(20):
            sender, receiver = Client(max_skip=100), Client(max_skip=100)
            messages = [sender.send(name) for name in MEMBERS for _ in range(10)]
            random.Random(seed).shuffle(messages)
            for message in messages:
                receiver.receive(message)
            self.assertEqual(sender.lanes, receiver.lanes)
            self.assertEqual(receiver.skipped, {})


class ForkAndCrashTests(unittest.TestCase):
    def test_partition_hides_fork_until_authenticated_views_meet(self):
        crypto = IdealCrypto()
        malicious, honest = crypto.signer(), crypto.signer()
        monitors = [ForkMonitor(b"group", ERA, [malicious.public, honest.public]) for _ in range(2)]
        publications = []
        for payload in (b"branch A", b"branch B"):
            p = Publication(b"group", ERA, malicious.public, 1, b"", payload)
            publications.append(replace(p, signature=crypto.sign(malicious, p.body())))
        for monitor, publication in zip(monitors, publications):
            monitor.observe(crypto, publication)
            self.assertEqual(monitor.frozen, set())  # Expected limitation, not successful detection.
        monitors[0].merge(crypto, tuple(monitors[1].seen.values()))
        self.assertIn(malicious.public, monitors[0].frozen)
        self.assertNotIn(honest.public, monitors[0].frozen)
        self.assertEqual(len(monitors[0].evidence), 1)

    def test_forged_evidence_cannot_freeze_an_honest_publisher(self):
        crypto = IdealCrypto()
        signer = crypto.signer()
        monitor = ForkMonitor(b"group", ERA, [signer.public])
        p = Publication(b"group", ERA, signer.public, 1, b"", b"data", b"forged")
        with self.assertRaises(ValueError):
            monitor.observe(crypto, p)
        self.assertEqual(monitor.frozen, set())

    def test_crash_after_send_commit_retries_opaque_bytes(self):
        crypto, durable = IdealCrypto(), DurableDevice(Client())
        signer, metadata = crypto.signer(), b"m" * 32
        with self.assertRaises(Crash):
            durable.send(crypto, "request", "alice", signer, metadata, b"secret", "after_commit")
        frame = durable.outbox["request"]
        self.assertEqual(durable.send(crypto, "request", "alice", signer, metadata, b"secret"), frame)
        self.assertEqual(durable.state.lanes["alice"].counter, 1)
        self.assertNotIn(b"secret", frame)
        self.assertEqual(receive_frame(crypto, Client(), frame, metadata, {"alice": signer.public})[1], b"secret")

    def test_precommit_crash_releases_nothing_and_old_backup_is_rejected(self):
        crypto, durable = IdealCrypto(), DurableDevice(Client())
        signer = crypto.signer()
        before = durable.snapshot()
        with self.assertRaises(Crash):
            durable.send(crypto, "request", "alice", signer, b"m" * 32, b"secret", "before_commit")
        self.assertEqual(durable.state.lanes, {})
        self.assertEqual(durable.outbox, {})
        durable.send(crypto, "request", "alice", signer, b"m" * 32, b"secret")
        with self.assertRaises(ValueError):
            durable.restore(before)


class CostTests(unittest.TestCase):
    def test_reference_workload_and_padding(self):
        report = estimate(Workload())
        self.assertEqual(report["recipient_refresh_download"], 872640)
        self.assertEqual(report["sender_update_signatures_download"], 1598400)
        self.assertEqual(report["offline_control_replay_subtotal"], 17297280)
        self.assertEqual(application_frame_bytes(100), 1090)
        self.assertGreater(application_frame_bytes(1500), 1500 + 864)
        self.assertTrue(report["unmodeled"])

    def test_invalid_workloads_rejected(self):
        for args in ({"shards": 0}, {"devices": 0}, {"active_senders": 10001}, {"offline_days": -1}):
            with self.assertRaises(ValueError):
                Workload(**args)


if __name__ == "__main__":
    unittest.main()
