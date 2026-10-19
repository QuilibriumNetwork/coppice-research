from copy import deepcopy
from dataclasses import replace
import unittest

from fixtures import Lab
from membership import Policy, Credential, Checkpoint, Governance, Roster, verify_checkpoint
from resumption import accept_entry, entry_selector, resume, authorize_sender, EntryBuilder
from envelopes import message_frame, receive_frame
from history import ArchiveWriter, ArchiveReader
from service import Meter, Record
from wire import pack, unpack
from core import digest
from durability import DurableDevice, Crash


class MembershipTests(unittest.TestCase):
    def test_service_cannot_add_device_or_alter_policy(self):
        lab = Lab()
        checkpoint = lab.epoch()
        for forged in (replace(checkpoint, count=5),
                       replace(checkpoint, policy=Policy(history="ALL_RETAINED")),
                       replace(checkpoint, roster_root=b"x" * 32)):
            with self.assertRaises(ValueError):
                verify_checkpoint(lab.crypto, lab.governance, lab.log.signer.public, forged, lab.group)

    def test_unknown_profiles_and_invalid_window_rejected(self):
        for args in ({"protection": "SHARED"}, {"history": "PUBLIC"},
                     {"history": "WINDOW"}, {"history": "NONE", "window": 10}):
            with self.assertRaises(ValueError):
                Policy(**args)

    def test_log_refuses_conflicting_or_out_of_order_membership(self):
        lab = Lab()
        checkpoint = lab.epoch()
        alternate = replace(checkpoint, nonce=b"other", approvals=(), finality=b"")
        alternate = lab.governance.authorize(lab.crypto, alternate, [lab.guardian])
        with self.assertRaises(ValueError):
            lab.log.commit(alternate)
        self.assertEqual(lab.log.commit(checkpoint), checkpoint)

    def test_device_signing_key_cannot_self_authorize_recovery(self):
        lab = Lab()
        checkpoint = lab.epoch()
        replacement = replace(checkpoint, number=2, previous=checkpoint.identifier,
                              nonce=b"stolen identity rekey", approvals=(), finality=b"")
        with self.assertRaises(ValueError):
            lab.governance.authorize(lab.crypto, replacement, [lab.signers["bob"]])
        old_public = lab.signers["bob"].public
        lab.add_identity("bob")
        lab.epoch()
        self.assertNotEqual(lab.sessions["bob"].credential.public, old_public)

    def test_duplicate_approval_does_not_satisfy_threshold(self):
        lab = Lab()
        checkpoint = lab.epoch()
        other = lab.crypto.signer()
        governance = Governance([lab.guardian.public, other.public], threshold=2)
        with self.assertRaises(ValueError):
            governance.authorize(lab.crypto, checkpoint, [lab.guardian, lab.guardian])

    def test_join_cannot_read_prior_live_era_and_removal_rotates_delivery(self):
        lab = Lab(("alice", "bob"))
        lab.epoch()
        alice = lab.sessions["alice"]
        old = message_frame(lab.crypto, alice.ratchet, "alice", lab.signers["alice"], alice.metadata_key, b"old")
        old_capability = alice.delivery_capability
        lab.add_identity("carol")
        lab.epoch(("alice", "carol"))
        lab.learn_sender("carol", "alice")
        carol = lab.sessions["carol"]
        with self.assertRaises(ValueError):
            receive_frame(lab.crypto, carol.ratchet, old, carol.metadata_key, lab.credentials())
        with self.assertRaises(LookupError):
            lab.return_device("bob")
        with self.assertRaises(ValueError):
            lab.service.put(lab.route, old_capability, Record(b"x" * 32, b"old authorization"))
        fresh = message_frame(lab.crypto, lab.sessions["alice"].ratchet, "alice", lab.signers["alice"],
                              lab.sessions["alice"].metadata_key, b"new")
        self.assertEqual(receive_frame(lab.crypto, carol.ratchet, fresh, carol.metadata_key,
                                      lab.credentials()), ("alice", b"new"))

    def test_roster_proof_prevents_index_and_identity_substitution(self):
        lab = Lab()
        lab.epoch()
        bob = lab.roster.by_name["bob"]
        for forged in (replace(bob, index=0), replace(bob, name="alice"), replace(bob, public=b"fake")):
            with self.assertRaises(ValueError):
                authorize_sender(lab.sessions["alice"], forged, lab.roster.proof("bob"))

    def test_shard_shape_changes_are_authenticated_membership(self):
        lab = Lab()
        lab.epoch()
        changed = replace(lab.roster.by_name["bob"], shard="split-shard")
        self.assertFalse(lab.checkpoint.verify_credential(changed, lab.roster.proof("bob")))
        roster = Roster(lab.group, [replace(c, shard=f"split-{c.index % 2}") for c in lab.roster.credentials])
        self.assertNotEqual(roster.tree.root, lab.roster.tree.root)


class ResumptionTests(unittest.TestCase):
    def test_seven_days_and_many_membership_changes_need_only_latest_entry(self):
        lab = Lab()
        lab.epoch()
        lab.provision("bob", 28)  # Done before Bob goes offline.
        for _ in range(28):
            lab.epoch(online=("alice", "carol", "dave"))
        before_private = len(lab.inboxes["bob"].secrets)
        meter = Meter()
        bob = lab.return_device("bob", meter)
        self.assertEqual(bob.checkpoint.number, 29)
        self.assertEqual(meter.round_trips, 2)
        self.assertLessEqual(meter.download, 64_000)
        self.assertEqual(len(lab.inboxes["bob"].secrets), before_private - 1)
        # Unread skipped-era tickets explicitly remain; they are not FS-protected history.
        frame = message_frame(lab.crypto, bob.ratchet, "bob", lab.signers["bob"], bob.metadata_key, b"back online")
        lab.learn_sender("alice", "bob")
        self.assertEqual(receive_frame(lab.crypto, lab.sessions["alice"].ratchet, frame,
                                      lab.sessions["alice"].metadata_key, lab.credentials()), ("bob", b"back online"))

    def test_same_era_return_preserves_consumed_state_and_needs_no_entry(self):
        lab = Lab()
        lab.epoch()
        bob = lab.sessions["bob"]
        bob.ratchet.send("bob")
        before = deepcopy(bob.ratchet.lanes)
        meter = Meter()
        resumed = lab.return_device("bob", meter)
        self.assertIs(resumed, bob)
        self.assertEqual(resumed.ratchet.lanes, before)
        self.assertEqual(meter.round_trips, 1)

    def test_withheld_entry_does_not_consume_ticket_or_restore_old_era(self):
        lab = Lab()
        lab.epoch()
        lab.provision("bob", 1)
        previous = lab.sessions["bob"]
        lab.epoch(online=("alice", "carol", "dave"))
        ticket = lab.last_tickets["bob"]
        selector = entry_selector(lab.inboxes["bob"], lab.checkpoint)
        lab.service.withheld.add(selector)
        with self.assertRaises(LookupError):
            lab.return_device("bob")
        self.assertIn(ticket.identifier, lab.inboxes["bob"].secrets)
        self.assertIs(lab.sessions["bob"], previous)
        lab.service.withheld.clear()
        lab.return_device("bob")

    def test_expired_entry_reports_gap(self):
        lab = Lab()
        lab.epoch()
        lab.provision("bob", 1)
        lab.epoch(online=("alice", "carol", "dave"))
        lab.service.collect(31 * 86400)
        with self.assertRaises(LookupError):
            lab.return_device("bob")

    def test_offline_inventory_exhaustion_defers_transition_not_existing_lane(self):
        lab = Lab()
        old = lab.epoch()
        with self.assertRaises(LookupError):
            lab.epoch(online=("alice", "carol", "dave"))
        self.assertEqual(lab.log.head, old)
        self.assertEqual(lab.sessions["alice"].ratchet.send("alice").counter, 0)

    def test_online_members_also_erase_entry_capabilities(self):
        lab = Lab()
        lab.epoch()
        for name, ticket in lab.last_tickets.items():
            self.assertNotIn(ticket.identifier, lab.inboxes[name].secrets)
            self.assertIn(ticket.identifier, lab.inboxes[name].consumed)
        self.assertEqual(lab.last_builder.values, {})
        with self.assertRaises(ValueError):
            lab.last_builder.prepare(lab.last_tickets["alice"], lab.reserved)

    def test_entry_cannot_reopen_consumed_era_or_wrong_recipient(self):
        lab = Lab()
        lab.epoch()
        bob = lab.sessions["bob"]
        packet = lab.last_builder.packets["bob"]
        for name in ("alice", "bob"):
            with self.assertRaises(ValueError):
                accept_entry(lab.crypto, lab.governance, lab.log.signer.public, lab.group,
                             lab.roster.by_name[name], lab.inboxes[name], packet,
                             lab.checkpoint.identifier, lab.sessions[name])
        self.assertEqual(bob.ratchet.lanes, {})

    def test_stale_finality_response_rejected_by_fresh_challenge(self):
        lab = Lab()
        lab.epoch()
        old_response = lab.log.latest(lab.crypto.fresh())
        with self.assertRaises(ValueError):
            resume(lab.crypto, lab.governance, lab.log, lab.service, lab.group,
                   lab.roster.by_name["bob"], lab.inboxes["bob"], lab.sessions["bob"],
                   latest_response=old_response)

    def test_entry_processing_crash_is_atomic_with_ticket_deletion(self):
        lab = Lab()
        lab.epoch()
        lab.provision("bob", 1)
        previous = lab.sessions["bob"]
        lab.epoch(online=("alice", "carol", "dave"))
        ticket = lab.last_tickets["bob"]
        durable = DurableDevice({"session": previous, "inbox": lab.inboxes["bob"]})
        packet = lab.last_builder.packets["bob"]

        def accept(state, outbox):
            state["session"] = accept_entry(lab.crypto, lab.governance, lab.log.signer.public,
                                            lab.group, lab.roster.by_name["bob"], state["inbox"],
                                            packet, lab.checkpoint.identifier, state["session"])
        with self.assertRaises(Crash):
            durable.transact(accept, "before_commit")
        self.assertIn(ticket.identifier, durable.state["inbox"].secrets)
        with self.assertRaises(Crash):
            durable.transact(accept, "after_commit")
        self.assertNotIn(ticket.identifier, durable.state["inbox"].secrets)
        self.assertEqual(durable.state["session"].checkpoint, lab.checkpoint)

    def test_service_trace_has_no_entry_plaintext_or_member_keys(self):
        lab = Lab()
        lab.epoch()
        view = lab.service.public_view()
        for name, signer in lab.signers.items():
            self.assertNotIn(name.encode(), view)
            self.assertNotIn(signer.public, view)
            self.assertNotIn(lab.sessions[name].metadata_key, view)
            self.assertNotIn(lab.sessions[name].era_next, view)

    def test_incomplete_entry_coverage_cannot_be_published(self):
        lab = Lab()
        lab.epoch()
        builder = EntryBuilder(lab.crypto, lab.group, lab.roster, Policy(), lab.checkpoint,
                               lab.signers["alice"], lab.governance, [lab.guardian], lab.log, lab.route)
        with self.assertRaises(ValueError):
            builder.finish()


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.lab = Lab(("alice", "bob"))
        self.policy = Policy(history="ALL_RETAINED")
        self.lab.epoch(policy=self.policy)
        self.writer = ArchiveWriter(self.lab.group)
        self.route, self.cap = self.lab.crypto.fresh(), self.lab.crypto.fresh()
        self.lab.service.register(self.route, self.cap)
        for position in range(5):
            self.writer.append(self.lab.crypto, self.lab.checkpoint, self.lab.roster,
                               self.lab.signers["alice"], position, f"message-{position}".encode(),
                               self.lab.service, self.route, self.cap)
        self.lab.add_identity("carol")
        self.lab.epoch(policy=self.policy, history_boundary=5)

    def grant(self, start=0, stop=5):
        lab = self.lab
        key = lab.crypto.kem_key()
        recipient = lab.roster.by_name["carol"]
        blob = self.writer.grant(lab.crypto, lab.checkpoint, lab.roster, lab.signers["bob"],
                                 recipient, key.public, start, stop, 5)
        reader = ArchiveReader(lab.group, recipient, lab.checkpoint, key.secret)
        return reader, blob

    def test_grant_prepared_before_inviter_offline_preserves_original_author(self):
        reader, blob = self.grant(1, 4)
        lab = self.lab
        # Server stores only the encrypted grant. No live inviter is consulted.
        selector = digest(b"history grant", blob)
        lab.service.put(self.route, self.cap, Record(selector, blob))
        reader.accept(lab.crypto, lab.service.get(self.route, self.cap, selector).ciphertext)
        self.assertEqual(reader.private_ticket, b"")
        for pos in (3, 1, 2):
            self.assertEqual(reader.read(lab.crypto, lab.governance, lab.log.signer.public,
                                         lab.service, self.route, self.cap, pos),
                             ("alice", f"message-{pos}".encode()))
        with self.assertRaises(ValueError):
            reader.read(lab.crypto, lab.governance, lab.log.signer.public,
                        lab.service, self.route, self.cap, 0)
        with self.assertRaises(ValueError):
            reader.accept(lab.crypto, blob)

    def test_history_policy_window_binds_authenticated_admission_boundary(self):
        lab = self.lab
        lab.epoch(policy=Policy(history="WINDOW", window=2))
        with self.assertRaises(ValueError):
            self.grant(0, 5)
        reader, blob = self.grant(3, 5)
        reader.accept(lab.crypto, blob)
        self.assertEqual(set(reader.access), {3, 4})
        key = lab.crypto.kem_key()
        with self.assertRaises(ValueError):
            self.writer.grant(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"],
                               lab.roster.by_name["carol"], key.public, 0, 2, 2)

    def test_original_window_cannot_be_broadened_by_later_all_history_policy(self):
        lab = self.lab
        lab.epoch(policy=Policy(history="WINDOW", window=2), history_boundary=5)
        for position in range(5, 10):
            self.writer.append(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"],
                               position, b"windowed", lab.service, self.route, self.cap)
        lab.epoch(policy=self.policy, history_boundary=10)
        key = lab.crypto.kem_key()
        with self.assertRaises(ValueError):
            self.writer.grant(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"],
                               lab.roster.by_name["carol"], key.public, 5, 10, 10)

    def test_none_policy_rejects_archiving_and_new_grants(self):
        lab = self.lab
        lab.epoch(policy=Policy())
        with self.assertRaises(ValueError):
            self.writer.append(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"],
                               5, b"private", lab.service, self.route, self.cap)
        with self.assertRaises(ValueError):
            self.grant()

    def test_wrong_recipient_or_changed_grant_does_not_consume_key(self):
        reader, blob = self.grant()
        before = reader.private_ticket
        corrupted = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaises(ValueError):
            reader.accept(self.lab.crypto, corrupted)
        self.assertEqual(reader.private_ticket, before)
        reader.recipient = self.lab.roster.by_name["bob"]
        with self.assertRaises(ValueError):
            reader.accept(self.lab.crypto, blob)
        self.assertFalse(reader.consumed)

    def test_archive_compromise_exposes_granted_history_but_not_future_keys(self):
        reader, blob = self.grant()
        reader.accept(self.lab.crypto, blob)
        compromised = deepcopy(reader)
        lab = self.lab
        future = self.writer.append(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"],
                                    5, b"future", lab.service, self.route, self.cap)
        self.assertEqual(compromised.read(lab.crypto, lab.governance, lab.log.signer.public,
                                          lab.service, self.route, self.cap, 0)[1], b"message-0")
        self.assertNotIn(future.key, [key for _, key, _ in compromised.access.values()])
        with self.assertRaises(ValueError):
            compromised.read(lab.crypto, lab.governance, lab.log.signer.public,
                             lab.service, self.route, self.cap, 5)

    def test_service_cannot_decrypt_or_mint_history_grant(self):
        reader, blob = self.grant()
        lab = self.lab
        lab.service.put(self.route, self.cap, Record(digest(b"grant", blob), blob))
        view = lab.service.public_view()
        for segment in self.writer.segments.values():
            self.assertNotIn(segment.key, view)
        self.assertNotIn(b"message-0", view)
        with self.assertRaises(ValueError):
            lab.crypto.open_with(b"service has no key", blob, b"")
        outsider = lab.crypto.signer()
        with self.assertRaises(ValueError):
            self.writer.grant(lab.crypto, lab.checkpoint, lab.roster, outsider,
                               lab.roster.by_name["carol"], lab.crypto.kem_key().public, 0, 5, 5)

    def test_history_fetch_is_independent_of_live_first_send(self):
        lab = self.lab
        reader, blob = self.grant()
        lab.service.withheld.update(segment.selector for segment in self.writer.segments.values())
        reader.accept(lab.crypto, blob)
        with self.assertRaises(LookupError):
            reader.read(lab.crypto, lab.governance, lab.log.signer.public,
                        lab.service, self.route, self.cap, 0)
        carol = lab.sessions["carol"]
        frame = message_frame(lab.crypto, carol.ratchet, "carol", lab.signers["carol"],
                              carol.metadata_key, b"live")
        lab.learn_sender("alice", "carol")
        self.assertEqual(receive_frame(lab.crypto, lab.sessions["alice"].ratchet, frame,
                                      lab.sessions["alice"].metadata_key, lab.credentials())[1], b"live")


if __name__ == "__main__":
    unittest.main()
