"""Regression tests for the symbolic Coppice core.

Run the complete suite with: python3 -B research/coppice/run.py
"""
from copy import deepcopy
from itertools import permutations
import unittest
from core import (SUITE, GROUP, ERA, MEMBERS, u64, encode, digest, kdf,
                  SecretFrontier, Contribution, Update, Lane, Message, Client,
                  DeliveryTicket, DeliverySlot, TicketOutbox, TicketBoxLane,
                  TicketBox, AdmissionCapability, receiving_partition,
                  header_material)


class ProtocolModelTests(unittest.TestCase):
    def contribution(self, name, era=ERA):
        return Contribution(era, name.encode(), digest(b"test entropy", name.encode()))

    def test_tree_frontier_cannot_reopen_consumed_leaf(self):
        tree = SecretFrontier(b"s" * 32, ERA, 8)
        reference = SecretFrontier(b"s" * 32, ERA, 8)
        self.assertEqual(tree.open(2), reference.open(2))
        self.assertFalse(tree.covers(2))
        with self.assertRaises(ValueError):
            tree.open(2)
        for index in (7, 0, 5, 1, 6, 3, 4):
            self.assertEqual(tree.open(index), reference.open(index))
            for consumed in tree.opened:
                self.assertFalse(tree.covers(consumed))
        self.assertEqual(tree.nodes, {})

    def test_non_power_of_two_tree_discards_padding_and_bounds_frontier(self):
        for count in (1, 3, 5, 17, 78):
            tree = SecretFrontier(b"s" * 32, ERA, count)
            order = list(range(0, count, 2)) + list(range(1, count, 2))
            for consumed, index in enumerate(order, 1):
                tree.open(index)
                bound = min(count - consumed, consumed * tree.depth)
                self.assertLessEqual(len(tree.nodes), bound)
                self.assertTrue(all(not tree.covers(leaf) for leaf in tree.opened))
            self.assertEqual(tree.nodes, {})

    def test_two_senders_and_entropy_deliver_in_every_order(self):
        sender = Client()
        a, b = self.contribution("a"), self.contribution("b")
        sender.add_contribution(a)
        sender.add_contribution(b)
        ua = sender.make_update("alice", [a.identifier])
        ub = sender.make_update("bob", [b.identifier])
        sender.receive_update(ua)
        sender.receive_update(ub)
        ma, mb = sender.send("alice"), sender.send("bob")
        for order in permutations([a, b, ua, ub]):
            receiver = Client()
            for event in order:
                if isinstance(event, Contribution):
                    receiver.add_contribution(event)
                else:
                    receiver.receive_update(event)
            receiver.receive(mb)
            receiver.receive(ma)
            self.assertEqual(receiver.lanes, sender.lanes)
            self.assertEqual(receiver.pending, {})

    def test_successor_waits_for_predecessor_without_blocking_other_lane(self):
        sender, receiver = Client(), Client()
        a, b = self.contribution("a"), self.contribution("b")
        for client in (sender, receiver):
            client.add_contribution(a)
            client.add_contribution(b)
        first = sender.make_update("alice", [a.identifier])
        sender.receive_update(first)
        second = sender.make_update("alice", [b.identifier])
        sender.receive_update(second)
        receiver.receive_update(second)
        receiver.receive(sender.send("bob"))
        self.assertNotIn("alice", receiver.lanes)
        self.assertEqual(len(receiver.pending), 1)
        receiver.receive_update(first)
        self.assertEqual(receiver.lanes["alice"], sender.lanes["alice"])

    def test_offline_replay_many_generations_in_reversed_batches(self):
        sender = Client()
        archive = []
        for index in range(40):
            event = self.contribution(f"offline-{index}")
            sender.add_contribution(event)
            update = sender.make_update("alice", [event.identifier])
            sender.receive_update(update)
            archive.append((event, update, sender.send("alice")))
        # Receiver uses only the stored archive. No sender interaction or clocks.
        receiver = Client(max_skip=64)
        for offset in range(0, len(archive), 10):
            batch = archive[offset:offset + 10]
            for _, update, _ in reversed(batch):
                receiver.receive_update(update)
            for event, _, _ in reversed(batch):
                receiver.add_contribution(event)
        for _, _, message in reversed(archive):
            receiver.receive(message)
        self.assertEqual(receiver.pending, {})
        self.assertEqual(receiver.skipped, {})
        self.assertEqual(receiver.lanes, sender.lanes)

    def test_deleted_message_cannot_be_replayed_after_entropy_is_relearned(self):
        sender, receiver = Client(), Client()
        a = self.contribution("a")
        sender.add_contribution(a)
        receiver.add_contribution(a)
        initial = sender.make_update("alice", [a.identifier])
        sender.receive_update(initial)
        receiver.receive_update(initial)
        message = sender.send("alice")
        receiver.receive(message)
        live = deepcopy(receiver.lanes["alice"])
        receiver.add_contribution(a)  # Duplicate delivery must not restore entropy leaves.
        receiver.receive_update(initial)  # Replayed control object cannot reset lane.
        self.assertEqual(receiver.lanes["alice"], live)
        self.assertFalse(receiver.frontier.covers(MEMBERS["alice"]))
        with self.assertRaises(ValueError):
            receiver.receive(message)

    def test_negative_control_reexposing_raw_entropy_still_breaks_security(self):
        sender = Client()
        sender.lane("alice")
        old_compromise = deepcopy(sender)
        healing = self.contribution("previously-unknown-healing-input")
        sender.add_contribution(healing)
        update = sender.make_update("alice", [healing.identifier])
        sender.receive_update(update)
        target = sender.send("alice")
        # Negative control: deliberately violate v0.3 by giving raw entropy to
        # the old snapshot. This is the v0.2 attack the new lifecycle prevents.
        old_compromise.add_contribution(healing)
        old_compromise.receive_update(update)
        reconstructed = old_compromise.send("alice")
        self.assertEqual(reconstructed.key, target.key)

    def ticket(self, index=0, owner="carol"):
        return DeliveryTicket(owner, index, digest(
            b"fresh test ticket", owner.encode(), u64(index)))

    def test_combined_snapshots_cannot_reopen_consumed_healing_input(self):
        receiver = Client()
        receiver.lane("alice")
        old = deepcopy(receiver)
        # This ticket is generated after the old compromise, not from its RNG.
        ticket = self.ticket()
        receiver.install_ticket(ticket)
        healing = self.contribution("fresh-healing")
        slot = TicketOutbox("carol").seal(ticket, healing)
        receiver.receive_slot(slot)
        update = receiver.make_update("alice", [healing.identifier])
        receiver.receive_update(update)
        target = receiver.send("alice")
        later = deepcopy(receiver)
        self.assertNotIn(ticket.identifier, later.tickets)
        with self.assertRaises(ValueError):
            slot.open(None)  # Neither exposure supplies the erased capability.
        frontier = later.entropy[healing.identifier]
        self.assertFalse(frontier.covers(MEMBERS["alice"]))
        with self.assertRaises(ValueError):
            frontier.open(MEMBERS["alice"])
        self.assertTrue(frontier.covers(MEMBERS["bob"]))
        # Give the old snapshot ALL the later entropy frontiers and metadata.
        # These remain useful for Bob but cannot supply Alice's consumed input.
        old.entropy = deepcopy(later.entropy)
        old.metadata = deepcopy(later.metadata)
        old.seen_entropy = set(later.seen_entropy)
        old.receive_update(update)
        self.assertIn("alice", old.frozen)
        self.assertEqual(old.lanes["alice"].generation, 0)
        self.assertNotEqual(old.step("alice"), target.key)
        # Even replaying the original delivery cannot reset the later frontier.
        before = dict(later.entropy[healing.identifier].nodes)
        later.receive_slot(slot)
        self.assertEqual(before, later.entropy[healing.identifier].nodes)
        later.receive_update(later.make_update("bob", [healing.identifier]))
        self.assertEqual(later.lanes["bob"].generation, 1)

    def test_consumed_leaf_stays_punctured_after_duplicate_installation(self):
        client = Client()
        event = self.contribution("puncture")
        client.add_contribution(event)
        original = deepcopy(client.entropy[event.identifier])
        client.receive_update(client.make_update("alice", [event.identifier]))
        client.add_contribution(event)
        self.assertFalse(client.entropy[event.identifier].covers(MEMBERS["alice"]))
        self.assertEqual(client.entropy[event.identifier].open(MEMBERS["bob"]),
                         original.open(MEMBERS["bob"]))
        self.assertIn(event.identifier, client.metadata)
        self.assertTrue(all(isinstance(value, SecretFrontier)
                            for value in client.entropy.values()))

    def test_offline_shared_ticket_copy_is_an_explicit_exposure(self):
        online, offline = Client(), Client()
        ticket = self.ticket()
        for client in (online, offline):
            client.install_ticket(ticket)
        slot = TicketOutbox("carol").seal(ticket, self.contribution("offline"))
        online.receive_slot(slot)
        self.assertNotIn(ticket.identifier, online.tickets)
        self.assertEqual(slot.open(offline.tickets[ticket.identifier].secret), slot.event)
        # Its own consumption needs no interaction with the online recipient.
        offline.receive_slot(slot)
        self.assertNotIn(ticket.identifier, offline.tickets)
        self.assertEqual(online.entropy[slot.event.identifier].nodes,
                         offline.entropy[slot.event.identifier].nodes)

    def test_different_producers_have_disjoint_tickets_and_any_delivery_order(self):
        tickets = [self.ticket(owner=name) for name in ("alice", "bob")]
        slots = [TicketOutbox(ticket.owner).seal(ticket, self.contribution(ticket.owner))
                 for ticket in tickets]
        for order in permutations(slots):
            client = Client()
            for ticket in tickets:
                client.install_ticket(ticket)
            for slot in order:
                client.receive_slot(slot)
            self.assertEqual(len(client.seen_entropy), 2)
            self.assertEqual(client.tickets, {})
        with self.assertRaises(ValueError):
            TicketOutbox("bob").seal(tickets[0], self.contribution("misassigned"))

    def test_wrong_assignment_and_invalid_auth_do_not_consume_ticket(self):
        from dataclasses import replace
        client = Client()
        ticket = self.ticket()
        client.install_ticket(ticket)
        slot = TicketOutbox("carol").seal(ticket, self.contribution("valid"))
        for bad in (replace(slot, author="alice"),
                    replace(slot, purpose=b"transition"),
                    replace(slot, valid=False)):
            with self.assertRaises(ValueError):
                client.receive_slot(bad)
            self.assertIn(ticket.identifier, client.tickets)
            self.assertEqual(client.seen_entropy, set())
        with self.assertRaises(ValueError):
            client.receive_slot(slot, signature_ok=False)
        self.assertIn(ticket.identifier, client.tickets)
        client.receive_slot(slot)

    def test_ticket_reuse_fork_cannot_restore_first_event(self):
        client = Client()
        ticket = self.ticket()
        client.install_ticket(ticket)
        first = TicketOutbox("carol").seal(ticket, self.contribution("first"))
        # A cloned/malicious producer disregards its reservation store.
        fork = TicketOutbox("carol").seal(ticket, self.contribution("fork"))
        client.receive_slot(first)
        with self.assertRaises(ValueError):
            client.receive_slot(fork)
        self.assertNotIn(fork.event.identifier, client.seen_entropy)
        with self.assertRaises(ValueError):
            client.install_ticket(ticket)

    def test_crash_reservation_is_never_recycled_and_retry_is_identical(self):
        producer = TicketOutbox("carol")
        abandoned, usable = self.ticket(0), self.ticket(1)
        event = self.contribution("outbox")
        with self.assertRaises(ValueError):
            producer.seal(abandoned, event, crash_after_reservation=True)
        with self.assertRaises(ValueError):
            producer.seal(abandoned, self.contribution("replacement"))
        slot = producer.seal(usable, event)
        self.assertIs(slot, producer.retry(event.identifier))
        with self.assertRaises(ValueError):
            producer.seal(usable, event)

    def test_shared_ticket_box_cannot_restore_consumed_ticket(self):
        publisher = TicketBoxLane(b"p" * 32)
        before = deepcopy(publisher)
        # An independently delivered producer leaf is consumed here.
        leaf, core = digest(b"healing producer leaf"), b"publication core"
        _, wrapping_key = publisher.material(leaf, core)
        used, unused = self.ticket(0), self.ticket(1)
        box = TicketBox(core, digest(b"symbolic box key", wrapping_key), (used, unused))
        publisher.accept(box, leaf)
        del publisher.tickets[used.identifier]  # Its one contribution was consumed.
        publisher.accept(box, leaf)  # Replay must not import it again.
        self.assertNotIn(used.identifier, publisher.tickets)
        self.assertIn(unused.identifier, publisher.tickets)
        # Even revealing the old leaf does not undo the CURRENT chain step.
        with self.assertRaises(ValueError):
            box.open(publisher.material(leaf, core)[1])
        # Conversely, an earlier chain snapshot needs the erased fresh leaf.
        with self.assertRaises(ValueError):
            box.open(before.material(b"unknown input" * 3, core)[1])
        self.assertNotEqual(unused.secret, used.secret)

    def test_long_offline_replay_consumes_tickets_without_live_peers(self):
        sender, receiver = Client(max_skip=64), Client(max_skip=64)
        producer = TicketOutbox("carol")
        archive = []
        for index in range(40):
            ticket = self.ticket(index)
            for client in (sender, receiver):
                client.install_ticket(ticket)
            event = self.contribution(f"ticketed-{index}")
            slot = producer.seal(ticket, event)
            sender.receive_slot(slot)
            update = sender.make_update("alice", [event.identifier])
            sender.receive_update(update)
            archive.append((slot, update, sender.send("alice")))
        for offset in range(0, len(archive), 10):
            batch = archive[offset:offset + 10]
            for _, update, _ in reversed(batch):
                receiver.receive_update(update)
            for slot, _, _ in reversed(batch):
                receiver.receive_slot(slot)
        for _, _, message in reversed(archive):
            receiver.receive(message)
        self.assertEqual(receiver.lanes, sender.lanes)
        self.assertEqual(receiver.tickets, {})
        self.assertEqual(receiver.pending, {})
        self.assertTrue(all(not frontier.covers(MEMBERS["alice"])
                            for frontier in receiver.entropy.values()))

    def test_missing_ticket_defers_entropy_but_existing_messages_continue(self):
        sender, receiver = Client(), Client()
        slot = TicketOutbox("carol").seal(self.ticket(), self.contribution("no inventory"))
        with self.assertRaises(ValueError):
            receiver.receive_slot(slot)
        self.assertEqual(receiver.entropy, {})
        receiver.receive(sender.send("alice"))
        self.assertEqual(receiver.lanes["alice"], sender.lanes["alice"])

    def test_skipped_key_is_deleted_on_use(self):
        sender, receiver = Client(), Client()
        messages = [sender.send("alice") for _ in range(4)]
        receiver.receive(messages[3])
        self.assertEqual(len(receiver.skipped), 3)
        receiver.receive(messages[1])
        self.assertEqual(len(receiver.skipped), 2)
        with self.assertRaises(ValueError):
            receiver.receive(messages[1])
        receiver.receive(messages[0])
        receiver.receive(messages[2])
        self.assertEqual(receiver.skipped, {})

    def test_skipped_key_quota_is_global_and_failure_is_transactional(self):
        sender, receiver = Client(), Client(max_skip=3)
        alice = [sender.send("alice") for _ in range(3)]
        bob = [sender.send("bob") for _ in range(3)]
        receiver.receive(alice[2])
        previous = deepcopy(receiver.__dict__)
        with self.assertRaises(ValueError):
            receiver.receive(bob[2])
        self.assertEqual(receiver.lanes, previous["lanes"])
        self.assertEqual(receiver.frontier.nodes, previous["frontier"].nodes)
        self.assertEqual(receiver.skipped, previous["skipped"])

    def test_invalid_message_cannot_consume_tree_leaf_or_chain(self):
        sender, receiver = Client(), Client()
        message = sender.send("alice")
        original_frontier = dict(receiver.frontier.nodes)
        with self.assertRaises(ValueError):
            receiver.receive(message, signature_ok=False)
        self.assertEqual(receiver.lanes, {})
        self.assertEqual(receiver.frontier.nodes, original_frontier)
        receiver.receive(message)

    def test_fork_freezes_only_that_producer_without_rollback(self):
        client = Client()
        a = self.contribution("a")
        client.add_contribution(a)
        update = client.make_update("alice", [a.identifier], b"one")
        conflicting = client.make_update("alice", [a.identifier], b"two")
        client.receive_update(update)
        before = deepcopy(client.lanes["alice"])
        with self.assertRaises(ValueError):
            client.receive_update(conflicting)
        self.assertEqual(client.lanes["alice"], before)
        self.assertIn("alice", client.frozen)
        self.assertEqual(client.send("bob").counter, 0)

    def test_invalid_control_does_not_block_independent_lane(self):
        client = Client()
        event = self.contribution("a")
        client.add_contribution(event)
        valid = client.make_update("alice", [event.identifier])
        invalid = Update(valid.era, valid.sender, valid.generation,
                         b"wrong predecessor", valid.final_counter,
                         valid.references, valid.nonce)
        initial = deepcopy(client.lanes["alice"])
        client.receive_update(invalid)
        self.assertEqual(client.lanes["alice"], initial)
        self.assertIn("alice", client.frozen)
        client.receive_update(client.make_update("bob", [event.identifier]))
        self.assertEqual(client.lanes["bob"].generation, 1)

    def test_update_waits_for_capacity_without_treating_sender_as_faulty(self):
        sender, receiver = Client(), Client(max_skip=1)
        messages = [sender.send("alice") for _ in range(3)]
        event = self.contribution("a")
        sender.add_contribution(event)
        receiver.add_contribution(event)
        update = sender.make_update("alice", [event.identifier])
        receiver.receive_update(update)
        self.assertEqual(len(receiver.pending), 1)
        self.assertEqual(receiver.frozen, set())
        for message in messages:
            receiver.receive(message)
        self.assertEqual(receiver.pending, {})
        self.assertEqual(receiver.lanes["alice"].generation, 1)

    def test_old_generation_unread_messages_survive_sender_update(self):
        sender, receiver = Client(), Client()
        old = [sender.send("alice") for _ in range(3)]
        event = self.contribution("a")
        for client in (sender, receiver):
            client.add_contribution(event)
        update = sender.make_update("alice", [event.identifier])
        sender.receive_update(update)
        receiver.receive_update(update)
        receiver.receive(sender.send("alice"))
        for message in reversed(old):
            receiver.receive(message)
        self.assertEqual(receiver.skipped, {})

    def test_admission_changes_tree_and_rejects_old_era(self):
        existing = Client()
        old = existing.send("alice")
        joined = Client(seed=b"new-admission-seed" * 2, era=b"membership-era-2")
        with self.assertRaises(ValueError):
            joined.receive(old)
        with self.assertRaises(ValueError):
            joined.add_contribution(self.contribution("old"))
        self.assertNotEqual(joined.send("alice").key, old.key)

    def test_single_use_welcome_cannot_restore_erased_tree(self):
        capability = AdmissionCapability(b"join-plan", b"s" * 32)
        with self.assertRaises(ValueError):
            capability.accept(b"another-plan")
        client = Client(seed=capability.accept(b"join-plan"))
        client.send("alice")
        with self.assertRaises(ValueError):
            capability.accept(b"join-plan")
        self.assertFalse(client.frontier.covers(MEMBERS["alice"]))

    def test_header_material_binds_ciphertext_and_era(self):
        first = header_material(b"h" * 32, ERA, b"ciphertext one")
        self.assertEqual(first, header_material(b"h" * 32, ERA, b"ciphertext one"))
        self.assertNotEqual(first, header_material(b"h" * 32, ERA, b"ciphertext two"))
        self.assertNotEqual(first, header_material(b"h" * 32, b"another-era", b"ciphertext one"))

    def test_removal_excludes_old_shard_key_and_uses_direct_fallback(self):
        slots = receiving_partition({"alice", "bob", "carol"}, [
            {"alice", "removed"}, {"bob", "carol"},
        ])
        self.assertEqual(slots, [frozenset({"bob", "carol"}), frozenset({"alice"})])
        self.assertTrue(all("removed" not in slot for slot in slots))

    def test_duplicate_entropy_references_and_pending_flood_are_rejected(self):
        client = Client(max_pending=1)
        event = self.contribution("a")
        with self.assertRaises(ValueError):
            client.receive_update(client.make_update("alice", [event.identifier] * 2))
        client.receive_update(client.make_update("alice", [event.identifier]))
        with self.assertRaises(ValueError):
            client.receive_update(client.make_update("bob", [event.identifier]))
        self.assertEqual(len(client.pending), 1)

    def test_unordered_global_hash_ratchet_would_not_converge(self):
        initial, a, b = b"s" * 32, b"a" * 32, b"b" * 32
        advance = lambda state, delta: kdf(encode(state, delta), b"old global ratchet", ERA)
        self.assertNotEqual(advance(advance(initial, a), b), advance(advance(initial, b), a))


if __name__ == "__main__":
    unittest.main(verbosity=2)
