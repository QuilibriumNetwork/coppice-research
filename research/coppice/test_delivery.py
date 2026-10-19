from copy import deepcopy
from dataclasses import replace
import unittest

from fixtures import Lab
from core import Client, DeferredUpdate, digest
from delivery import issue_batch, Inventory, ContributionOutbox, accept_partial, Partial
from envelopes import seal_control, open_control
from service import Record


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.lab = Lab()
        self.lab.epoch()
        lab = self.lab
        self.clients = {name: Client(b"s" * 32, lab.checkpoint.identifier,
                                    members=lab.roster.indices(), group=lab.group)
                        for name in lab.signers}
        self.inventories = {name: Inventory(name) for name in lab.signers}
        self.producer = ContributionOutbox("alice")

    def tickets(self, shared=True):
        lab = self.lab
        if shared:
            issued = issue_batch(lab.crypto, lab.roster, lab.checkpoint.identifier, "bob", lab.signers["bob"],
                                 [(tuple(lab.signers), "alice")])
        else:
            issued = sum((issue_batch(lab.crypto, lab.roster, lab.checkpoint.identifier, name,
                                      lab.signers[name], [((name,), "alice")]) for name in lab.signers), ())
        for ticket, key in issued:
            for holder in ticket.descriptor.holders:
                self.inventories[holder].install(lab.crypto, lab.roster, lab.checkpoint.identifier, ticket, key)
        return [ticket for ticket, _ in issued]

    def contribution(self, tickets=None):
        lab = self.lab
        tickets = self.tickets() if tickets is None else tickets
        return self.producer.create(lab.crypto, lab.roster, lab.checkpoint.identifier,
                                    lab.signers["alice"], tickets)

    def receive(self, name, partial):
        lab = self.lab
        return accept_partial(lab.crypto, lab.roster, self.clients[name], self.inventories[name], partial)

    def test_authenticated_shared_delivery_then_sender_update_and_message(self):
        partial = self.contribution()[0]
        for name in ("alice", "dave", "bob", "carol"):
            identifier = self.receive(name, partial)
            self.assertEqual(self.inventories[name].secrets, {})
        alice = self.clients["alice"]
        update = alice.make_update("alice", [identifier])
        for client in self.clients.values():
            client.receive_update(update)
        message = alice.send("alice")
        for name in ("bob", "carol", "dave"):
            self.clients[name].receive(message)
            self.assertEqual(self.clients[name].lanes, alice.lanes)

    def test_direct_fallback_partial_fetches_have_authenticated_paths(self):
        partials = self.contribution(self.tickets(shared=False))
        self.assertEqual(len(partials), 4)
        identifiers = {self.receive(p.ticket.descriptor.holders[0], p) for p in reversed(partials)}
        self.assertEqual(len(identifiers), 1)
        for partial in partials:
            self.assertEqual(Partial.read(partial.wire()), partial)

    def test_sealed_partial_transport_does_not_expose_author_or_assignment(self):
        lab = self.lab
        partial = self.contribution()[0]
        session = lab.sessions["alice"]
        frame = seal_control(lab.crypto, lab.signers["alice"], session.metadata_key,
                             lab.group, lab.checkpoint.identifier, "publication", partial.wire())
        selector = digest(b"sealed partial", frame)
        lab.service.put(lab.route, session.delivery_capability, Record(selector, frame))
        returned = lab.service.get(lab.route, session.delivery_capability, selector).ciphertext
        author, kind, raw = open_control(lab.crypto, returned, session.metadata_key,
                                        lab.group, lab.checkpoint.identifier, set(lab.credentials().values()))
        self.receive("bob", Partial.read(raw))
        view = lab.service.public_view()
        for name in lab.signers:
            self.assertNotIn(name.encode(), view)
            self.assertNotIn(lab.signers[name].public, view)

    def test_bad_signature_path_slot_or_ticket_binding_does_not_consume(self):
        partial = self.contribution()[0]
        bad_cases = (replace(partial, signature=b"forged"),
                     replace(partial, slot=partial.slot[:-1] + bytes([partial.slot[-1] ^ 1])),
                     replace(partial, proof=replace(partial.proof, count=2)),
                     replace(partial, ticket=replace(partial.ticket, descriptor=replace(
                         partial.ticket.descriptor, producer="carol"))))
        before = dict(self.inventories["bob"].secrets)
        for bad in bad_cases:
            with self.assertRaises(ValueError):
                self.receive("bob", bad)
            self.assertEqual(self.inventories["bob"].secrets, before)
            self.assertEqual(self.clients["bob"].entropy, {})

    def test_incomplete_overlapping_or_wrong_producer_coverage_rejected(self):
        tickets = self.tickets(shared=False)
        for selection in (tickets[:-1], tickets + tickets[:1]):
            with self.assertRaises(ValueError):
                self.contribution(selection)
        lab = self.lab
        with self.assertRaises(ValueError):
            ContributionOutbox("bob").create(lab.crypto, lab.roster, lab.checkpoint.identifier,
                                              lab.signers["bob"], tickets)

    def test_manifest_cannot_claim_arbitrary_subset_as_shared_shard(self):
        lab = self.lab
        with self.assertRaises(ValueError):
            issue_batch(lab.crypto, lab.roster, lab.checkpoint.identifier,
                        "bob", lab.signers["bob"], [(("alice", "bob"), "alice")])

    def test_ticket_and_contribution_replay_does_not_restore_leaf(self):
        partial = self.contribution()[0]
        identifier = self.receive("alice", partial)
        client = self.clients["alice"]
        client.receive_update(client.make_update("alice", [identifier]))
        nodes = dict(client.entropy[identifier].nodes)
        self.receive("alice", partial)
        self.assertEqual(client.entropy[identifier].nodes, nodes)
        self.assertFalse(client.entropy[identifier].covers(0))

    def test_frontier_quota_keeps_unconsumed_ticket(self):
        partial = self.contribution()[0]
        self.clients["bob"].max_frontier_bytes = 32
        before = dict(self.inventories["bob"].secrets)
        with self.assertRaises(DeferredUpdate):
            self.receive("bob", partial)
        self.assertEqual(self.inventories["bob"].secrets, before)
        self.assertEqual(self.clients["bob"].consumed_tickets, {})

    def test_offline_copy_still_exposes_its_unread_contribution(self):
        partial = self.contribution()[0]
        self.receive("alice", partial)
        self.assertEqual(self.inventories["alice"].secrets, {})
        self.assertTrue(self.inventories["bob"].secrets)
        self.receive("bob", partial)  # No contact with the original contributor.
        self.assertEqual(self.clients["bob"].seen_entropy, self.clients["alice"].seen_entropy)

    def test_reservation_crash_cannot_recycle_private_delivery_ticket(self):
        lab = self.lab
        tickets = self.tickets()
        with self.assertRaises(RuntimeError):
            self.producer.create(lab.crypto, lab.roster, lab.checkpoint.identifier,
                                 lab.signers["alice"], tickets, crash_after_reservation=True)
        with self.assertRaises(ValueError):
            self.contribution(tickets)

    def test_successor_delivery_waits_without_consuming_its_ticket(self):
        lab = self.lab
        first = self.contribution()[0]
        first_id = digest(b"contribution", first.header)
        second = self.producer.create(lab.crypto, lab.roster, lab.checkpoint.identifier,
                                      lab.signers["alice"], self.tickets(), 1, first_id)[0]
        with self.assertRaises(LookupError):
            self.receive("bob", second)
        self.assertIn(second.ticket.descriptor.identifier, self.inventories["bob"].secrets)
        self.receive("bob", first)
        self.receive("bob", second)


if __name__ == "__main__":
    unittest.main()
