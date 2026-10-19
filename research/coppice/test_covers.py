from copy import deepcopy
from dataclasses import replace
import random
import unittest

from cover import (CapsuleBuilder, CoverInventory, SparseRoster, choose_cover,
                   identity, open_metadata, seal_metadata, resume_capsule)
from cover_lab import CoverLab
from compare_covers import cover_experiment, exhaustion_experiment, repair_experiment
from durability import DurableDevice, Crash
from envelopes import message_frame, receive_frame
from service import Meter
from wire import Proof, pack, unpack


NAMES = tuple(f"member-{i}" for i in range(8))


def make_lab(mode="tree", depth=4, producers=None):
    lab = CoverLab(NAMES, mode, shard_size=4)
    lab.provision(depth, producers=producers)
    lab.epoch()
    return lab


class CoverDistributionTests(unittest.TestCase):
    def test_shared_ciphertext_is_uploaded_once_and_online_tickets_are_erased(self):
        lab = make_lab("direct")
        builder = lab.last_builder
        common = [r for (_, selector), r in lab.service.records.items() if selector == builder.common_selector]
        self.assertEqual(len(common), 1)
        self.assertEqual(len(builder.packets), 8)
        for subset, ticket in builder.selected:
            for credential in subset.members:
                inv = lab.inventories[credential.name]
                self.assertNotIn(ticket.identifier, inv.secrets)
                self.assertIn(ticket.identifier, inv.consumed)
        for name in NAMES:
            self.assertEqual(lab.enrollment_secrets[name], {})
            self.assertFalse(lab.enrollment_consumed[name])  # Singleton pools are generated locally.
        for forbidden in ("key", "values", "sender_seed", "plaintext", "box_key"):
            self.assertFalse(hasattr(builder, forbidden))

    def test_shard_removal_uses_unaffected_shard_and_exact_direct_fallback(self):
        lab = make_lab("shard")
        self.assertEqual(len(lab.last_builder.selected), 2)
        lab.epoch([n for n in NAMES if n != NAMES[2]])
        sizes = sorted(len(s.members) for s, _ in lab.last_builder.selected)
        self.assertEqual(sizes, [1, 1, 1, 4])

    def test_tree_single_removal_uses_logarithmic_cover(self):
        lab = make_lab()
        self.assertEqual(len(lab.last_builder.selected), 1)
        lab.epoch([n for n in NAMES if n != NAMES[3]])
        self.assertEqual(sorted(len(s.members) for s, _ in lab.last_builder.selected), [1, 2, 4])

    def test_randomized_covers_are_disjoint_complete_and_exclude_removed_keys(self):
        lab = make_lab(depth=3)
        for seed in range(16):
            removed = set(random.Random(seed).sample(list(NAMES[1:]), 3))
            roster = SparseRoster(lab.group, [c for n, c in lab.credentials.items() if n not in removed], lab.capacity)
            selected = choose_cover(lab.subsets, roster, lab.pools, identity(lab.credentials[NAMES[0]]), lab.reserved)
            holders = [c.name for s, _ in selected for c in s.members]
            self.assertEqual(set(holders), set(NAMES) - removed)
            self.assertEqual(len(holders), len(set(holders)))
            for _, ticket in selected:
                for name in removed:
                    self.assertNotIn(ticket.identifier, lab.inventories[name].secrets)

    def test_removed_member_cannot_open_any_selected_wrapper(self):
        lab = make_lab(depth=3)
        removed = NAMES[3]
        old_secrets = tuple(lab.inventories[removed].secrets.values())
        lab.epoch([n for n in NAMES if n != removed])
        for packet in lab.last_builder.packets.values():
            subset, ticket, wrapped, _, common = open_metadata(
                lab.crypto, lab.lookup_key, packet, pack((lab.group, lab.checkpoint.identifier, "cover wrapper")))
            for secret in old_secrets:
                with self.assertRaises(ValueError):
                    lab.crypto.open_with(secret, wrapped, pack((lab.group, lab.checkpoint.identifier, subset, ticket, common)))
        with self.assertRaises(LookupError):
            lab.return_device(removed)

    def test_join_uses_new_cohort_without_giving_old_pool_keys(self):
        lab = make_lab()
        previous_common = lab.last_builder.common
        old_ticket_ids = set().union(*(set(i.refs) for i in lab.inventories.values()))
        lab.add_identity("new-member")
        added = lab.add_cohort(("new-member",))
        lab.provision(3, subsets=added, online=(*NAMES, "new-member"))
        lab.epoch((*NAMES, "new-member"))
        self.assertEqual(sorted(len(s.members) for s, _ in lab.last_builder.selected), [1, 8])
        self.assertFalse(set(lab.inventories["new-member"].refs) & old_ticket_ids)
        self.assertNotEqual(lab.last_builder.common, previous_common)
        new = lab.sessions["new-member"]
        frame = message_frame(lab.crypto, new.ratchet, "new-member", lab.signers["new-member"], new.metadata_key, b"joined")
        lab.learn_sender(NAMES[0], "new-member")
        receiver = lab.sessions[NAMES[0]]
        self.assertEqual(receive_frame(lab.crypto, receiver.ratchet, frame, receiver.metadata_key,
                                      lab.public_credentials()), ("new-member", b"joined"))

    def test_replacement_author_needs_assigned_inventory(self):
        lab = make_lab()
        old = lab.log.head
        with self.assertRaises(LookupError):
            lab.epoch(author=NAMES[1])
        self.assertEqual(lab.log.head, old)
        lab.provision(2, producers=(NAMES[1],))
        lab.epoch(author=NAMES[1])
        self.assertTrue(all(t.manifest.scope.producer == identity(lab.credentials[NAMES[1]])
                            for _, t in lab.last_builder.selected))

    def test_preprovisioned_authors_rotate_while_recipient_is_offline(self):
        lab = make_lab(producers=NAMES[:2])
        for i in range(3):
            lab.epoch(online=NAMES[:-1], author=NAMES[i % 2])
        lab.now = 7 * 86400
        before = deepcopy(lab.meters)
        meter = Meter()
        session = lab.return_device(NAMES[-1], meter)
        self.assertEqual(session.checkpoint, lab.checkpoint)
        self.assertEqual(lab.meters, before)
        self.assertEqual(meter.round_trips, 4)
        self.assertLess(meter.download, 64_000)

    def test_ready_catalog_follows_complete_private_pool_preparation(self):
        lab = CoverLab(NAMES, "tree")
        original = lab._get
        observed = []
        def checked(selector, tag, name, phase):
            value = original(selector, tag, name, phase)
            if tag == "pool catalog":
                observed.append(selector)
                # A catalog is the producer's readiness signal. All enrollment
                # parent keys have already been erased in this setup adapter.
                self.assertTrue(all(not keys for keys in lab.enrollment_secrets.values()))
                body, signature = value
                self.assertEqual(len(signature), 666)
                self.assertIsInstance(unpack(body)[0], bytes)
            return value
        lab._get = checked
        lab.provision(2, producers=(NAMES[1],))
        self.assertTrue(observed)

    def test_public_directory_only_uploads_changed_hash_paths(self):
        lab = make_lab()
        old_count = len(lab.known_hashes)
        lab.epoch()
        self.assertEqual(len(lab.known_hashes), old_count)
        lab.epoch([n for n in NAMES if n != NAMES[3]])
        self.assertEqual(len(lab.known_hashes) - old_count, lab.capacity.bit_length())

    def test_opaque_service_view_contains_no_credentials_private_keys_or_signatures(self):
        lab = make_lab(depth=2)
        view = lab.service.public_view()
        for name, credential in lab.credentials.items():
            self.assertNotIn(name.encode(), view)
            self.assertNotIn(credential.public, view)
            self.assertNotIn(credential.blind, view)
            for secret in lab.inventories[name].secrets.values():
                self.assertNotIn(secret, view)
        self.assertFalse(hasattr(lab.service, "crypto"))


class CoverAdversaryTests(unittest.TestCase):
    def test_bad_public_ticket_and_wrong_producer_do_not_reserve(self):
        lab = make_lab("direct")
        selected = choose_cover(lab.subsets, lab.roster, lab.pools, identity(lab.credentials[NAMES[0]]), lab.reserved)
        subset, ticket = selected[0]
        broken = ((subset, replace(ticket, public=b"x" * 930)), *selected[1:])
        before = lab.reserved.copy()
        with self.assertRaises(ValueError):
            self.build(lab, broken)
        self.assertEqual(lab.reserved, before)
        with self.assertRaises(ValueError):
            self.build(lab, selected, author=NAMES[1])
        self.assertEqual(lab.reserved, before)

    @staticmethod
    def build(lab, selected, author=NAMES[0], crash=False):
        return CapsuleBuilder(lab.crypto, lab.governance, [lab.guardian], lab.log, lab.roster,
                              lab.checkpoint, lab.checkpoint.policy, lab.signers[author], lab.credentials[author],
                              selected, lab.reserved, lab.route, lab.lookup_key, crash_after_reservation=crash)

    def test_incomplete_and_overlapping_cover_never_advance_finality(self):
        lab = make_lab("direct")
        selected = choose_cover(lab.subsets, lab.roster, lab.pools, identity(lab.credentials[NAMES[0]]), lab.reserved)
        head, reserved = lab.log.head, lab.reserved.copy()
        for bad in (selected[:-1], (*selected, selected[0])):
            with self.assertRaises(ValueError):
                self.build(lab, bad)
        self.assertEqual(lab.log.head, head)
        self.assertEqual(lab.reserved, reserved)

    def test_reservation_crash_abandons_tickets_and_retry_is_immutable(self):
        lab = make_lab()
        selected = choose_cover(lab.subsets, lab.roster, lab.pools, identity(lab.credentials[NAMES[0]]), lab.reserved)
        head = lab.log.head
        with self.assertRaises(RuntimeError):
            self.build(lab, selected, crash=True)
        self.assertEqual(lab.log.head, head)
        self.assertTrue(all(t.identifier in lab.reserved for _, t in selected))
        with self.assertRaises(ValueError):
            self.build(lab, selected)
        lab.epoch()
        builder, roster = lab.last_builder, lab.roster
        old = dict(builder.packets), builder.common, lab.checkpoint
        builder.publish(lab.service, lab.store_route, lab.store_cap, Meter(), lab.known_hashes, roster, 31*86400)
        self.assertEqual(old, (builder.packets, builder.common, builder.checkpoint))

    def test_concurrent_authors_cannot_finalize_conflicting_checkpoints(self):
        lab = make_lab(producers=NAMES[:2])
        first, _ = lab.prepare(author=NAMES[0])
        second, _ = lab.prepare(author=NAMES[1])
        first.finish()
        with self.assertRaises(ValueError):
            second.finish()
        self.assertEqual(lab.log.head, first.checkpoint)
        self.assertTrue(all(t.identifier in lab.reserved for _, t in second.selected))

    def test_withheld_common_or_proof_does_not_consume_entry(self):
        for what in ("common", "proof"):
            lab = make_lab()
            lab.epoch(online=NAMES[:-1])
            before = deepcopy(lab.inventories[NAMES[-1]])
            hidden = lab.last_builder.common_selector if what == "common" else lab.checkpoint.roster_root
            lab.service.withheld.add(hidden)
            with self.assertRaises(LookupError):
                lab.return_device(NAMES[-1])
            self.assertEqual(lab.inventories[NAMES[-1]], before)
            lab.service.withheld.clear()
            lab.return_device(NAMES[-1])

    def test_tampered_common_and_roster_proof_are_rejected_without_erasure(self):
        for what in ("common", "proof"):
            lab = make_lab()
            lab.epoch(online=NAMES[:-1])
            before = deepcopy(lab.inventories[NAMES[-1]])
            selector = lab.last_builder.common_selector if what == "common" else lab.checkpoint.roster_root
            original = lab.service.records[lab.store_route, selector]
            forged = b"corrupt" if what == "common" else pack((b"x"*32, b"y"*32))
            lab.service.records[lab.store_route, selector] = replace(original, ciphertext=forged)
            with self.assertRaises((ValueError, LookupError)):
                lab.return_device(NAMES[-1])
            self.assertEqual(lab.inventories[NAMES[-1]], before)

    def test_same_era_and_stale_log_never_restore_consumed_roots(self):
        lab = make_lab()
        target = NAMES[-1]
        session = lab.sessions[target]
        session.ratchet.send(target)
        before = deepcopy(session.ratchet.lanes)
        meter = Meter()
        self.assertIs(lab.return_device(target, meter), session)
        self.assertEqual(meter.round_trips, 1)
        self.assertEqual(session.ratchet.lanes, before)
        replay = lab.log.latest(lab.crypto.fresh())
        with self.assertRaises(ValueError):
            resume_capsule(lab.crypto, lab.governance, lab.log, lab.service, lab.group,
                           lab.inventories[target], lab.lookup_key, lab.store_route, lab.store_cap,
                           session, latest_response=replay)

    def test_expiry_is_explicit_and_offline_inventory_is_not_replenished(self):
        lab = make_lab()
        lab.epoch(online=NAMES[:-1])
        before = deepcopy(lab.inventories[NAMES[-1]])
        lab.service.collect(31*86400)
        with self.assertRaises(LookupError):
            lab.return_device(NAMES[-1])
        with self.assertRaises(LookupError):
            lab.provision(1, online=NAMES[:-1])
        self.assertEqual(lab.inventories[NAMES[-1]], before)

    def test_entry_installation_and_ticket_erasure_are_one_durable_transaction(self):
        lab = make_lab()
        target = NAMES[-1]
        lab.epoch(online=NAMES[:-1])
        device = DurableDevice({"inventory": lab.inventories[target], "session": lab.sessions[target]})
        def operation(state, _):
            state["session"] = resume_capsule(lab.crypto, lab.governance, lab.log, lab.service, lab.group,
                state["inventory"], lab.lookup_key, lab.store_route, lab.store_cap, state["session"])
        original = deepcopy(device.state["inventory"])
        with self.assertRaises(Crash):
            device.transact(operation, crash="before_commit")
        self.assertEqual(device.state["inventory"], original)
        with self.assertRaises(Crash):
            device.transact(operation, crash="after_commit")
        self.assertEqual(device.state["session"].checkpoint, lab.checkpoint)
        self.assertEqual(len(device.state["inventory"].secrets), len(original.secrets)-1)
        device.transact(operation)
        self.assertEqual(len(device.state["inventory"].secrets), len(original.secrets)-1)

    def test_pool_reimport_or_key_alias_cannot_restore_consumed_ticket(self):
        # A captured setup snapshot is an adversarial backup, not retained endpoint state.
        fresh = CoverLab(("alice", "bob"), "direct")
        fresh.provision(2)
        node = next(s for s in fresh.subsets if s.members[0].name == "bob")
        items = fresh.pools[node.identifier, identity(fresh.credentials["alice"])]
        inv = fresh.inventories["bob"]
        keys = tuple((t.public, inv.secrets[t.identifier]) for t in items)
        fresh.epoch()
        with self.assertRaises(ValueError):
            inv.import_box(fresh.crypto, fresh.governance, fresh.group, items[0].manifest, keys, node.proof(inv.credential))
        empty = CoverInventory(fresh.credentials["bob"])
        bad = ((keys[0][0], b"x"*1234), keys[1])
        with self.assertRaises(ValueError):
            empty.import_box(fresh.crypto, fresh.governance, fresh.group, items[0].manifest, bad, node.proof(inv.credential))
        self.assertEqual(empty.secrets, {})

    def test_pool_import_and_parent_erasure_are_atomic(self):
        lab = CoverLab(("alice", "bob"), "direct")
        lab.provision(2)
        subset = next(s for s in lab.subsets if s.members[0].name == "bob")
        tickets = lab.pools[subset.identifier, identity(lab.credentials["alice"])]
        keys = tuple((t.public, lab.inventories["bob"].secrets[t.identifier]) for t in tickets)
        device = DurableDevice({"inventory": CoverInventory(lab.credentials["bob"]), "enrollment_key": b"fixture parent"})
        def operation(state, _):
            state["inventory"].import_box(lab.crypto, lab.governance, lab.group, tickets[0].manifest,
                                          keys, subset.proof(lab.credentials["bob"]))
            del state["enrollment_key"]
        with self.assertRaises(Crash):
            device.transact(operation, crash="before_commit")
        self.assertEqual(device.state["inventory"].secrets, {})
        self.assertIn("enrollment_key", device.state)
        with self.assertRaises(Crash):
            device.transact(operation, crash="after_commit")
        self.assertEqual(len(device.state["inventory"].secrets), 2)
        self.assertNotIn("enrollment_key", device.state)

    def test_unread_ticket_compromise_is_exposed_and_consumed_copy_is_deleted(self):
        lab = make_lab()
        target = NAMES[-1]
        captured = dict(lab.inventories[target].secrets)
        lab.epoch(online=NAMES[:-1])
        packet = next(iter(lab.last_builder.packets.values()))
        subset, ticket, wrapped, _, common = open_metadata(
            lab.crypto, lab.lookup_key, packet, pack((lab.group, lab.checkpoint.identifier, "cover wrapper")))
        key = lab.crypto.open_with(captured[ticket], wrapped,
                                  pack((lab.group, lab.checkpoint.identifier, subset, ticket, common)))
        self.assertIsInstance(lab.crypto.open(key, lab.last_builder.common,
                            pack((lab.group, lab.checkpoint.identifier, "shared entry"))), tuple)
        lab.return_device(target)
        self.assertNotIn(ticket, lab.inventories[target].secrets)
        # Advancing precompromised inventory does NOT heal this exposure.
        self.assertIn(ticket, captured)

    def test_cross_group_scope_and_unapproved_pool_fail(self):
        lab = make_lab()
        manifest = lab.last_builder.selected[0][1].manifest
        with self.assertRaises(ValueError):
            manifest.verify(lab.crypto, lab.governance, b"other group")
        with self.assertRaises(ValueError):
            replace(manifest, scope=replace(manifest.scope, approvals=())).verify(lab.crypto, lab.governance, lab.group)

    def test_metadata_encryption_uses_fresh_context_bound_keys(self):
        lab = CoverLab()
        aad = pack((lab.group, "metadata"))
        first = seal_metadata(lab.crypto, lab.lookup_key, b"same", aad)
        second = seal_metadata(lab.crypto, lab.lookup_key, b"same", aad)
        self.assertNotEqual(unpack(first)[0], unpack(second)[0])
        self.assertEqual(open_metadata(lab.crypto, lab.lookup_key, first, aad), b"same")
        with self.assertRaises(ValueError):
            open_metadata(lab.crypto, lab.lookup_key, first, b"wrong context")
        salt, cipher = unpack(first)
        with self.assertRaises(ValueError):
            open_metadata(lab.crypto, lab.lookup_key, pack((unpack(second)[0], cipher)), aad)

    def test_private_inventory_and_return_discovery_budgets_are_explicit(self):
        lab = make_lab("direct", depth=2)
        subset = next(s for s in lab.subsets if s.members[0].name == NAMES[-1])
        items = lab.pools[subset.identifier, identity(lab.credentials[NAMES[0]])]
        inv = CoverInventory(lab.credentials[NAMES[-1]], max_private_bytes=1)
        with self.assertRaises(LookupError):
            inv.import_box(lab.crypto, lab.governance, lab.group, items[0].manifest,
                           tuple((t.public, b"x"*1234) for t in items), subset.proof(inv.credential))
        self.assertEqual(inv.secrets, {})
        lab.epoch(online=NAMES[:-1])
        before = deepcopy(lab.inventories[NAMES[-1]])
        with self.assertRaises(LookupError):
            resume_capsule(lab.crypto, lab.governance, lab.log, lab.service, lab.group,
                           before, lab.lookup_key, lab.store_route, lab.store_cap,
                           lab.sessions[NAMES[-1]], lookup_budget=0)
        self.assertEqual(before, lab.inventories[NAMES[-1]])


class CoverReportTests(unittest.TestCase):
    def test_return_cost_does_not_grow_with_missed_eras_but_inventory_does(self):
        short = cover_experiment("tree", devices=8, changes=1, churn=False, messages=10)
        long = cover_experiment("tree", devices=8, changes=4, churn=False, messages=10)
        self.assertEqual(short["resume_control"]["download_bytes"], long["resume_control"]["download_bytes"])
        self.assertGreater(long["provisioning_all_devices"]["upload_bytes"], short["provisioning_all_devices"]["upload_bytes"])
        self.assertTrue(long["busy_sender_needed_backlog"])
        self.assertEqual(long["participant_actions_required_at_return"], 0)

    def test_reports_include_setup_busiest_device_fragmentation_and_repair(self):
        direct = cover_experiment("direct", devices=8, changes=3, messages=10)
        tree = cover_experiment("tree", devices=8, changes=3, messages=10)
        self.assertLess(tree["transition_authors_during_absence"]["upload_bytes"], direct["transition_authors_during_absence"]["upload_bytes"])
        self.assertGreater(tree["provisioning_all_devices"]["upload_bytes"], direct["provisioning_all_devices"]["upload_bytes"])
        self.assertGreater(tree["provisioning_all_devices"]["peak_device_download_bytes"], 0)
        self.assertLess(tree["all_modeled_control_traffic_including_setup"]["upload_bytes"],
                        tree["all_modeled_device_traffic_including_setup"]["upload_bytes"])
        self.assertGreater(tree["returning_device_storage_before_absence"]["raw_private_ticket_bytes"], 0)
        repair = repair_experiment("tree")
        self.assertLess(repair["wraps_after_rebuild"], repair["wraps_before_rebuild"])
        self.assertGreater(repair["explicit_rebuild_traffic"]["upload_bytes"], 0)

    def test_exhaustion_can_fragment_cover_before_blocking(self):
        tree = exhaustion_experiment("tree")
        self.assertEqual(tree["wraps_until_exhaustion_including_genesis"], [1, 2, 4, 8])
        self.assertTrue(tree["offline_holder_not_silently_replenished"])
        self.assertTrue(tree["no_finality_advance_on_exhaustion"])
        self.assertTrue(tree["existing_lane_continued"])
        self.assertTrue(tree["transition_succeeded_after_replenishment"])


if __name__ == "__main__":
    unittest.main()
