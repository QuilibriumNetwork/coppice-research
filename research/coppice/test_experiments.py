from dataclasses import replace
import random
import unittest
import json
from pathlib import Path

from core import Client, Contribution, DeferredUpdate, digest, ERA
from replay import ReplayQueue, Work, apply_sender_update
from simulate import offline_experiment, history_experiment, frontier_experiment, fork_experiment
from fixtures import Lab


class ReplayTests(unittest.TestCase):
    def test_seeded_dependency_schedules_apply_contributions_updates_and_messages(self):
        sender = Client(max_skip=100)
        events = []
        for number in range(12):
            event = Contribution(ERA, str(number).encode(), digest(b"entropy", str(number).encode()))
            sender.add_contribution(event)
            update = sender.make_update("alice", [event.identifier])
            sender.receive_update(update)
            events.append((event, update, sender.send("alice")))
        for seed in range(20):
            receiver, queue = Client(max_skip=100), ReplayQueue()
            work = []
            previous = None
            for event, update, message in events:
                event_id, update_id = event.identifier, update.identifier
                message_id = digest(b"message work", update_id)
                work.append(Work(event_id, (), 2048, lambda e=event: receiver.add_contribution(e)))
                deps = (event_id,) if previous is None else (event_id, previous)
                work.append(Work(update_id, deps, len(update.body), lambda u=update: apply_sender_update(receiver, u)))
                work.append(Work(message_id, (update_id,), 1090, lambda m=message: receiver.receive(m)))
                previous = update_id
            random.Random(seed).shuffle(work)
            for item in work:
                queue.add(item)
                queue.drain()
            self.assertEqual(queue.pending, {})
            self.assertEqual(queue.failed, {})
            self.assertEqual(receiver.lanes, sender.lanes)
            self.assertEqual(queue.bytes, 0)

    def test_withheld_dependency_does_not_block_other_lane(self):
        queue, seen = ReplayQueue(), []
        queue.add(Work(b"blocked", (b"missing",), 10, lambda: seen.append("blocked")))
        queue.add(Work(b"ready", (), 10, lambda: seen.append("ready")))
        queue.drain()
        self.assertEqual(seen, ["ready"])
        queue.add(Work(b"missing", (), 10, lambda: seen.append("dependency")))
        queue.drain()
        self.assertEqual(seen, ["ready", "dependency", "blocked"])

    def test_cycle_quota_and_explicit_gap_are_visible(self):
        queue = ReplayQueue(max_bytes=10)
        queue.add(Work(b"a", (b"b",), 5, lambda: None))
        with self.assertRaises(ValueError):
            queue.add(Work(b"b", (b"a",), 5, lambda: None))
        with self.assertRaises(ValueError):
            queue.add(Work(b"c", (), 6, lambda: None))
        queue.abandon(b"a")
        with self.assertRaises(ValueError):
            queue.add(Work(b"a", (), 1, lambda: None))

    def test_work_budget_and_invalid_object_isolation(self):
        queue, seen = ReplayQueue(), []
        def invalid():
            raise ValueError("invalid authenticated structure")
        queue.add(Work(b"bad", (), 1, invalid))
        queue.add(Work(b"good", (), 1, lambda: seen.append(True)))
        self.assertEqual(queue.drain(max_work=1), 1)
        self.assertEqual(seen, [])
        queue.drain()
        self.assertEqual(seen, [True])

    def test_resource_deferred_update_is_not_marked_complete(self):
        sender, receiver = Client(), Client(max_skip=1)
        old = [sender.send("alice") for _ in range(3)]
        event = Contribution(ERA, b"pending", b"p" * 32)
        for client in (sender, receiver):
            client.add_contribution(event)
        update = sender.make_update("alice", [event.identifier])
        queue = ReplayQueue()
        queue.add(Work(update.identifier, (), len(update.body), lambda: apply_sender_update(receiver, update)))
        queue.drain()
        self.assertNotIn(update.identifier, queue.completed)
        self.assertIn(update.identifier, queue.pending)
        for message in old:
            receiver.receive(message)
        queue.drain()
        self.assertIn(update.identifier, queue.completed)


class ExperimentTests(unittest.TestCase):
    def test_checked_in_research_vectors_match(self):
        from vectors import generate
        self.assertEqual(json.loads(Path(__file__).with_name("vectors.json").read_text()), generate())

    def test_first_send_cost_is_independent_of_missed_transition_count(self):
        short = offline_experiment(devices=4, changes=1, days=7, messages=10)
        long = offline_experiment(devices=4, changes=8, days=7, messages=10)
        self.assertEqual(short["resume_control"]["download_bytes"], long["resume_control"]["download_bytes"])
        self.assertGreater(long["entry_preparer_upload_during_absence"], short["entry_preparer_upload_during_absence"])
        self.assertEqual(long["virtual_return_time_seconds"], 7 * 86400)
        self.assertTrue(long["under_64000_byte_control_target"])
        self.assertTrue(long["busy_sender_receive_needed_backlog"])
        self.assertEqual(long["other_participant_actions_needed_at_return"], 0)

    def test_reports_include_history_costs_and_failure_boundaries(self):
        history = history_experiment(3)
        self.assertGreater(history["new_member_grant_and_history"]["download_bytes"], 300)
        self.assertFalse(history["live_resume_dependency"])
        self.assertFalse(fork_experiment()["bounded_detection_during_permanent_partition"])
        self.assertGreater(frontier_experiment(128, 100)["projected_fragmented_total_secret_bytes"], 0)

    def test_incomplete_entry_coverage_does_not_advance_finality(self):
        from resumption import EntryBuilder
        from membership import Policy
        lab = Lab()
        previous = lab.epoch()
        builder = EntryBuilder(lab.crypto, lab.group, lab.roster, Policy(), previous,
                               lab.signers["alice"], lab.governance, [lab.guardian], lab.log, lab.route)
        with self.assertRaises(ValueError):
            builder.finish()
        self.assertEqual(lab.log.head, previous)

    def test_removing_preparer_requires_offline_inventory_for_replacement(self):
        lab = Lab()
        lab.epoch()
        lab.provision("dave", 1, "alice")
        with self.assertRaises(LookupError):
            lab.epoch(("bob", "carol", "dave"), online=("bob", "carol"))
        lab.provision("dave", 1, "bob")  # Explicit replenishment while Dave is available.
        lab.epoch(("bob", "carol", "dave"), online=("bob", "carol"))
        lab.return_device("dave")
        self.assertNotIn("alice", lab.roster.by_name)


if __name__ == "__main__":
    unittest.main()
