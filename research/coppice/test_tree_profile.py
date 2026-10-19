from copy import deepcopy
import unittest

from cover import BlindedCredential
from cover_lab import CoverLab
from envelopes import message_frame, receive_frame
from history import ArchiveWriter, ArchiveReader
from membership import Policy
from simulate import report


class SelectedTreeProfileTests(unittest.TestCase):
    def test_default_report_exercises_tree_return_exhaustion_repair_and_history(self):
        result = report(devices=8, changes=2, days=7, producers=2)
        self.assertEqual(result["selected_delivery_profile"], "tree")
        offline = result["offline_tree_experiment"]
        self.assertEqual(offline["mode"], "tree")
        self.assertEqual(offline["participant_actions_required_at_return"], 0)
        self.assertEqual(offline["resume_control"]["round_trips"], 4)
        self.assertTrue(offline["first_current_send_succeeded"])
        self.assertGreater(offline["all_modeled_control_traffic_including_setup"]["upload_bytes"],
                           offline["transition_authors_during_absence"]["upload_bytes"])
        self.assertTrue(result["exhaustion"]["no_finality_advance_on_exhaustion"])
        self.assertTrue(result["repair"]["old_unused_tickets_retained"])
        self.assertTrue(result["history_experiment"]["original_authorship_verified"])

    def test_profile_and_retention_errors_are_explicit(self):
        for options in ({"profile": "unknown"}, {"days": 30},
                        {"profile": "legacy-direct", "producers": 2}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                report(devices=4, changes=1, **options)

    def test_tree_history_profiles_preserve_range_author_and_live_independence(self):
        for policy in (Policy(), Policy(history="WINDOW", window=2), Policy(history="ALL_RETAINED")):
            with self.subTest(policy=policy):
                lab = CoverLab(("alice", "bob"))
                lab.provision(2)
                lab.epoch(policy=policy)
                writer = ArchiveWriter(lab.group)
                route, capability = lab.crypto.fresh(), lab.crypto.fresh()
                lab.service.register(route, capability)
                if policy.history == "NONE":
                    with self.assertRaises(ValueError):
                        writer.append(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"],
                                      0, b"private", lab.service, route, capability)
                else:
                    for position in range(3):
                        writer.append(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"],
                                      position, b"old", lab.service, route, capability)
                old_tickets = set(lab.inventories["alice"].refs)
                lab.add_identity("carol")
                cohort = lab.add_cohort(("carol",))
                lab.provision(1, online=("alice", "bob", "carol"), subsets=cohort)
                lab.epoch(("alice", "bob", "carol"), online=("alice", "bob"),
                          policy=policy, history_boundary=3)
                self.assertFalse(old_tickets & set(lab.inventories["carol"].refs))
                recipient = lab.credentials["carol"]
                self.assertIsInstance(recipient, BlindedCredential)
                grant_key = lab.crypto.kem_key()
                if policy.history == "NONE":
                    with self.assertRaises(ValueError):
                        writer.grant(lab.crypto, lab.checkpoint, lab.roster, lab.signers["bob"],
                                     recipient, grant_key.public, 0, 3, 3)
                    continue
                start = 1 if policy.history == "WINDOW" else 0
                if start:
                    with self.assertRaises(ValueError):
                        writer.grant(lab.crypto, lab.checkpoint, lab.roster, lab.signers["bob"],
                                     recipient, grant_key.public, 0, 3, 3)
                grant = writer.grant(lab.crypto, lab.checkpoint, lab.roster, lab.signers["bob"],
                                     recipient, grant_key.public, start, 3, 3)
                # Prepared history may be unavailable; current participation
                # still requires only the entry, with no inviter action.
                selectors = {s.selector for s in writer.segments.values()}
                lab.service.withheld.update(selectors)
                lab.now = 7 * 86400
                lab.service.collect(lab.now)
                before = deepcopy(lab.meters)
                carol = lab.return_device("carol")
                for phase, meters in before.items():
                    for name, meter in meters.items():
                        if name != "carol":
                            self.assertEqual(lab.meters[phase][name], meter)
                frame = message_frame(lab.crypto, carol.ratchet, "carol", lab.signers["carol"],
                                      carol.metadata_key, b"back")
                lab.learn_sender("alice", "carol")
                alice = lab.sessions["alice"]
                self.assertEqual(receive_frame(lab.crypto, alice.ratchet, frame, alice.metadata_key,
                                               lab.public_credentials()), ("carol", b"back"))
                reader = ArchiveReader(lab.group, recipient, lab.checkpoint, grant_key.secret)
                reader.accept(lab.crypto, grant)
                self.assertEqual(reader.private_ticket, b"")
                with self.assertRaises(LookupError):
                    reader.read(lab.crypto, lab.governance, lab.log.signer.public,
                                lab.service, route, capability, start)
                lab.service.withheld.difference_update(selectors)
                for position in reversed(range(start, 3)):
                    self.assertEqual(reader.read(lab.crypto, lab.governance, lab.log.signer.public,
                                                 lab.service, route, capability, position), ("alice", b"old"))
                if start:
                    with self.assertRaises(ValueError):
                        reader.read(lab.crypto, lab.governance, lab.log.signer.public,
                                    lab.service, route, capability, 0)
                forged = deepcopy(reader)
                # Altering the stored blinding breaks membership authentication.
                forged.recipient = BlindedCredential(recipient.name, recipient.public, recipient.index,
                                                       recipient.shard, b"x" * 32)
                forged.consumed, forged.private_ticket = False, grant_key.secret
                with self.assertRaises(ValueError):
                    forged.accept(lab.crypto, grant)


if __name__ == "__main__":
    unittest.main()
