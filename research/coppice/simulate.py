"""Selected tree experiments, with an explicit legacy direct-entry comparison.

python3 -B research/coppice/simulate.py --output research/coppice/results/tree-128.json
"""
import argparse
import json
from dataclasses import replace
from pathlib import Path

from fixtures import Lab
from membership import Policy, Publication, ForkMonitor
from envelopes import message_frame, receive_frame
from history import ArchiveWriter, ArchiveReader
from service import Meter, Record
from core import SecretFrontier, digest, DeferredUpdate
from costs import estimate, Workload


def offline_experiment(devices=128, changes=7, days=7, messages=32):
    if devices < 2 or changes < 1 or days < 1 or messages < 10:
        raise ValueError("experiment needs >=2 devices, >=1 transition, >=1 day, >=10 messages")
    names = tuple(f"device-{i}" for i in range(devices))
    lab = Lab(names, seed=b"offline experiment")
    lab.epoch()
    target, sender = names[-1], names[0]
    before_provision = lab.inventory_upload.upload
    lab.provision(target, changes, sender)
    offline_ticket_upload = lab.inventory_upload.upload - before_provision
    offline_ticket_storage = sum(len(secret) for secret in lab.inboxes[target].secrets.values())
    first_entry_upload = lab.entry_upload.upload
    first_inventory_download = lab.inventory_fetch.download
    application_upload = Meter()
    for epoch_index in range(changes):
        lab.now = days * 86400 * (epoch_index + 1) // changes
        lab.service.collect(lab.now)
        lab.epoch(online=names[:-1])
        session = lab.sessions[sender]
        last_selectors = []
        for i in range(messages):
            payload = f"day-{days * (epoch_index + 1) / changes:.3f}: message-{i}".encode()
            frame = message_frame(lab.crypto, session.ratchet, sender, lab.signers[sender], session.metadata_key, payload)
            selector = digest(b"application record", frame)
            lab.service.put(lab.route, session.delivery_capability,
                            Record(selector, frame, expires=lab.now + 30 * 86400), application_upload)
            last_selectors.append(selector)
    # All other participant activity stops here. Only delivery and finality
    # services answer the returning device; the log is an explicit assumption.
    control = Meter()
    returned = lab.return_device(target, control)
    first_send = Meter()
    frame = message_frame(lab.crypto, returned.ratchet, target, lab.signers[target], returned.metadata_key, b"I'm back")
    lab.service.put(lab.route, returned.delivery_capability,
                    Record(digest(b"return message", frame), frame), first_send)
    lab.learn_sender(sender, target)
    receiving = lab.sessions[sender]
    receive_frame(lab.crypto, receiving.ratchet, frame, receiving.metadata_key, lab.credentials())

    # Separately measure reception of a busy sender. Discovery/credential
    # selectors are fixture inputs here; this is not a complete directory API.
    lab.learn_sender(target, sender)
    reception = Meter()
    latest = lab.service.get(lab.route, returned.delivery_capability, last_selectors[-1], reception)
    try:
        receive_frame(lab.crypto, returned.ratchet, latest.ciphertext, returned.metadata_key, lab.credentials())
        needed_replay = False
    except (DeferredUpdate, ValueError):
        needed_replay = True
    if needed_replay:
        for selector in last_selectors:
            record = lab.service.get(lab.route, returned.delivery_capability, selector, reception)
            receive_frame(lab.crypto, returned.ratchet, record.ciphertext, returned.metadata_key, lab.credentials())
    return {
        "construction": "EXPERIMENTAL O(n) presealed direct entries, not the baseline shard transition",
        "devices": devices, "days_offline": days, "virtual_return_time_seconds": lab.now,
        "missed_membership_transitions": changes,
        "first_current_send_succeeded": True,
        "other_participant_actions_needed_at_return": 0,
        "resume_control": control.report(), "first_message_submission": first_send.report(),
        "under_64000_byte_control_target": control.download <= 64_000,
        "returning_device_preabsence_entry_ticket_upload": offline_ticket_upload,
        "returning_device_preabsence_private_ticket_bytes": offline_ticket_storage,
        "entry_preparer_upload_during_absence": lab.entry_upload.upload - first_entry_upload,
        "entry_preparer_ticket_download_during_absence": lab.inventory_fetch.download - first_inventory_download,
        "aggregate_ticket_publication_upload_including_setup": lab.inventory_upload.upload,
        "application_sender_upload_during_absence": application_upload.upload,
        "busy_sender_receive_needed_backlog": needed_replay,
        "separate_busy_sender_reception": reception.report(),
        "unread_intermediate_entry_tickets_remaining": len(lab.inboxes[target].secrets),
        "server_ciphertext_and_selector_bytes": lab.service.storage_bytes,
        "limits": ["fresh trusted-finality service available; fixed independent guardian policy",
                   "entry tickets actually provisioned before absence",
                   "secret entries prepared for every member before using the era",
                   "metadata discovery and cold credential retrieval not included",
                   "actual PQ cryptographic CPU, physical erasure, and external transport not modeled"],
    }


def history_experiment(messages=32):
    lab = Lab(("alice", "bob"), seed=b"history experiment")
    policy = Policy(history="ALL_RETAINED")
    lab.epoch(policy=policy)
    writer = ArchiveWriter(lab.group)
    route, capability = lab.crypto.fresh(), lab.crypto.fresh()
    lab.service.register(route, capability)
    archive_upload = Meter()
    for i in range(messages):
        writer.append(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"], i,
                      b"a" * 100, lab.service, route, capability, archive_upload)
    lab.add_identity("carol")
    lab.epoch(policy=policy, history_boundary=messages)
    key = lab.crypto.kem_key()
    recipient = lab.roster.by_name["carol"]
    grant = writer.grant(lab.crypto, lab.checkpoint, lab.roster, lab.signers["bob"],
                         recipient, key.public, 0, messages, messages)
    grant_meter, history_meter = Meter(), Meter()
    selector = digest(b"encrypted grant", grant)
    lab.service.put(route, capability, Record(selector, grant), grant_meter)
    reader = ArchiveReader(lab.group, recipient, lab.checkpoint, key.secret)
    reader.accept(lab.crypto, lab.service.get(route, capability, selector, history_meter).ciphertext)
    for i in range(messages):
        reader.read(lab.crypto, lab.governance, lab.log.signer.public,
                    lab.service, route, capability, i, history_meter)
    return {"messages": messages, "plaintext_bytes_per_message": 100,
            "archive_writer": archive_upload.report(), "grant_preparer": grant_meter.report(),
            "new_member_grant_and_history": history_meter.report(),
            "format": "one-message segments with repeated authentication proofs; deliberately unoptimized",
            "live_resume_dependency": False,
            "limits": ["recipient grant KEM ticket enrollment is a precondition, not included in these counters",
                       "archive-capability compromise exposes retained history"]}


def frontier_experiment(leaves=10_000, events=4320):
    one = SecretFrontier(b"f" * 32, b"era", leaves)
    one.open(0)
    fragmented = SecretFrontier(b"f" * 32, b"era", leaves)
    for index in range(0, leaves, 2):
        fragmented.open(index)
    return {"lanes": leaves, "retained_events": events,
            "one_lane_consumed_raw_secret_bytes_per_event": 32 * len(one.nodes),
            "alternating_lanes_consumed_raw_secret_bytes_per_event": 32 * len(fragmented.nodes),
            "projected_fragmented_total_secret_bytes": 32 * len(fragmented.nodes) * events,
            "exceeds_initial_16MiB_budget": 32 * len(fragmented.nodes) * events > 16 * 1024**2,
            "excludes": "Python objects, indices, tombstones, metadata siblings and other endpoint state"}


def fork_experiment():
    lab = Lab(("alice", "bob"), seed=b"fork experiment")
    checkpoint = lab.epoch()
    signer = lab.signers["alice"]
    views = [ForkMonitor(lab.group, checkpoint.identifier, [signer.public]) for _ in range(2)]
    for index, view in enumerate(views):
        publication = Publication(lab.group, checkpoint.identifier, signer.public, 1, b"", bytes([index]))
        view.observe(lab.crypto, replace(publication, signature=lab.crypto.sign(signer, publication.body())))
    before = [len(v.evidence) for v in views]
    views[0].merge(lab.crypto, tuple(views[1].seen.values()))
    return {"evidence_during_partition": before, "evidence_after_view_exchange": len(views[0].evidence),
            "bounded_detection_during_permanent_partition": False}


def legacy_report(devices=128, changes=7, days=7):
    return {"model_version": "coppice-research-1", "cryptography": "ideal functionality, no hybrid",
            "baseline_analytical_subtotals": estimate(Workload()),
            "offline_entry_experiment": offline_experiment(devices, changes, days),
            "history_experiment": history_experiment(),
            "frontier_experiment": frontier_experiment(), "split_view_experiment": fork_experiment()}


def report(devices=128, changes=7, days=7, profile="tree", depth=None, producers=1):
    if profile == "tree":
        from tree_profile import report as tree_report
        return tree_report(devices, changes, days, depth, producers)
    if profile != "legacy-direct":
        raise ValueError("unknown research delivery profile")
    if depth is not None or producers != 1:
        raise ValueError("legacy-direct has no configurable tree depth or producer pool")
    return legacy_report(devices, changes, days)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--devices", type=int, default=128)
    parser.add_argument("--changes", type=int, default=7)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--profile", choices=("tree", "legacy-direct"), default="tree")
    parser.add_argument("--depth", type=int, help="tickets per subset per producer, including genesis")
    parser.add_argument("--producers", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = report(args.devices, args.changes, args.days, args.profile, args.depth, args.producers)
    except ValueError as error:
        parser.error(str(error))
    except LookupError as error:
        parser.error(f"workload pending: {error}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        offline = result["offline_tree_experiment"] if args.profile == "tree" else result["offline_entry_experiment"]
        print(f"Wrote {args.output}")
        print(f"Resume control: {offline['resume_control']['download_bytes']} downloaded bytes, "
              f"{offline['resume_control']['round_trips']} round trips")
        if args.profile == "tree":
            print(f"Tree transition author upload: {offline['transition_authors_during_absence']['upload_bytes']} bytes")
            print(f"Busiest-device control upload including setup: "
                  f"{offline['all_modeled_control_traffic_including_setup']['peak_device_upload_bytes']} bytes")
        else:
            print(f"Entry preparer upload: {offline['entry_preparer_upload_during_absence']} bytes")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
