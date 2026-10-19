"""Measured shared-entry comparisons; stdlib, ideal crypto, no production code.

python3 -B research/coppice/compare_covers.py --output research/coppice/results/cover-128.json
"""
import argparse
import json
from pathlib import Path

from core import DeferredUpdate, digest
from cover import identity, seal_metadata, open_metadata
from cover_lab import CoverLab
from envelopes import message_frame, receive_frame
from resumption import authorize_sender
from service import Meter, Record
from wire import pack


def snapshot(lab, phases):
    values = {}
    for phase in phases:
        for name, meter in lab.meters[phase].items():
            values[phase, name] = (meter.upload, meter.download)
    return values


def since(lab, phases, before):
    values = {}
    for phase in phases:
        for name, meter in lab.meters[phase].items():
            old = before.get((phase, name), (0, 0))
            up, down = values.get(name, (0, 0))
            values[name] = (up + meter.upload - old[0], down + meter.download - old[1])
    return {"upload_bytes": sum(v[0] for v in values.values()),
            "download_bytes": sum(v[1] for v in values.values()),
            "peak_device_upload_bytes": max((v[0] for v in values.values()), default=0),
            "peak_device_download_bytes": max((v[1] for v in values.values()), default=0)}


def removal_order(names, changes, protected):
    candidates = [n for n in names if n not in protected]
    # Spread exclusions across the immutable tree; do not cherry-pick one shard.
    return tuple(candidates[(i * len(candidates)) // changes] for i in range(changes))


def cover_experiment(mode, devices=128, changes=7, days=7, depth=None,
                     shard_size=64, producers=1, churn=True, messages=32):
    if (devices < 3 or changes < 1 or not 1 <= producers < devices - 1 or
            days < 1 or messages < 10 or churn and changes > devices - producers - 1):
        raise ValueError("invalid cover workload")
    names = tuple(f"device-{i}" for i in range(devices))
    lab = CoverLab(names, mode, shard_size)
    authors, target, sender = names[:producers], names[-1], names[0]
    depth = changes + 1 if depth is None else depth
    lab.provision(depth, producers=authors)
    preload = lab.storage(target)
    preload_peak = max(lab.storage(n)["raw_private_ticket_bytes"] for n in names)
    lab.epoch()
    after_genesis = snapshot(lab, ("transition", "online receive"))
    target_before = lab.storage(target)
    order = removal_order(names, changes, set(authors) | {target}) if churn else ()
    current, counts, directory_nodes = list(names), [], []
    first_hash_count = len(lab.known_hashes)
    for i in range(changes):
        lab.now = days * 86400 * (i + 1) // changes
        lab.service.collect(lab.now)
        if churn:
            current.remove(order[i])
        known = len(lab.known_hashes)
        lab.epoch(current, online=[n for n in current if n != target], author=authors[i % producers])
        counts.append(len(lab.last_builder.selected))
        directory_nodes.append(len(lab.known_hashes) - known)
        session = lab.sessions[sender]
        selectors = []
        for position in range(messages):
            frame = message_frame(lab.crypto, session.ratchet, sender, lab.signers[sender],
                                  session.metadata_key, b"m" * 100)
            selector = digest(b"cover experiment message", frame)
            lab.service.put(lab.route, session.delivery_capability,
                            Record(selector, frame, expires=lab.now + 30*86400), lab.meter("application", sender))
            selectors.append(selector)
        # A simple signed encrypted sender index; its actual bytes are counted.
        # Sender identity is cached (cold lookup remains an explicit omission).
        index_body = pack((lab.checkpoint.identifier, tuple(selectors)))
        index = seal_metadata(lab.crypto, session.directory_key,
                              (index_body, lab.crypto.sign(lab.signers[sender], index_body)),
                              pack((lab.group, identity(lab.credentials[sender]), "sender index")))
        index_selector = digest(b"sender index", session.directory_key, identity(lab.credentials[sender]))
        lab.service.put(lab.route, session.delivery_capability,
                        Record(index_selector, index, tuple(selectors), lab.now + 30*86400),
                        lab.meter("application index", sender))

    transition = since(lab, ("transition",), after_genesis)
    online = since(lab, ("online receive",), after_genesis)
    # From this boundary until the first send only target + services act.
    returned = lab.return_device(target)
    frame = message_frame(lab.crypto, returned.ratchet, target, lab.signers[target],
                          returned.metadata_key, b"I'm back")
    lab.service.put(lab.route, returned.delivery_capability,
                    Record(digest(b"first returned send", frame), frame), lab.meter("first send", target))
    # A verifier checks the first-send result AFTER it has been submitted.
    lab.learn_sender(sender, target)
    receiving = lab.sessions[sender]
    assert receive_frame(lab.crypto, receiving.ratchet, frame, receiving.metadata_key,
                         lab.public_credentials()) == (target, b"I'm back")

    reception = lab.meter("current reception", target)
    proof = lab.service.merkle_proof(lab.store_route, lab.store_cap, lab.checkpoint.roster_root,
                                     lab.credentials[sender].index, lab.capacity, reception)
    authorize_sender(returned, lab.credentials[sender], proof)
    index = lab.service.get(lab.route, returned.delivery_capability, index_selector, reception).ciphertext
    body, signature = open_metadata(lab.crypto, returned.directory_key, index,
                                     pack((lab.group, identity(lab.credentials[sender]), "sender index")))
    from wire import unpack
    index_era, fetched_selectors = unpack(body)
    if index_era != returned.checkpoint.identifier or not lab.crypto.verify(lab.signers[sender].public, body, signature):
        raise ValueError("invalid sender index")
    latest = lab.service.get(lab.route, returned.delivery_capability, fetched_selectors[-1], reception)
    try:
        receive_frame(lab.crypto, returned.ratchet, latest.ciphertext, returned.metadata_key, lab.public_credentials())
        needed_backlog = False
    except (DeferredUpdate, ValueError):
        needed_backlog = True
    if needed_backlog:
        for selector in fetched_selectors:
            record = lab.service.get(lab.route, returned.delivery_capability, selector, reception)
            receive_frame(lab.crypto, returned.ratchet, record.ciphertext, returned.metadata_key, lab.public_credentials())
    return {
        "mode": mode, "devices_initial": devices, "devices_final": len(current),
        "scenario": "spread removals" if churn else "unchanged membership, fresh entries",
        "days_offline": days, "membership_transitions": changes,
        "eligible_producers": producers, "tickets_per_subset_per_producer": depth,
        "shard_size": shard_size, "directory_slot_capacity": lab.capacity,
        "wraps_per_transition": counts,
        "genesis_directory_hash_nodes": first_hash_count,
        "new_directory_hash_nodes_per_transition": directory_nodes,
        "provisioning_all_devices": lab.traffic(("provision",)),
        "transition_authors_during_absence": transition,
        "online_receivers_during_absence": online,
        "all_modeled_device_traffic_including_setup": lab.traffic(),
        "all_modeled_control_traffic_including_setup": lab.traffic(
            ("provision", "transition", "online receive", "return")),
        "returning_device_provisioning": lab.meter("provision", target).report(),
        "returning_device_storage_after_provisioning": preload,
        "returning_device_storage_before_absence": target_before,
        "returning_device_storage_after_return": lab.storage(target),
        "maximum_raw_private_inventory_after_provisioning": preload_peak,
        "resume_control": lab.meter("return", target).report(),
        "first_message_submission": lab.meter("first send", target).report(),
        "first_current_send_succeeded": True, "participant_actions_required_at_return": 0,
        "separate_current_reception": reception.report(), "busy_sender_needed_backlog": needed_backlog,
        "counts": "serialized research requests/responses with 128-byte request/response padding",
    }


def exhaustion_experiment(mode):
    lab = CoverLab(tuple(f"device-{i}" for i in range(8)), mode, shard_size=4)
    lab.provision(1)
    lab.epoch()
    target, author = lab.names[-1], lab.names[0]
    counts = [len(lab.last_builder.selected)]
    while True:
        before = lab.log.head
        try:
            lab.epoch(online=lab.names[:-1])
            counts.append(len(lab.last_builder.selected))
        except LookupError:
            assert lab.log.head == before
            break
        if len(counts) > 16:
            raise AssertionError("exhaustion did not occur")
    existing = lab.sessions[author].ratchet.send(author)
    pending = False
    try:
        lab.provision(1, online=lab.names[:-1], phase="replenishment")
    except LookupError:
        pending = True
    lab.return_device(target)
    lab.provision(1, phase="replenishment")
    lab.epoch()
    return {"wraps_until_exhaustion_including_genesis": counts,
            "no_finality_advance_on_exhaustion": True,
            "existing_lane_continued": existing.counter == 0,
            "offline_holder_not_silently_replenished": pending,
            "explicit_online_replenishment_traffic": lab.traffic(("replenishment",)),
            "transition_succeeded_after_replenishment": True}


def repair_experiment(mode):
    names = tuple(f"device-{i}" for i in range(16))
    lab = CoverLab(names, mode, shard_size=4)
    lab.provision(5)
    lab.epoch()
    current = list(names)
    for removed in ("device-3", "device-7", "device-11"):
        current.remove(removed)
        lab.epoch(current)
    before = len(lab.last_builder.selected)
    before_storage = sum(lab.storage(n)["raw_private_ticket_bytes"] for n in current)
    rebuilt = lab.add_cohort(current)
    lab.provision(2, online=current, subsets=rebuilt, phase="cohort rebuild")
    lab.epoch(current)
    return {"devices_remaining": len(current), "wraps_before_rebuild": before,
            "wraps_after_rebuild": len(lab.last_builder.selected),
            "explicit_rebuild_traffic": lab.traffic(("cohort rebuild",)),
            "aggregate_raw_private_bytes_before_rebuild": before_storage,
            "aggregate_raw_private_bytes_after_rebuild": sum(lab.storage(n)["raw_private_ticket_bytes"] for n in current),
            "old_unused_tickets_retained": True,
            "requires_explicit_online_provisioning": True}


def report(devices=128, changes=7, days=7, depth=None, shard_size=64, producers=1):
    return {
        "model_version": "coppice-cover-research-1",
        "cryptography": "ideal NTRU/Falcon/SHAKE/AEAD functionality; no hybrid",
        "comparisons": [cover_experiment(mode, devices, changes, days, depth, shard_size, producers, churn)
                        for churn in (False, True) for mode in ("direct", "shard", "tree")],
        "exhaustion": {mode: exhaustion_experiment(mode) for mode in ("direct", "shard", "tree")},
        "repair": {mode: repair_experiment(mode) for mode in ("direct", "shard", "tree")},
        "limits": [
            "experimental independent era entries, not the baseline prior-era key schedule",
            "trusted fresh finality, independent pinned guardian policy, ideal atomic erasure",
            "cached initial identities/cohort topology; cold enrollment and membership authorization exchange excluded",
            "all published pool keys, private boxes, wraps, catalogs, hashes, return lookups and proofs are counted",
            "provisioning is explicitly online for all affected holders; no offline pool replenishment adapter",
            "retained lookup secret hides control fields from DS but does not hide them from former cohort members",
            "service observes traffic, routes, sizes, directory shape and requested positions; not PIR",
            "server cannot decrypt common entries/private pools or see explicit author credentials",
            "unused tickets expose unread entries on compromise; precompromised inventory does not provide PCS",
            "no general constant cover size under churn, fixed time-only offline guarantee, or bounded current reception",
            "storage reports raw ticket secrets, encoded ticket metadata and producer catalogs, not Python heap/disk size",
            "application traffic counts sender uploads and the selected returning reader, not every member's message downloads",
            "production crypto CPU, transport overhead, hardware erasure, guardian rotation and formal proof excluded",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--devices", type=int, default=128)
    parser.add_argument("--changes", type=int, default=7)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--depth", type=int)
    parser.add_argument("--shard-size", type=int, default=64)
    parser.add_argument("--producers", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = report(args.devices, args.changes, args.days, args.depth, args.shard_size, args.producers)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"Wrote {args.output}")
        for row in result["comparisons"]:
            print(f"{row['mode']:6} {row['scenario']}: author upload "
                  f"{row['transition_authors_during_absence']['upload_bytes']:,} B; "
                  f"provisioning upload {row['provisioning_all_devices']['upload_bytes']:,} B; "
                  f"return {row['resume_control']['download_bytes']:,} B")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
