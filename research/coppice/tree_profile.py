"""Selected tree-delivery research profile; ideal crypto and measured device costs."""
from compare_covers import cover_experiment, exhaustion_experiment, repair_experiment
from core import digest
from cover_lab import CoverLab
from history import ArchiveWriter, ArchiveReader
from membership import Policy
from service import Meter, Record


def history_experiment(messages=8):
    """A new tree member resumes and reads a prepared grant with no live inviter."""
    if not 1 <= messages <= 2048:
        raise ValueError("history experiment must fit one bounded grant")
    lab = CoverLab(("alice", "bob"), seed=b"tree history profile")
    policy = Policy(history="ALL_RETAINED")
    lab.provision(2)
    lab.epoch(policy=policy)
    writer = ArchiveWriter(lab.group)
    route, capability = lab.crypto.fresh(), lab.crypto.fresh()
    lab.service.register(route, capability)
    archive_meter, grant_meter, read_meter = Meter(), Meter(), Meter()
    for position in range(messages):
        writer.append(lab.crypto, lab.checkpoint, lab.roster, lab.signers["alice"], position,
                      b"a" * 100, lab.service, route, capability, archive_meter)
    lab.add_identity("carol")
    cohort = lab.add_cohort(("carol",))
    lab.provision(1, online=("alice", "bob", "carol"), subsets=cohort)
    lab.epoch(("alice", "bob", "carol"), online=("alice", "bob"),
              policy=policy, history_boundary=messages)
    key = lab.crypto.kem_key()  # Grant-ticket enrollment remains a precondition.
    recipient = lab.credentials["carol"]
    grant = writer.grant(lab.crypto, lab.checkpoint, lab.roster, lab.signers["bob"],
                         recipient, key.public, 0, messages, messages)
    selector = digest(b"tree encrypted grant", grant)
    lab.service.put(route, capability, Record(selector, grant), grant_meter)
    # Only Carol and the services act beyond this boundary.
    lab.now = 7 * 86400
    lab.service.collect(lab.now)
    lab.return_device("carol")
    reader = ArchiveReader(lab.group, recipient, lab.checkpoint, key.secret)
    reader.accept(lab.crypto, lab.service.get(route, capability, selector, read_meter).ciphertext)
    for position in reversed(range(messages)):
        assert reader.read(lab.crypto, lab.governance, lab.log.signer.public, lab.service,
                           route, capability, position, read_meter) == ("alice", b"a" * 100)
    return {
        "profile": "tree", "policy": "ALL_RETAINED", "messages": messages,
        "archive_writer": archive_meter.report(), "grant_preparer": grant_meter.report(),
        "new_member_grant_and_history": read_meter.report(),
        "live_entry_control": lab.meter("return", "carol").report(),
        "original_authorship_verified": True, "participant_actions_required_at_return": 0,
        "live_resume_dependency": False,
        "limits": ["one-message archive segments and repeated proofs; unoptimized",
                   "live cohort setup and grant-ticket enrollment excluded from archive counters",
                   "archive capabilities deliberately expose the retained content on compromise"],
    }


def report(devices=128, changes=7, days=7, depth=None, producers=1):
    # Retention is currently a fixed property of CoverLab, not an unbounded
    # promise inferred from how many tickets are in the pool.
    if not 1 <= days < 30:
        raise ValueError("tree workload must fit the 30-day object-retention horizon")
    return {
        "model_version": "coppice-tree-research-1",
        "selected_delivery_profile": "tree",
        "cryptography": "ideal NTRU-HPS-2048-677/Falcon-512/SHAKE256/AEAD; no hybrid",
        "offline_tree_experiment": cover_experiment(
            "tree", devices, changes, days, depth, producers=producers, churn=True),
        "stable_membership_experiment": cover_experiment(
            "tree", devices, changes, days, depth, producers=producers, churn=False),
        "exhaustion": exhaustion_experiment("tree"),
        "repair": repair_experiment("tree"),
        "history_experiment": history_experiment(),
        "limits": [
            "research state machine, not a production wire format or cryptographic proof",
            "uses existing v3 research hash labels; not a Coppice/4 interoperability vector",
            "fresh independent era entries; no previous-era replay needed for current sending",
            "trusted consistent finality, pinned guardian authorization and atomic erasure are assumptions",
            "cached initial identities/topology; cold enrollment and authority exchange are excluded",
            "all tree pools eagerly provisioned before absence; affected holders must be online for setup",
            "finite per-producer reserves; days alone do not guarantee return or new-epoch progress",
            "setup, private boxes, public catalogs, proofs, wrappers and busiest-device costs are counted",
            "no participant forwarding; service stores ciphertext and cannot decrypt entries or messages",
            "traffic, directory positions and group routes remain observable; no unlinkability proof",
            "former cohort members retain lookup metadata access, never fresh excluded entry keys",
            "unused/copied tickets expose unread entries; fresh secure inventory is necessary for PCS",
            "current-message reception can require backlog despite bounded first-send control",
            "same-era sender contributions remain separate research layers, not measured tree refresh traffic",
            "application totals include sender uploads and one returning reader, not all members' reads",
            "raw/encoded inventory is measured, not total device heap, disk or full directory storage",
            "PQ crypto CPU, physical erasure, external transport and guardian rotation are excluded",
        ],
    }
