# Shared-entry delivery experiment

**Tree is now the selected delivery design in [Coppice v0.4](../../FIP-coppice-spec.md).**
This document preserves the measured comparison with compact direct and shard
delivery. `simulate.py` selects the tree; `compare_covers.py` runs all three.
The design keeps independent fresh era entries from the earlier resumption
experiment. Wrapping the historical v0.3 design's
chained transition entropy alone would not let a returning device skip eras.
No production crates, real PQ library integration, or hybrid suite are involved.

## Reproduce

```sh
python3 -B research/coppice/run.py
python3 -B research/coppice/compare_covers.py --output research/coppice/results/cover-128.json
python3 -B research/coppice/compare_covers.py --devices 1000 --changes 2 --output research/coppice/results/cover-1000.json
python3 -B research/coppice/compare_covers.py --devices 32 --changes 4 --shard-size 8 --producers 2 --output research/coppice/results/cover-rotating.json
```

Each report compares unchanged membership with fresh entries and actual,
spread-out removals. Defaults are 128 devices, seven transitions, seven days,
64-device shards, one eligible author, and eight tickets per subset. The
reserve covers genesis plus seven further uses of any subset. It is an event
budget, not a promise of arbitrarily many transitions within seven days.

## Shared state and recipient covers

`CapsuleBuilder` encrypts the common checkpoint, fresh era state, author
credential/proof, and author signature once with a random 32-byte capsule key.
The state commitment also binds a Merkle root over the selected
`(subset_id, ticket_id)` pairs. Each selected ticket wraps only the capsule key;
its context binds the group, checkpoint, subset, ticket, and common ciphertext.
The author must validate complete, nonoverlapping coverage before reserving any
tickets. Every admitted device receives exactly one path to the common state.

The three layouts use the same object format and cost accounting:

- **Direct:** one independent ticket per device.
- **Shard:** one shared ticket per unchanged shard, with singleton tickets for
  survivors of an affected shard or when a shared pool is exhausted.
- **Tree:** tickets for immutable complete subtrees, including singleton
  fallback. Select the largest available subsets containing only current
  members. A single exclusion in a fully provisioned balanced tree needs at
  most its depth in wrappers. Multiple exclusions and exhaustion fragment the
  cover; neither update size nor repair cost stays logarithmic indefinitely.

The layout draws on the complete-subtree method in
[Naor, Naor, and Lotspiech, §3.1](https://www.wisdom.weizmann.ac.il/~naor/PAPERS/2nl.pdf).
That paper's static receiver-key security does not prove this design's
single-use-key or CGKA composition. This is not TreeKEM or a new broadcast KEM.
All nodes and ticket uses have independently generated NTRU keys. There is no
ancestor key or master seed capable of regenerating descendants.

Each immutable cohort fixes credential identities, audiences, and a generation.
A pinned guardian certifies the audience and its publisher; the publisher must
belong to that audience. Removing someone makes every subset containing their
credential ineligible. Joining devices get a fresh cohort and fresh inventory,
not another member's old pool. Rebuilding a cohort is a separately metered
operation. Old unread capabilities are not silently erased to make the storage
results look better.

There is an author per transition, not a permanent coordinator. Pools remain
producer-assigned, so replacement authors need their own preprovisioned pools.
The rotating-author report measures two such authors and the added inventory.

## Provisioning and erasure

The harness measures the following setup work:

1. A subset member generates independent random ticket pairs, signs a Merkle
   manifest, and publishes encrypted public-ticket records. A separately signed
   readiness catalog is released after private-pool preparation and removal of
   extra private-key/box-key copies, making the pool eligible for use.
2. The assigned author obtains that catalog and manifest. Selected public keys
   are fetched when used; a publisher using its own keys reads them locally.
3. For a shared subset, its publisher uploads one encrypted box containing the
   complete private pool. Each other holder publishes a signed one-use NTRU
   enrollment key. The publisher fetches it and uploads a box-key wrapper.
4. Each holder fetches its wrapper and the shared box, verifies authorization,
   audience inclusion, manifest root, and every private/public key relation,
   then imports the complete pool and erases its enrollment private key, box
   key, and plaintext box. A publisher imports locally and erases extra copies.
   Singleton pools need no private-key upload to self.

`CoverLab` orchestrates these actions and owns the ideal crypto oracle. It is
not an endpoint. Endpoint inventories retain only individual unused secrets,
ticket metadata, and consumption/alias tombstones. Ciphertext boxes remain
available at the service; recovering one requires a wrapping key already erased
by a holder that imported it. All recipients, including the author and other
online devices, consume their selected entry ticket before using the new era.
The capsule builder retains ciphertext outboxes, not capsule keys or era roots.

Private-pool import checks a 16 MiB raw-private-key budget and 100,000 ticket
reference limit before mutation. The model assumes atomic persistence and
erasure; its durable-state tests exercise crash boundaries, not flash erasure.
The current provisioning adapter explicitly requires affected holders online.
It does not simulate replenishing an offline holder via additional prepublished
enrollment reserves. Missing inventory defers a transition and preserves
established lanes; it never reuses tickets or falls back to a static content key.

Compromise of unused tickets exposes unread entries. Tickets copied in an
earlier compromise remain compromised even if unused; consuming them does not
constitute PCS. Recovery needs newly secret inventory and independent identity
authorization where appropriate. These are explicit negative-control tests.

## Directory and return path

Per-device membership proofs must not become a hidden O(n) upload on every
change. This candidate therefore uses stable roster slots and random blinding
inside credential leaves. The author uploads only changed Merkle hash nodes;
the service assembles proofs from those hashes without seeing credentials.
Empty slots are committed tombstones. Here `Checkpoint.count` means allocated
slot capacity, the selected research interpretation that is not compatible with
the v0.3 dense roster format. Slot exhaustion requires an explicit resize;
automatic resizing is not implemented.

The cached-identity return path normally has four sequential requests:

1. Obtain a fresh challenge-bound finality response.
2. Batch opaque lookups for the device's known subsets. Exactly one wrapper
   must exist in the current cover.
3. Fetch the common encrypted capsule and stage its authenticated opening.
4. Fetch the device's membership proof, validate all bindings, and atomically
   install the session and erase the consumed ticket.

An unchanged-era return preserves the existing ratchet and needs only the
freshness request. More than 256 subset lookups produces an explicit pending
result; repeated cohort rebuilds cannot create an unbounded silent scan.
Missing wrappers, common objects, proofs, or retention dependencies leave
secret state untouched. Old/same-era capsules cannot reset a consumed ratchet.
No participant acts at the instant of return in the measured offline scenarios.
Current-message reception is measured separately: a signed encrypted sender
index and a fresh credential proof are fetched, and a busy sender can still
force backlog processing because of skipped-key limits.

The service sees routes, opaque selectors, traffic sizes/timing, and blinded
directory shape/positions. This is not PIR or a proof of traffic unlinkability.
Author certificates and signatures remain encrypted. Control metadata uses an
explicit fresh 32-byte salt to derive a distinct AEAD key per object; the salt
is counted in the wire format. The retained lookup secret unwraps metadata and
inner ciphertexts, never the common entry or a private ticket box. Former
cohort members retain access to this control metadata; metadata revocation from
former members is not demonstrated. The existing IP-hiding transport is an
input assumption, and no account-authenticated fallback exists.

## Measured results

The [128-device report](results/cover-128.json) uses seven spread-out removals
during a seven-day absence, eight tickets per subset, and one update author.
All MB below are decimal. The whole-run columns include setup, genesis, online
receipt, 32 application messages per transition, first send, and the separate
current-reception experiment; they are not control-only costs.
Application traffic includes sender uploads and the selected returning reader's
downloads, not every member reading every message. The JSON also provides a
separate `all_modeled_control_traffic_including_setup` total and peak.

| Layout | Author upload for seven changes | Busiest device upload, whole run | All devices' upload, whole run | Return control download |
|---|---:|---:|---:|---:|
| Compact direct | 1.615 MB | 2.378 MB | 5.218 MB | 8,064 B |
| Shard | 1.163 MB | 1.851 MB | 5.134 MB | 8,064 B |
| Tree | 0.277 MB | 1.163 MB | 11.847 MB | 7,936 B |

All three return paths use four round trips. Their busiest-device whole-run
downloads are respectively 2.090 MB, 1.691 MB, and 1.881 MB. The tree reduces
peak upload in this workload but uses more aggregate device upload and download.

| Layout | All devices' provisioning upload | Largest device provisioning download | Returning device's setup download | Returning device's private reserve before absence |
|---|---:|---:|---:|---:|
| Compact direct | 2.130 MB | 0.634 MB | 0 B | 8,638 B |
| Shard | 2.723 MB | 0.768 MB | 23,040 B | 18,510 B |
| Tree | 10.070 MB | 1.652 MB | 160,384 B | 77,742 B |

The direct recipient generates its own keys locally; its setup upload is
16,384 bytes. Zero setup download therefore does not mean free provisioning.
The tree's successive covers have 7, 10, 14, 17, 22, 25, and 29 wrappers.
Shard delivery eventually falls back across both affected shards. The unchanged
membership scenario separately measures 1,641,472, 59,136, and 46,592 bytes of
author upload: churn materially changes the comparison.

In [the 1,000-device, two-removal report](results/cover-1000.json), author upload
is 3.853 MB, 0.427 MB, and 65,536 bytes respectively. Tree provisioning alone
uploads 66.320 MB across devices and makes one producer download 11.746 MB of
catalogs and setup material. Its busiest-device whole-run upload is 3.321 MB,
versus 1.606 MB for shards. Eagerly provisioning every tree node is therefore
not a general bandwidth recommendation. Adaptive reserve depths, fewer unused
fallback pools, and more compact catalog authentication remain research work;
their savings are not included in these measurements.

[The rotating-author report](results/cover-rotating.json) uses 32 devices,
four removals, and two eligible authors. It accounts for both independent pools
and demonstrates rotation while the returning device stays offline. This is a
different workload, not a same-size apples-to-apples author-count benchmark.

## Accounting and limitations

The JSON reports contain total upload/download and the busiest device in each
phase: public/private pool provisioning, transition authors, online recipients,
return control, first send, and separate current reception. They also include
genesis, changed directory-node counts, per-transition wrapper counts, raw
private inventory, encoded ticket metadata, and cached producer catalogs.
Requests and responses use the model's 128-byte padding. Shared ciphertext
uploads occur once; every recipient download is charged to that recipient.
Counters are device traffic, not service egress or projected group storage.

Cold identity enrollment/cohort topology, membership authorization exchange,
guardian rotation, external transport, real crypto CPU, Python heap overhead,
actual storage erasure, and formal adaptive-compromise analysis are excluded.
The ideal finality service remains a trust assumption. The tested fixed
capacity/directory format and enrollment flow are candidate constructions,
not final interoperability formats. No full initial signing-key directory is
claimed to be included in the traffic totals.

The exhaustion experiments demonstrate cover fragmentation before blocking:
with one ticket per node, an eight-member tree uses covers of 1, 2, 4, then 8
wrappers before exhausting all paths. Replenishment is explicitly metered.
Repair experiments publish fresh cohorts after repeated removals, measure the
improved cover and its setup cost, and retain old unread tickets. These costs
remain part of the selected tree design's device budget.
