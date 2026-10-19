# Coppice research prototype

This directory contains executable protocol experiments for `FIP-coppice-spec.md`.
Work here is limited to research and specification development. There is no
production Coppice implementation, no crate integration, and no hybrid suite.
Python's standard library is sufficient.

**Tree delivery is the selected research path in the v0.4 spec.** The service
stores one encrypted era entry and wrappers for a disjoint cover of receiving
nodes. Devices fetch directly; the tree does not require member forwarding.

## Run

From the repository root:

```sh
python3 -B research/coppice/run.py
python3 -B research/coppice/run.py --verbose
python3 -B research/coppice/vectors.py --check
python3 -B research/coppice/simulate.py --output research/coppice/results/tree-128.json
python3 -B research/coppice/simulate.py --devices 1000 --changes 2 --output research/coppice/results/tree-1000.json
python3 -B research/coppice/compare_covers.py --output research/coppice/results/cover-128.json
```

The simulation selects `tree` by default and accepts `--devices`, `--changes`,
`--days`, `--depth` (tickets per node per producer, including genesis), and
`--producers`. Defaults are 128 devices, seven spread removals, seven days
offline, eight tickets per node, and one eligible author. It also runs an
unchanged-membership comparison, exhaustion, repair and history. It uses virtual
time, deterministic fixture entropy, and no network connections or sleeps.
The old `python3 -B research/coppice/test_protocol_model.py` command still runs
the original 30 regressions. `run.py` runs the complete expanded suite.

`results/tree-128.json` and `results/tree-1000.json` are the selected reports.
Setup, the busiest device's traffic, return costs and current reception are
separate fields. The modeled absence must fit the fixed 30-day retention
horizon; enough inventory is also required. No day count implies unlimited
transition capacity.

Reproduce the historical full-per-device entry reports explicitly:

```sh
python3 -B research/coppice/simulate.py --profile legacy-direct --output research/coppice/results/example.json
python3 -B research/coppice/simulate.py --profile legacy-direct --devices 1000 --changes 2 --output research/coppice/results/scale-1000.json
```

Those reports include the older analytical shard subtotals, archive costs,
frontier storage and split-view negative control. Re-run the relevant command
after changing its modeled encoding. Use `vectors.py` without `--check` only
when intentionally updating the research vectors.

## Model boundaries

There are three distinct levels:

1. **Ratchet and deletion rules:** SHAKE-derived symmetric state, one-use
   capabilities, per-lane entropy puncturing, authenticated dependency ordering,
   membership boundaries, skipped-key limits, and transactional state changes.
2. **Ideal cryptography:** `IdealCrypto` substitutes opaque, integrity-protected
   byte strings for NTRU encapsulations, Falcon signatures and AEAD ciphertexts.
   Keys/signatures/encapsulations have the suite's modeled byte lengths. The
   oracle's private tables are test fixtures and are never in an endpoint
   snapshot or service object. This is not a cryptographic implementation.
3. **Selected and comparison constructions:** shared tree entries are selected;
   direct/shard entries remain comparisons. Archive grants, fixed-guardian
   authorization and encrypted control framing make assumptions executable.
   Selection does not establish a proved composition or final wire format.

`Lab` and `CoverLab` are test harnesses, not devices. They own the oracle, fixture identities,
and ideal finality service. Compromise experiments copy selected endpoint state,
not either harness or the oracle. Core `Message.key`, `Contribution.delta`, `DeliverySlot`
and `TicketBox` plaintexts are test oracles. They must not cross the service
boundary; the envelope layer serializes opaque ciphertexts instead.

Python object deletion does not establish memory or disk erasure. The durable
store models atomic transactions and a separately retained rollback witness.
It does not implement secure storage, filesystem recovery, hardware monotonic
counters, or protection if the witness is rolled back with the backup.

The fixed guardian policy authorizes membership independently of device signing
keys. An ideal consistent log supplies ordering and fresh challenge-bound head
responses. This is an explicit trusted-finality deployment model, not a BFT
protocol. Guardian-set changes and an untrusted-log consistency construction
are not implemented. Source-IP hiding is assumed from the existing transport.

## Components

| Module | Purpose |
|---|---|
| `core.py` | Sender ratchets, contribution frontiers, single-use tickets, ticket boxes, skipped-key expiry, byte quotas |
| `wire.py` | Bounded tagged research encoding and context/index/count-bound Merkle proofs |
| `ideal.py` | Ideal crypto capabilities and deterministic fixture generation |
| `delivery.py` | Earlier shard/direct contribution layer, manifests, partial fetches, reservations and consumption |
| `membership.py` | Authenticated policies/rosters, independent guardian authorization, ideal finality, fork evidence |
| `envelopes.py` | Encrypted authors/signatures, ciphertext-dependent headers, control envelopes and content padding |
| `service.py` | Opaque storage, shared delivery capabilities, request traces, device meters, dependency-preserving collection |
| `replay.py` | Bounded dependency queue with explicit deferral and gaps; completed payloads are discarded |
| `resumption.py` | Experimental presealed per-era entry packages and latest-era return |
| `cover.py` | Shared entry capsules, authenticated one-use subset pools, stable blinded roster slots and bounded return discovery |
| `cover_lab.py` | Metered private/public pool provisioning, exact recipient covers and rotating authors |
| `tree_profile.py` | Selected tree workloads, setup/peak-device accounting, exhaustion, repair and blinded-roster history |
| `compare_covers.py` | Direct/shard/tree comparisons, repeated removals, exhaustion and cohort-rebuild costs |
| `history.py` | Independent archive keys, policy-bound range grants and verifiable authorship |
| `durability.py` | Atomic commit/crash/outbox/rollback oracle |
| `costs.py` | Historical shard byte formulas with explicit omissions |
| `simulate.py` | Tree by default; explicit legacy-direct comparison |
| `vectors.py`, `vectors.json` | Research encoding, Merkle, frontier and header-derivation vectors |

The tagged encoding is deliberately labeled a **candidate research format**.
It is not the final binary schema described abstractly in the spec. Its framing
costs are counted as emitted; they must not be mixed with historical estimates
as if both were measurements of one interoperable implementation.
It retains the v3 research hash labels, an inert credential shard field and an
unused independent `era_next` sibling. These are counted compatibility fields,
not the selected v4 key schedule or interoperability vectors. The same-era
contribution/lane tests remain separate layers; the tree contribution adapter
is not yet integrated or included in the selected report's refresh costs.

## Selected tree path

The [current spec](../../FIP-coppice-spec.md) puts node-key preparation, exact
recipient covers, forward-secret consumption and latest-entry return in the
main protocol. [Implementation and comparison details](COVER-EXPERIMENT.md)
describe the encrypted private-pool adapter, public catalogs, proof directory,
producer rotation, retention and failure boundaries.

In the default seven-removal run, the update author uploads **277,376 bytes**.
The returning device's setup costs **32,512 bytes uploaded and 160,384 bytes
downloaded**; its raw private reserve before absence is **77,742 bytes**.
Current-entry return costs **1,024 bytes uploaded and 7,936 downloaded in four
round trips**, with no other member acting. The busiest device's control upload
including setup/genesis is **853,376 bytes**. Current reception is measured
separately and can require backlog processing.

These savings depend on preinstalled independent one-use keys. Setup is
explicitly online for affected holders; an exhausted pool cannot be silently
refilled while they are absent. Tree setup is expensive, particularly eager
catalog downloads at 1,000 devices. The reports preserve that cost instead of
calling the small transition upload the complete device budget.

All three history policies compose with the tree's blinded credentials. Tests
cover authorized new-member grants, window enforcement, original authorship,
no old live-ticket access, and current sending while archive objects are
unavailable. Archive grant-ticket enrollment remains a separate precondition.

## Resumption experiment

This historical comparison explores a direct entry profile with these rules.
It runs only with `--profile legacy-direct` in the simulation CLI:

1. While online, each recipient publishes independent entry tickets assigned to
   eligible preparers. Ticket publication, preparer downloads and private-key
   storage are counted. The harness never replenishes an offline recipient.
2. A retained member prepares one independently encrypted entry for **every**
   member at an authorized membership boundary. Entries contain the new era's
   sibling state, the recipient's credential proof and private delivery state.
   This direct distribution experiment uses fresh era state; it does not model
   the v0.3 design's previous-era chaining plus shard transition contribution.
3. All entries are prepared before finality and before anybody uses the new
   sender tree. Finality signs the already fixed checkpoint identifier and can
   be attached without changing encrypted contents. The builder erases its
   extra seed/state copies when preparation completes.
4. Every member, including the preparer and other online members, consumes its
   own entry ticket before using the era. Keeping an unopened backup entry for
   an era already in use would reopen consumed message roots.
5. A returning device obtains a fresh signed log head and fetches only its
   latest entry. It verifies independent membership authorization, finality,
   its credential proof, the preparer's proof/signature, and the common state
   commitment, then atomically consumes the entry key and installs the state.
6. An entry cannot reset the same or an older era. An unchanged-era return
   preserves the saved sending lane. Prior unread intermediate entries remain
   explicit unread-state exposures, not forward-secure archived history.

The stored entry is recipient-specific, not sender-identifying to the service.
Mailbox delivery authorization is provisioned separately from the rotating
group submission capability. No account-authenticated fallback exists.

In the checked-in 128-device, seven-transition example, current-send control
download is **8,064 bytes in two round trips**, with **256 bytes uploaded**.
The entry preparer uploads **6,537,216 bytes** and downloads **2,523,136 bytes**
of ticket records over those transitions. The returning device prepublishes
**19,712 bytes** of entry inventory and retains **8,638 bytes** of private entry
keys for its absence. These are costs of this candidate format and workload,
not a guarantee for other layouts or all group policies.

`results/scale-1000.json` repeats the experiment with 1,000 devices and two
membership transitions over seven days. Its first-send control download is
8,320 bytes in two round trips; the preparer uploads 14,848,000 bytes of entries
over the two boundaries. The small receiving cost does not eliminate the
preparer's linear device bandwidth cost.

This achieves a small *first-send* control path by paying O(n) preparation per
membership boundary. Missing entry inventory, a missing package, unavailable
finality, or a newly selected preparer without assigned tickets causes a visible
pending result. The service cannot invent replacement keys.

The experiment also demonstrates that first-send readiness does not imply
bounded reception from an active sender. A returning device whose skipped-key
budget is smaller than that sender's backlog must process dependencies/history.
Cold credential lookup, encrypted discovery, guardian rotation and archive
retrieval are not included in the 8,064-byte control count. Existing transport
costs and real cryptographic CPU costs are also excluded.

## Shared-entry comparisons

The [shared-entry experiment](COVER-EXPERIMENT.md) encrypts common state once
and compares direct, shard, and hierarchical one-use delivery. It includes
authenticated private-pool distribution and deletion, public catalogs, stable
blinded membership proofs, rotating authors, removal fragmentation, inventory
exhaustion, and explicit cohort-rebuild costs. It uses the existing pure PQ
suite through the ideal functionality. Tree is selected for further work;
the other layouts remain comparison constructions.

In [the 128-device, seven-removal run](results/cover-128.json), transition-author
upload is 1,614,592 bytes for compact direct delivery, 1,163,008 for shards, and
277,376 for the tree. First-send control is 7,936–8,064 downloaded bytes in four
round trips, with no participant action needed at return. A separate busy-sender
reception measurement still needs backlog processing.

Those update savings do not make the tree the cheapest overall. Aggregate
provisioning upload is 2.13 MB, 2.72 MB and 10.07 MB respectively; the largest
single-device provisioning download is 0.63 MB, 0.77 MB and 1.65 MB. The reports
separately expose aggregate device traffic, busiest-device traffic, and endpoint
storage. [The 1,000-device run](results/cover-1000.json) and
[two-author run](results/cover-rotating.json) show the scaling and extra inventory
needed for rotation. See the experiment document for exact scopes and costs.

Private-pool provisioning currently requires its holders online; all necessary
inventory is installed before the modeled absence. No setup operation is hidden
inside offline resumption. The sparse directory avoids per-device proof uploads
on every change, but initial enrollment, authority exchanges, directory resizing,
metadata revocation from former members and traffic-correlation resistance remain
outside these measured results. Service-visible directory hashes commit blinded
credentials; the service can still observe tree shape and requested positions.

## History experiment

The prototype has `NONE`, `WINDOW` and `ALL_RETAINED` policies, authenticated at
membership boundaries. Windows use an archive position boundary authorized in
the checkpoint; service timestamps cannot broaden them. The archive index is
separate from live message ordering. Each message is its own independently
keyed segment to keep grant boundaries exact.

Grant creation and encryption happen at an authorized endpoint. The grant binds
the recipient, admission checkpoint, policy and exact range. A recipient can
consume a prepared grant while the inviter is offline and fetch messages in any
order. Archived records carry original-author signatures and authenticated
historical credentials; the grant issuer does not become their author.

The candidate format repeats historical checkpoints/proofs per record and is
intentionally unoptimized. The report exposes that overhead. Grant size is
bounded to 2,048 records; larger histories need multiple grants/pages. Public
grant-ticket enrollment and full private-directory discovery are preconditions,
not measured archive operations. A history grant is independent of live entry.

Existing grants cannot be revoked, and their keys expose retained content on
compromise. Future segments use independent keys. Normal policy changes cannot
broaden a previously narrower policy or recreate erased `NONE` history; explicit
export of previously private content is not modeled.

## Adversarial scenarios and conformance mapping

| Spec scenario | Exercised behavior |
|---|---|
| 1–3 | Concurrent sender updates, all-order and seeded delivery schedules, lazy frontier deletion |
| 4 | Combined earlier/later snapshots and the negative control that deliberately retains raw entropy |
| 5, 13 | Idempotent retries, signed forks, immutable outboxes, producer assignment; view comparison required for detection |
| 6, 9 | Single-use admission/entry, authorized join/removal/recovery, recipient exclusion, direct fallback |
| 7 | Ciphertext-dependent header derivation, encrypted signatures, context binding and padding validation |
| 8, 19 | Long replay, virtual multi-day absence, many membership changes, experimental latest-entry first send |
| 10 | Offline ticket exhaustion, contributor replacement without assigned inventory, continued established lanes |
| 11, 15 | Pending bytes/objects, frontier quota, skipped-key quotas/TTL, bounded parser and dependency scheduler |
| 12, 14 | Reservation crashes, atomic send/entry consumption, immutable retries, rollback witness and key-box lifecycle |
| 16–17 | Service traces contain opaque records and non-identifying authorization; identifying headers are rejected |
| 18 | Recipient/policy/range-bound history, independent archive access, original authorship and prospective policies |
| 20–22 (tree and comparisons) | Exact subsets, fresh joins, shared-box erasure, salted metadata, incremental proofs, setup/repair/exhaustion costs |
| 23 | Default tree runner; NONE/WINDOW/ALL_RETAINED with blinded credentials; live sending while archives are withheld |

Historical shared-shard ticket-box behavior remains a separate symbolic lifecycle
model; the authenticated delivery experiment assumes already validated box import.
The selected shared-entry path has its own ideal encrypted enrollment/box-import
adapter, which must not be mistaken for the earlier producer-ratchet adapter.
The scheduler assumes authentication before enqueueing. Signature/KEM security,
adaptive cryptographic proofs, a complete private directory bootstrap, privacy
against traffic correlation, real persistence/erasure, and PQ library side
channels are outside what these tests can establish.

Two expected negative results are preserved instead of hidden behind passing
tests: isolated split views are undetectable until authenticated views meet,
and fragmented entropy frontiers can exceed the configured memory budget. At
10,000 lanes, the alternating-consumption example retains 160,000 secret bytes
per contribution, projecting to 691,200,000 bytes across 4,320 events before
bookkeeping. Resource limits defer work or produce explicit gaps; they do not
make that workload fit a 16 MiB endpoint budget.
