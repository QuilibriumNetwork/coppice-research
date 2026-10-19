"""Harness for comparing direct, shard, and tree shared-capsule delivery.

The harness owns all identities and the ideal oracle; it is NOT an endpoint.
Every modeled publication/download is assigned to the acting device's meter.
Cold identity enrollment, membership authorization exchange, actual erasure,
and external transport remain explicit preconditions, not measured traffic.
"""
from collections import defaultdict
from dataclasses import replace

from core import digest
from cover import (BlindedCredential, SparseRoster, Scope, PoolManifest, Ticket,
                   CoverInventory, CapsuleBuilder, make_subsets, choose_cover,
                   identity, resume_capsule, seal_metadata, open_metadata)
from ideal import IdealCrypto
from membership import Governance, FinalityLog, Policy
from resumption import authorize_sender
from service import DeliveryService, Meter, Record
from wire import Merkle, Proof, pack, unpack


class CoverLab:
    def __init__(self, names=("alice", "bob", "carol", "dave"), mode="tree",
                 shard_size=64, seed=b"cover experiment", capacity=None):
        if len(set(names)) != len(names) or not names:
            raise ValueError("invalid initial membership")
        self.crypto = IdealCrypto(seed)
        self.group, self.route = self.crypto.fresh(), self.crypto.fresh()
        self.store_route, self.store_cap, self.lookup_key = (self.crypto.fresh() for _ in range(3))
        self.guardian = self.crypto.signer()
        self.governance = Governance([self.guardian.public])
        self.log = FinalityLog(self.crypto, self.governance, self.group)
        self.service = DeliveryService(quota=2_000_000)
        self.service.register(self.store_route, self.store_cap)
        self.mode, self.shard_size = mode, shard_size
        self.capacity = capacity or 1 << len(names).bit_length()
        self.signers, self.credentials, self.inventories, self.sessions = {}, {}, {}, {}
        self.enrollment_secrets = defaultdict(dict)
        self.enrollment_consumed = defaultdict(set)
        self.meters = defaultdict(lambda: defaultdict(Meter))
        self.catalog_bytes = defaultdict(int)
        self.catalogs, self.manifests, self.pools = {}, {}, defaultdict(list)
        self.reserved, self.known_hashes = set(), set()
        self.subsets, self.checkpoint, self.roster = [], None, None
        self.now, self.cohorts, self.next_index = 0, 0, 0
        self.names = tuple(names)
        for name in names:
            self.add_identity(name)
        self.add_cohort(names)

    def add_identity(self, name):
        if name in self.credentials:
            raise ValueError("new device identity/name required")
        if self.next_index >= self.capacity:
            raise ValueError("sparse capacity exhausted; explicit directory resize required")
        signer = self.crypto.signer()
        credential = BlindedCredential(name, signer.public, self.next_index,
                                       f"shard-{self.next_index // self.shard_size}", self.crypto.fresh(b"credential blind"))
        self.next_index += 1
        self.signers[name], self.credentials[name] = signer, credential
        self.inventories[name] = CoverInventory(credential)

    def add_cohort(self, names):
        self.cohorts += 1
        subsets = make_subsets(self.group, self.crypto.fresh(b"cohort"),
                               [self.credentials[n] for n in names], self.mode, self.shard_size)
        self.subsets.extend(subsets)
        return subsets

    def meter(self, phase, name):
        return self.meters[phase][name]

    def _put(self, value, tag, name, phase, dependencies=()):
        blob = seal_metadata(self.crypto, self.lookup_key, value, pack((self.group, tag)))
        selector = digest(b"private cover object", blob)
        self.service.put(self.store_route, self.store_cap,
                         Record(selector, blob, dependencies, self.now + 30 * 86400), self.meter(phase, name))
        return selector

    def _get(self, selector, tag, name, phase):
        record = self.service.get(self.store_route, self.store_cap, selector, self.meter(phase, name))
        return open_metadata(self.crypto, self.lookup_key, record.ciphertext, pack((self.group, tag)))

    def provision(self, depth, producers=None, online=None, subsets=None, phase="provision"):
        """Explicit online setup/replenishment, never conjured on offline return.

        Each subset's publisher uploads one encrypted PRIVATE KEY BOX and one
        KEM box-key wrap per holder. Holders publish signed one-use enrollment
        keys first, import the WHOLE box, and erase both wrapping keys. Public
        tickets and catalogs are separate; only eligible producers fetch them.
        """
        if not 1 <= depth <= 4096:
            raise ValueError("invalid inventory depth")
        producers = (self.names[0],) if producers is None else tuple(producers)
        online = set(self.names if online is None else online)
        subsets = self.subsets if subsets is None else tuple(subsets)
        # Validate all dependencies BEFORE creating any pool.
        if not producers or any(p not in online or p not in self.credentials for p in producers):
            raise LookupError("producer unavailable for explicit catalog enrollment")
        if any(any(c.name not in online for c in s.members) for s in subsets):
            raise LookupError("private pool provisioning requires online holders in this experiment")
        for subset in subsets:
            for producer in producers:
                self._provision_pool(subset, depth, producer, phase)

    def _provision_pool(self, subset, depth, producer, phase):
        publisher = subset.publisher.name
        signer = self.signers[publisher]
        scope = Scope(self.group, subset.identifier, subset.generation, subset.tree.root, len(subset.members),
                      subset.publisher.body(), subset.proof(subset.publisher).wire(), identity(self.credentials[producer]))
        scope = replace(scope, approvals=((self.guardian.public, self.crypto.sign(self.guardian, scope.body())),))
        keys = [self.crypto.kem_key() for _ in range(depth)]
        manifest = PoolManifest(scope, self.crypto.fresh(b"pool nonce"), b"", depth)
        tree = Merkle([manifest.descriptor(i, key.public) for i, key in enumerate(keys)], manifest.context)
        manifest = replace(manifest, root=tree.root)
        manifest = replace(manifest, signature=self.crypto.sign(signer, manifest.body()))
        manifest_selector = self._put(manifest.wire(), "pool manifest", publisher, phase)
        tickets, selectors = [], []
        for i, key in enumerate(keys):
            ticket = Ticket(manifest, i, key.public, tree.proof(i))
            selector = self._put((manifest_selector, i, key.public, ticket.proof.wire()),
                                 "public ticket", publisher, phase, (manifest_selector,))
            tickets.append(ticket)
            selectors.append(selector)
            self.catalogs[ticket.identifier] = (selector, manifest_selector)
        def advertise():
            # A signed ready catalog is released only after the private box
            # and all wraps exist. Seeing an unadvertised public key is not
            # permission to use a half-prepared pool.
            body = pack((manifest_selector, tuple(selectors)))
            signed = (body, self.crypto.sign(signer, body))
            catalog = self._put(signed, "pool catalog", publisher, phase, (manifest_selector,))
            if producer == publisher:
                received_body, signature = signed
                loaded = manifest
            else:
                received_body, signature = self._get(catalog, "pool catalog", producer, phase)
                received_manifest, _ = unpack(received_body)
                loaded = PoolManifest.read(self._get(received_manifest, "pool manifest", producer, phase))
            received_manifest, received_selectors = unpack(received_body)
            catalog_publisher = loaded.verify(self.crypto, self.governance, self.group)
            if (loaded.scope.producer != identity(self.credentials[producer]) or
                    received_manifest != manifest_selector or received_selectors != tuple(selectors) or
                    not self.crypto.verify(catalog_publisher.public, received_body, signature)):
                raise ValueError("invalid producer catalog")
            self.manifests[producer, manifest_selector] = loaded
            self.catalog_bytes[producer] += len(pack((loaded.wire(), received_selectors)))

        if len(subset.members) == 1:
            # Local generation does not require uploading a private box to self.
            self.inventories[publisher].import_box(self.crypto, self.governance, self.group, manifest,
                tuple((k.public, k.secret) for k in keys), subset.proof(subset.publisher))
            keys.clear()
            key = None
            advertise()
            self.pools[subset.identifier, identity(self.credentials[producer])].extend(tickets)
            return
        box_key = self.crypto.fresh(b"private subset box key")
        box_aad = pack((self.group, manifest_selector, "private subset box"))
        box = self.crypto.seal(box_key, (manifest.wire(), tuple((k.public, k.secret) for k in keys)), box_aad)
        box_selector = self._put(box, "private pool ciphertext", publisher, phase, (manifest_selector,))
        for credential in subset.members:
            name = credential.name
            if name == publisher:
                self.inventories[name].import_box(self.crypto, self.governance, self.group, manifest,
                    tuple((k.public, k.secret) for k in keys), subset.proof(credential))
                continue
            enrollment = self.crypto.kem_key()
            body = pack((self.group, subset.identifier, identity(subset.publisher), identity(credential),
                         enrollment.public, self.crypto.fresh(b"enrollment nonce")))
            ticket_id = digest(b"pool enrollment", body)
            self.enrollment_secrets[name][ticket_id] = enrollment.secret
            signed = (body, self.crypto.sign(self.signers[name], body))
            prekey = self._put(signed, "pool enrollment key", name, phase)
            received_body, signature = self._get(prekey, "pool enrollment key", publisher, phase)
            if received_body != body or not self.crypto.verify(credential.public, received_body, signature):
                raise ValueError("unauthenticated pool enrollment")
            packet = self.crypto.seal_to(enrollment.public,
                        (box_key, box_selector, manifest_selector, subset.proof(credential).wire()),
                        pack((self.group, ticket_id)))
            packet_selector = self._put((ticket_id, packet), "pool enrollment wrap", publisher, phase,
                                        (box_selector,))
            received_id, received_packet = self._get(packet_selector, "pool enrollment wrap", name, phase)
            if received_id != ticket_id or received_id in self.enrollment_consumed[name]:
                raise ValueError("duplicate or substituted enrollment")
            imported_key, imported_box, imported_manifest, audience_proof = self.crypto.open_with(
                self.enrollment_secrets[name][received_id], received_packet, pack((self.group, received_id)))
            encrypted_box = self._get(imported_box, "private pool ciphertext", name, phase)
            manifest_raw, imported_keys = self.crypto.open(imported_key, encrypted_box,
                                                          pack((self.group, imported_manifest, "private subset box")))
            imported = PoolManifest.read(manifest_raw)
            if imported.scope.subset != subset.identifier or imported_manifest != manifest_selector:
                raise ValueError("substituted private pool")
            self.inventories[name].import_box(self.crypto, self.governance, self.group, imported,
                                             imported_keys, Proof(*unpack(audience_proof)))
            # Atomic import/erasure assumption, independently exercised by the
            # durable-state tests. No box key/plaintext is retained by a holder.
            del self.enrollment_secrets[name][received_id]
            self.enrollment_consumed[name].add(received_id)
        # Drop every extra private-key/box-key alias before advertising readiness.
        # Python cannot promise physical erasure; these are semantic deletions.
        keys.clear()
        key = box_key = imported_key = imported_keys = enrollment = None
        advertise()
        self.pools[subset.identifier, identity(self.credentials[producer])].extend(tickets)
        # The only persisted private copies live in holders' CoverInventory.

    def prepare(self, names=None, author=None, policy=None, crash_after_reservation=False,
                history_boundary=None):
        names = self.names if names is None else tuple(names)
        author = names[0] if author is None else author
        if author not in names:
            raise ValueError("removed or unadmitted update author")
        roster = SparseRoster(self.group, [self.credentials[n] for n in names], self.capacity)
        selected = choose_cover(self.subsets, roster, self.pools, identity(self.credentials[author]), self.reserved)
        loaded = []
        for subset, expected in selected:
            selector, manifest_selector = self.catalogs[expected.identifier]
            if subset.publisher.name == author:
                ticket = expected
            else:
                manifest_ref, index, public, proof = self._get(selector, "public ticket", author, "transition")
                if manifest_ref != manifest_selector:
                    raise ValueError("substituted public inventory")
                ticket = Ticket(self.manifests[author, manifest_selector], index, public, Proof(*unpack(proof)))
            if ticket.identifier != expected.identifier:
                raise ValueError("substituted public ticket")
            ticket.verify(self.crypto, self.governance, self.group)
            loaded.append((subset, ticket))
        builder = CapsuleBuilder(self.crypto, self.governance, [self.guardian], self.log, roster,
                                 self.checkpoint, policy or (self.checkpoint.policy if self.checkpoint else Policy()),
                                 self.signers[author], self.credentials[author], loaded, self.reserved,
                                 self.route, self.lookup_key,
                                 history_boundary=(0 if self.checkpoint is None else self.checkpoint.history_boundary)
                                 if history_boundary is None else history_boundary,
                                 crash_after_reservation=crash_after_reservation)
        return builder, roster

    def epoch(self, names=None, online=None, author=None, policy=None, history_boundary=None):
        names = self.names if names is None else tuple(names)
        online = names if online is None else tuple(online)
        author = names[0] if author is None else author
        if author not in online or not set(online) <= set(names):
            raise ValueError("membership author must be online and retained")
        builder, roster = self.prepare(names, author, policy, history_boundary=history_boundary)
        checkpoint = builder.publish(self.service, self.store_route, self.store_cap, self.meter("transition", author),
                                     self.known_hashes, roster, self.now + 30 * 86400)
        self.checkpoint, self.roster, self.last_builder, self.names = checkpoint, roster, builder, names
        for name in online:
            self.return_device(name, phase="online receive")
        return checkpoint

    def return_device(self, name, meter=None, phase="return"):
        session = resume_capsule(self.crypto, self.governance, self.log, self.service, self.group,
                                 self.inventories[name], self.lookup_key, self.store_route, self.store_cap,
                                 self.sessions.get(name), self.meter(phase, name) if meter is None else meter)
        self.sessions[name] = session
        session.ratchet.expire_skipped(self.now)
        self.service.register(self.route, session.delivery_capability)
        return session

    def learn_sender(self, recipient, sender):
        authorize_sender(self.sessions[recipient], self.roster.by_name[sender], self.roster.proof(sender))

    def public_credentials(self):
        return {name: c.public for name, c in self.roster.by_name.items()}

    def storage(self, name):
        result = self.inventories[name].storage()
        result["producer_catalog_bytes"] = self.catalog_bytes[name]
        result["pending_enrollment_private_bytes"] = sum(map(len, self.enrollment_secrets[name].values()))
        return result

    def traffic(self, phases=None):
        phases = tuple(self.meters) if phases is None else phases
        totals = defaultdict(lambda: [0, 0])
        for phase in phases:
            for name, meter in self.meters[phase].items():
                totals[name][0] += meter.upload
                totals[name][1] += meter.download
        if not totals:
            return {"upload_bytes": 0, "download_bytes": 0, "peak_device_upload_bytes": 0,
                    "peak_device_download_bytes": 0}
        busiest_up = max(totals, key=lambda name: totals[name][0])
        busiest_down = max(totals, key=lambda name: totals[name][1])
        return {"upload_bytes": sum(v[0] for v in totals.values()),
                "download_bytes": sum(v[1] for v in totals.values()),
                "peak_device_upload_bytes": totals[busiest_up][0], "peak_upload_device": busiest_up,
                "peak_device_download_bytes": totals[busiest_down][1], "peak_download_device": busiest_down}
