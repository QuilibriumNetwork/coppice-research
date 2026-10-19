"""Selected tree-delivery research path and direct/shard comparison layouts.

This is not TreeKEM, a broadcast-encryption primitive, or a proved CGKA.
All cryptography uses ideal.py. Subset keys are independently random one-use
NTRU tickets, never derived from ancestor keys. The trusted guardian certifies
immutable audiences; only an audience member may publish its private pool.
"""
from dataclasses import dataclass, field, replace

from core import Client, digest, kdf
from membership import Credential, Checkpoint, verify_checkpoint
from resumption import Session
from service import Record
from wire import Merkle, Proof, pack, unpack


def identity(credential):
    return digest(b"cover device", credential.name.encode(), credential.public)


def seal_metadata(crypto, lookup_key, value, aad):
    """Fresh per-object AEAD key, fixed zero AEAD nonce; salt is on the wire."""
    salt = crypto.fresh(b"cover metadata salt")
    key = kdf(lookup_key, b"cover metadata object", pack((aad, salt)))
    return pack((salt, crypto.seal(key, value, aad)))


def open_metadata(crypto, lookup_key, blob, aad):
    salt, ciphertext = unpack(blob)
    if not isinstance(salt, bytes) or len(salt) != 32:
        raise ValueError("invalid metadata salt")
    key = kdf(lookup_key, b"cover metadata object", pack((aad, salt)))
    return crypto.open(key, ciphertext, aad)


@dataclass(frozen=True)
class BlindedCredential(Credential):
    blind: bytes = b""

    def body(self):
        return pack((self.name, self.public, self.index, self.shard, self.blind))

    @classmethod
    def read(cls, raw):
        result = cls(*unpack(raw))
        if len(result.blind) != 32:
            raise ValueError("invalid credential blinding")
        return result


class SparseRoster:
    """Fixed-capacity stable slots; empty slots are committed tombstones.

    Checkpoint.count is SLOT CAPACITY in this candidate, not active membership
    count. A credential proof proves a live leaf. Resizing is an explicit O(n)
    directory rebuild; the experiment normally preallocates spare slots.
    """
    def __init__(self, group, credentials, capacity):
        credentials = tuple(sorted(credentials, key=lambda c: c.index))
        if (not credentials or capacity < 1 or capacity & (capacity - 1) or
                len({c.index for c in credentials}) != len(credentials) or
                len({c.name for c in credentials}) != len(credentials) or
                len({c.public for c in credentials}) != len(credentials) or
                any(not 0 <= c.index < capacity or len(c.blind) != 32 for c in credentials)):
            raise ValueError("invalid sparse roster")
        self.group, self.capacity, self.credentials = group, capacity, credentials
        self.by_name = {c.name: c for c in credentials}
        leaves = [pack(None)] * capacity
        for c in credentials:
            leaves[c.index] = c.body()
        self.tree = Merkle(leaves, pack(("credential roster", group)))

    def proof(self, name):
        return self.tree.proof(self.by_name[name].index)

    def publish_hashes(self, service, route, capability, known, meter, expires):
        """Upload changed hash nodes only. No plaintext credentials reach DS."""
        for level, hashes in enumerate(self.tree.levels):
            for i, value in enumerate(hashes):
                if value in known:
                    continue
                children = () if level == 0 else tuple(self.tree.levels[level - 1][2*i:2*i+2])
                service.put(route, capability, Record(value, pack(children), children, expires), meter)
                known.add(value)


@dataclass
class Subset:
    group: bytes
    generation: bytes
    members: tuple
    publisher: BlindedCredential

    def __post_init__(self):
        self.members = tuple(sorted(self.members, key=lambda c: c.index))
        if (not self.members or self.publisher not in self.members or
                len({identity(c) for c in self.members}) != len(self.members)):
            raise ValueError("subset publisher must be a holder")
        self.tree = Merkle([c.body() for c in self.members],
                           pack(("cover audience", self.group, self.generation)))
        self.identifier = digest(b"cover subset", self.group, self.generation, self.tree.root)

    def proof(self, credential):
        return self.tree.proof(self.members.index(credential))


def make_subsets(group, generation, credentials, mode, shard_size=64):
    """Immutable cohorts. Joins use fresh cohorts; removals never relabel one."""
    credentials = tuple(sorted(credentials, key=lambda c: c.index))
    if mode not in ("direct", "shard", "tree") or shard_size < 1 or not credentials:
        raise ValueError("invalid recipient layout")
    audiences = []
    if mode == "tree":
        width = 1 << (len(credentials) - 1).bit_length()
        def visit(start, stop):
            members = credentials[start:min(stop, len(credentials))]
            if not members:
                return
            audiences.append(members)
            if stop - start > 1:
                middle = (start + stop) // 2
                visit(start, middle)
                visit(middle, stop)
        visit(0, width)
    else:
        if mode == "shard":
            audiences.extend(credentials[i:i+shard_size] for i in range(0, len(credentials), shard_size))
        audiences.extend((c,) for c in credentials)
    result, seen = [], set()
    for members in audiences:
        key = tuple(identity(c) for c in members)
        if key in seen:
            continue
        seen.add(key)
        # Distributes publishers across holders; no outsider owns private pools.
        publisher = members[len(result) % len(members)]
        result.append(Subset(group, generation, members, publisher))
    return tuple(result)


@dataclass(frozen=True)
class Scope:
    group: bytes
    subset: bytes
    generation: bytes
    audience_root: bytes
    audience_count: int
    publisher: bytes
    publisher_proof: bytes
    producer: bytes
    approvals: tuple = ()

    def body(self):
        return pack((self.group, self.subset, self.generation, self.audience_root,
                     self.audience_count, self.publisher, self.publisher_proof, self.producer))

    def wire(self):
        return pack((self.body(), self.approvals))

    @classmethod
    def read(cls, raw):
        body, approvals = unpack(raw)
        return cls(*unpack(body), approvals)

    def includes(self, credential, proof):
        return (proof.count == self.audience_count and
                Merkle.verify(credential.body(), proof, self.audience_root,
                              pack(("cover audience", self.group, self.generation))))

    def verify(self, crypto, governance, group):
        if self.group != group or self.subset != digest(b"cover subset", group, self.generation, self.audience_root):
            raise ValueError("wrong subset scope")
        publisher = BlindedCredential.read(self.publisher)
        if not self.includes(publisher, Proof(*unpack(self.publisher_proof))):
            raise ValueError("private pool publisher is outside audience")
        seen = set()
        for public, signature in self.approvals:
            if public in seen or public not in governance.keys or not crypto.verify(public, self.body(), signature):
                raise ValueError("invalid subset authorization")
            seen.add(public)
        if len(seen) < governance.threshold:
            raise ValueError("insufficient subset authorization")
        return publisher


@dataclass(frozen=True)
class PoolManifest:
    scope: Scope
    nonce: bytes
    root: bytes
    count: int
    signature: bytes = b""

    @property
    def context(self):
        return pack(("cover pool", self.scope.group, self.scope.subset, self.scope.producer, self.nonce))

    def descriptor(self, index, public):
        return pack((self.context, index, public))

    def body(self):
        return pack((self.scope.wire(), self.nonce, self.root, self.count))

    def wire(self):
        return pack((self.body(), self.signature))

    @classmethod
    def read(cls, raw):
        body, signature = unpack(raw)
        scope, nonce, root, count = unpack(body)
        return cls(Scope.read(scope), nonce, root, count, signature)

    def verify(self, crypto, governance, group):
        publisher = self.scope.verify(crypto, governance, group)
        if not 1 <= self.count <= 4096 or not crypto.verify(publisher.public, self.body(), self.signature):
            raise ValueError("invalid pool manifest")
        return publisher


@dataclass(frozen=True)
class Ticket:
    manifest: PoolManifest
    index: int
    public: bytes
    proof: Proof

    @property
    def identifier(self):
        return digest(b"cover ticket", self.manifest.descriptor(self.index, self.public))

    def verify(self, crypto, governance, group):
        self.manifest.verify(crypto, governance, group)
        if (len(self.public) != 930 or self.index != self.proof.index or
                self.proof.count != self.manifest.count or
                not Merkle.verify(self.manifest.descriptor(self.index, self.public), self.proof,
                                  self.manifest.root, self.manifest.context)):
            raise ValueError("invalid public pool ticket")


@dataclass
class CoverInventory:
    credential: BlindedCredential
    secrets: dict = field(default_factory=dict)
    refs: dict = field(default_factory=dict)  # id -> (subset, producer), no roots
    public_seen: set = field(default_factory=set)
    consumed: set = field(default_factory=set)
    subsets: set = field(default_factory=set)
    max_private_bytes: int = 16 * 1024**2
    max_ticket_refs: int = 100_000

    def import_box(self, crypto, governance, group, manifest, keys, audience_proof):
        manifest.verify(crypto, governance, group)
        if not manifest.scope.includes(self.credential, audience_proof) or len(keys) != manifest.count:
            raise ValueError("wrong private pool recipient or size")
        if (len(self.refs) + len(keys) > self.max_ticket_refs or
                sum(map(len, self.secrets.values())) + len(keys) * 1234 > self.max_private_bytes):
            raise LookupError("private pool budget exhausted")
        tree = Merkle([manifest.descriptor(i, public) for i, (public, _) in enumerate(keys)], manifest.context)
        if tree.root != manifest.root:
            raise ValueError("private pool differs from authenticated public pool")
        staged, fingerprints = {}, set()
        for i, (public, secret) in enumerate(keys):
            ticket_id = digest(b"cover ticket", manifest.descriptor(i, public))
            fingerprint = digest(b"cover public key", public)
            if (len(public) != 930 or len(secret) != 1234 or ticket_id in self.refs or
                    fingerprint in self.public_seen or fingerprint in fingerprints):
                raise ValueError("duplicate, aliased, or malformed private ticket")
            probe = crypto.seal_to(public, b"key validation", b"cover probe")
            crypto.open_with(secret, probe, b"cover probe")
            staged[ticket_id] = secret
            fingerprints.add(fingerprint)
        self.secrets.update(staged)
        self.refs.update({t: (manifest.scope.subset, manifest.scope.producer) for t in staged})
        self.public_seen.update(fingerprints)
        self.subsets.add(manifest.scope.subset)
        # Caller atomically erases the enrollment KEM key, box key, and plaintext.

    def storage(self):
        return {"raw_private_ticket_bytes": sum(map(len, self.secrets.values())),
                "ticket_metadata_bytes": len(pack((self.refs, tuple(sorted(self.public_seen)),
                                                  tuple(sorted(self.consumed)), tuple(sorted(self.subsets))))),
                "unused_tickets": len(self.secrets)}


def choose_cover(subsets, roster, pools, producer, reserved):
    """Largest available safe subsets; direct tickets are explicit fallback."""
    remaining = {identity(c) for c in roster.credentials}
    current = remaining.copy()
    candidates = []
    for subset in subsets:
        holders = {identity(c) for c in subset.members}
        available = [t for t in pools.get((subset.identifier, producer), ()) if t.identifier not in reserved]
        if holders <= current and available:
            candidates.append((subset, available[0], holders))
    selected = []
    for subset, ticket, holders in sorted(candidates, key=lambda item: (-len(item[2]), item[0].identifier)):
        if holders <= remaining:
            selected.append((subset, ticket))
            remaining -= holders
    if remaining:
        raise LookupError("eligible cover inventory exhausted; transition pending")
    return tuple(selected)


def wrapper_selector(lookup_key, era, subset):
    return digest(b"private cover lookup", lookup_key, era, subset)


class CapsuleBuilder:
    """One immutable common object, one wrap per selected subset, no seed cache."""
    def __init__(self, crypto, governance, guardians, log, roster, previous, policy,
                 author, author_credential, selected, reserved, route, lookup_key,
                 history_boundary=0, crash_after_reservation=False):
        if roster.by_name.get(author_credential.name) != author_credential or author.public != author_credential.public:
            raise ValueError("unadmitted capsule author")
        expected, covered = {identity(c) for c in roster.credentials}, set()
        for subset, ticket in selected:
            ticket.verify(crypto, governance, roster.group)
            scope = ticket.manifest.scope
            holders = {identity(c) for c in subset.members}
            if (scope.subset != subset.identifier or scope.audience_root != subset.tree.root or
                    scope.producer != identity(author_credential) or
                    not holders <= expected or holders & covered or ticket.identifier in reserved):
                raise ValueError("unsafe, overlapping, reserved, or misassigned cover")
            covered.update(holders)
        if covered != expected:
            raise ValueError("incomplete capsule coverage")
        self.crypto, self.log = crypto, log
        self.selected = tuple(selected)
        reserved.update(t.identifier for _, t in selected)  # Durable before any sealing.
        if crash_after_reservation:
            raise RuntimeError("crash after reservation; abandon tickets")
        context = pack(("entry cover", roster.group))
        cover = Merkle([pack((s.identifier, t.identifier)) for s, t in selected], context)
        values = {label: crypto.fresh(label.encode()) for label in
                  ("sender_seed", "era_next", "metadata_key", "directory_key", "delivery_capability")}
        values.update(route=route, cover_root=cover.root)
        checkpoint = Checkpoint(roster.group, 1 if previous is None else previous.number + 1,
                                b"" if previous is None else previous.identifier, roster.tree.root,
                                roster.capacity, policy, digest(b"shared capsule state", pack(values)),
                                crypto.fresh(b"capsule checkpoint"), history_boundary)
        checkpoint = governance.authorize(crypto, checkpoint, guardians)
        self.checkpoint = checkpoint
        body = pack(("shared entry", checkpoint.identifier, values, author_credential.body(),
                     roster.proof(author_credential.name).wire()))
        key = crypto.fresh(b"common capsule key")
        self.common = crypto.seal(key, (checkpoint.wire(), body, crypto.sign(author, body)),
                                  pack((roster.group, checkpoint.identifier, "shared entry")))
        self.common_selector = digest(b"common capsule ciphertext", self.common)
        self.packets = {}
        for i, (subset, ticket) in enumerate(selected):
            aad = pack((roster.group, checkpoint.identifier, subset.identifier, ticket.identifier, self.common_selector))
            wrapped = crypto.seal_to(ticket.public, key, aad)
            packet = (subset.identifier, ticket.identifier, wrapped, cover.proof(i).wire(), self.common_selector)
            self.packets[wrapper_selector(lookup_key, checkpoint.identifier, subset.identifier)] = seal_metadata(
                crypto, lookup_key, packet, pack((roster.group, checkpoint.identifier, "cover wrapper")))
        # No key, sender_seed, values, plaintext, or random-generator seed is
        # kept on this builder. Its remaining outbox is immutable ciphertext.
        self.finished = False
        self.publication_scope = None
        self.expires = None

    def finish(self):
        if not self.finished:
            self.checkpoint = self.log.commit(self.checkpoint)
            self.finished = True
        return self.checkpoint

    def publish(self, service, route, capability, meter, known_hashes, roster, expires):
        scope = (route, capability, roster.tree.root)
        if roster.tree.root != self.checkpoint.roster_root or (
                self.publication_scope is not None and scope != self.publication_scope):
            raise ValueError("outbox publication scope changed")
        if self.publication_scope is None:
            self.publication_scope, self.expires = scope, expires
        expires = self.expires  # Retries retain the original retention metadata too.
        checkpoint = self.finish()
        roster.publish_hashes(service, route, capability, known_hashes, meter, expires)
        service.put(route, capability, Record(self.common_selector,
                    pack((self.common, checkpoint.finality)), (checkpoint.roster_root,), expires), meter)
        for selector, packet in self.packets.items():
            service.put(route, capability, Record(selector, packet, (self.common_selector,), expires), meter)
        return checkpoint


def open_capsule(crypto, governance, log_public, group, inventory, packet, common_record,
                 latest_id, latest_number, lookup_key, own_proof, previous=None):
    """All checks precede mutation; caller persists session + erasure atomically."""
    subset, ticket_id, wrapped, proof_raw, common_selector = open_metadata(
        crypto, lookup_key, packet, pack((group, latest_id, "cover wrapper")))
    if ticket_id in inventory.consumed or ticket_id not in inventory.secrets:
        raise ValueError("entry ticket consumed or missing")
    if inventory.refs[ticket_id][0] != subset or common_record.selector != common_selector:
        raise ValueError("wrong wrapper audience or common object")
    common, finality = unpack(common_record.ciphertext)
    if digest(b"common capsule ciphertext", common) != common_selector:
        raise ValueError("common ciphertext substitution")
    key = crypto.open_with(inventory.secrets[ticket_id], wrapped,
                          pack((group, latest_id, subset, ticket_id, common_selector)))
    raw, body, signature = crypto.open(key, common, pack((group, latest_id, "shared entry")))
    checkpoint = replace(Checkpoint.read(raw), finality=finality)
    verify_checkpoint(crypto, governance, log_public, checkpoint, group)
    if (checkpoint.identifier != latest_id or checkpoint.number != latest_number or
            previous is not None and checkpoint.number <= previous.checkpoint.number):
        raise ValueError("entry would roll back or restore consumed state")
    kind, era, values, author_raw, author_proof = unpack(body)
    author = BlindedCredential.read(author_raw)
    credential = inventory.credential
    if (kind != "shared entry" or era != latest_id or
            inventory.refs[ticket_id][1] != identity(author) or
            not checkpoint.verify_credential(author, Proof(*unpack(author_proof))) or
            not checkpoint.verify_credential(credential, own_proof) or
            not crypto.verify(author.public, body, signature) or
            digest(b"shared capsule state", pack(values)) != checkpoint.state_commitment or
            not Merkle.verify(pack((subset, ticket_id)), Proof(*unpack(proof_raw)),
                              values["cover_root"], pack(("entry cover", group)))):
        raise ValueError("unauthenticated shared entry")
    ratchet = Client(values["sender_seed"], checkpoint.identifier,
                     members={credential.name: credential.index}, group=group, leaf_count=checkpoint.count)
    session = Session(checkpoint, credential, ratchet, values["metadata_key"], values["directory_key"],
                      values["era_next"], values["route"], values["delivery_capability"])
    del inventory.secrets[ticket_id]
    inventory.consumed.add(ticket_id)
    return session


def resume_capsule(crypto, governance, log, service, group, inventory, lookup_key,
                   route, capability, previous=None, meter=None, latest_response=None, lookup_budget=256):
    challenge = crypto.fresh(b"cover finality challenge")
    body, signature = log.latest(challenge) if latest_response is None else latest_response
    if meter is not None:
        meter.charge("finality", pack((group, challenge)), pack((body, signature)))
    g, number, era, received = unpack(body)
    if g != group or received != challenge or not crypto.verify(log.signer.public, body, signature):
        raise ValueError("stale or invalid finality")
    if previous is not None:
        if number < previous.checkpoint.number:
            raise ValueError("membership rollback")
        if number == previous.checkpoint.number:
            if era != previous.checkpoint.identifier:
                raise ValueError("conflicting final membership")
            return previous
    selectors = [wrapper_selector(lookup_key, era, subset) for subset in sorted(inventory.subsets)]
    if len(selectors) > lookup_budget:
        raise LookupError("resumption lookup budget exhausted; explicit recovery required")
    found = []
    for start in range(0, len(selectors), 256):
        found.extend(r for r in service.get_many(route, capability, selectors[start:start+256], meter) if r is not None)
    if not found:
        raise LookupError("no current entry for recipient")
    if len(found) != 1:
        raise ValueError("overlapping entry paths")
    packet = found[0].ciphertext
    _, _, _, _, common_selector = open_metadata(crypto, lookup_key, packet, pack((group, era, "cover wrapper")))
    common = service.get(route, capability, common_selector, meter)
    # Root is inside the common ciphertext. Stage an opening just to obtain the
    # authenticated directory root; never consume a ticket before proof fetch.
    subset, ticket_id, wrapped, _, _ = open_metadata(crypto, lookup_key, packet, pack((group, era, "cover wrapper")))
    if ticket_id not in inventory.secrets or inventory.refs[ticket_id][0] != subset:
        raise ValueError("entry ticket consumed, absent, or wrong subset")
    key = crypto.open_with(inventory.secrets[ticket_id], wrapped, pack((group, era, subset, ticket_id, common_selector)))
    encrypted, finality = unpack(common.ciphertext)
    raw, _, _ = crypto.open(key, encrypted, pack((group, era, "shared entry")))
    checkpoint = replace(Checkpoint.read(raw), finality=finality)
    verify_checkpoint(crypto, governance, log.signer.public, checkpoint, group)
    if checkpoint.identifier != era or checkpoint.number != number:
        raise ValueError("wrong checkpoint")
    proof = service.merkle_proof(route, capability, checkpoint.roster_root,
                                 inventory.credential.index, checkpoint.count, meter)
    return open_capsule(crypto, governance, log.signer.public, group, inventory, packet,
                        common, era, number, lookup_key, proof, previous)
