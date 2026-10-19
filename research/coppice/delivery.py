"""Authenticated partial-fetch experiment for assigned, one-use contributions.

Uses the ideal crypto functionality and candidate encoding. Full membership
and ticket descriptors are endpoint inputs, not service-visible records.
Shared private-key distribution is separately modeled by core.TicketBoxLane;
installing an inventory here represents an already authenticated box import.
"""
from copy import deepcopy
from dataclasses import dataclass, field
from core import Contribution, digest
from wire import pack, unpack, Merkle, Proof


@dataclass(frozen=True)
class Descriptor:
    group: bytes
    era: bytes
    holders: tuple
    producer: str
    issuer: str
    purpose: str
    index: int
    public: bytes

    def body(self):
        return pack((self.group, self.era, self.holders, self.producer, self.issuer,
                     self.purpose, self.index, self.public))

    @property
    def identifier(self):
        return digest(b"research delivery ticket", self.body())


@dataclass(frozen=True)
class Manifest:
    group: bytes
    era: bytes
    issuer: str
    root: bytes
    count: int
    nonce: bytes
    signature: bytes = b""

    def body(self):
        return pack((self.group, self.era, self.issuer, self.root, self.count, self.nonce))

    @property
    def context(self):
        return pack(("ticket manifest", self.group, self.era, self.issuer))


@dataclass(frozen=True)
class PublicTicket:
    descriptor: Descriptor
    manifest: Manifest
    proof: Proof

    def verify(self, crypto, roster, era):
        d, m = self.descriptor, self.manifest
        if (d.group != roster.group or m.group != roster.group or d.era != era or m.era != era or
                d.issuer != m.issuer or d.issuer not in roster.by_name or d.producer not in roster.by_name or
                not d.holders or tuple(sorted(set(d.holders))) != d.holders or
                d.issuer not in d.holders or any(h not in roster.by_name for h in d.holders) or
                d.purpose != "group entropy" or self.proof.count != m.count or
                not crypto.verify(roster.by_name[m.issuer].public, m.body(), m.signature) or
                not Merkle.verify(d.body(), self.proof, m.root, m.context)):
            raise ValueError("invalid assigned-ticket manifest or descriptor")
        if len(d.holders) > 1:
            shard = roster.by_name[d.issuer].shard
            expected = {c.name for c in roster.credentials if c.shard == shard}
            if set(d.holders) != expected:
                raise ValueError("shared ticket does not cover exact authenticated shard")


def issue_batch(crypto, roster, era, issuer, signer, assignments):
    """assignments: ordered (holders, producer) entries; random independent keys."""
    from dataclasses import replace
    if roster.by_name[issuer].public != signer.public:
        raise ValueError("wrong ticket issuer")
    keys, descriptors = [], []
    for index, (holders, producer) in enumerate(assignments):
        key = crypto.kem_key()
        keys.append(key)
        descriptors.append(Descriptor(roster.group, era, tuple(sorted(holders)), producer,
                                      issuer, "group entropy", index, key.public))
    context = pack(("ticket manifest", roster.group, era, issuer))
    tree = Merkle([d.body() for d in descriptors], context)
    manifest = Manifest(roster.group, era, issuer, tree.root, len(descriptors), crypto.fresh())
    manifest = replace(manifest, signature=crypto.sign(signer, manifest.body()))
    tickets = [PublicTicket(d, manifest, tree.proof(i)) for i, d in enumerate(descriptors)]
    for ticket in tickets:
        ticket.verify(crypto, roster, era)
    return tuple(zip(tickets, keys))


@dataclass
class Inventory:
    holder: str
    secrets: dict = field(default_factory=dict)
    public_keys: dict = field(default_factory=dict)
    seen_sequences: dict = field(default_factory=dict)
    frozen: set = field(default_factory=set)

    def install(self, crypto, roster, era, ticket, key):
        ticket.verify(crypto, roster, era)
        d = ticket.descriptor
        if self.holder not in d.holders or key.public != d.public:
            raise ValueError("inventory recipient/key mismatch")
        if d.identifier in self.secrets or d.public in self.public_keys:
            raise ValueError("duplicate or aliased private ticket")
        # Validate the private/public relation through an ideal encapsulation.
        probe = crypto.seal_to(d.public, b"key validation", b"probe")
        crypto.open_with(key.secret, probe, b"probe")
        self.secrets[d.identifier] = key.secret
        self.public_keys[d.public] = d.identifier  # Tombstones survive consumption.


@dataclass(frozen=True)
class Partial:
    header: bytes
    signature: bytes
    slot: bytes
    proof: Proof
    ticket: PublicTicket

    def wire(self):
        t = self.ticket
        return pack((self.header, self.signature, self.slot, self.proof.wire(),
                     t.descriptor.body(), t.manifest.body(), t.manifest.signature, t.proof.wire()))

    @classmethod
    def read(cls, raw):
        header, signature, slot, proof, descriptor, manifest, manifest_sig, ticket_proof = unpack(raw)
        ticket = PublicTicket(Descriptor(*unpack(descriptor)),
                              Manifest(*unpack(manifest), signature=manifest_sig),
                              Proof(*unpack(ticket_proof)))
        return cls(header, signature, slot, Proof(*unpack(proof)), ticket)


class ContributionOutbox:
    def __init__(self, producer):
        self.producer, self.reserved, self.outbox = producer, set(), {}

    def create(self, crypto, roster, era, signer, tickets, sequence=0, previous=b"",
               crash_after_reservation=False):
        if signer.public != roster.by_name[self.producer].public:
            raise ValueError("wrong contribution signer")
        covered = set()
        for ticket in tickets:
            ticket.verify(crypto, roster, era)
            d = ticket.descriptor
            if d.producer != self.producer or d.identifier in self.reserved or covered.intersection(d.holders):
                raise ValueError("wrong assignment, used ticket, or overlapping coverage")
            covered.update(d.holders)
        if covered != set(roster.by_name):
            raise ValueError("incomplete recipient coverage")
        reservation = tuple(t.descriptor.identifier for t in tickets)
        if (era, sequence) in self.outbox:
            raise ValueError("producer sequence already committed")
        if sequence == 0:
            if previous:
                raise ValueError("unexpected genesis predecessor")
        elif (era, sequence - 1) not in self.outbox or previous != digest(
                b"contribution", self.outbox[era, sequence - 1][0].header):
            raise ValueError("missing contribution predecessor")
        self.reserved.update(reservation)
        if crash_after_reservation:
            raise RuntimeError("crash after reservation; abandon tickets")
        config = digest(b"recipient configuration", pack(reservation), roster.tree.root)
        context = pack((roster.group, era, self.producer, sequence, previous, config))
        delta = crypto.fresh(b"contribution entropy")
        commitment = digest(b"contribution value", context, delta)
        slots = []
        for ticket in tickets:
            d = ticket.descriptor
            aad = pack((context, commitment, d.identifier, d.holders))
            slots.append(pack((d.identifier, d.holders, crypto.seal_to(d.public, delta, aad))))
        tree = Merkle(slots, context)
        header = pack((context, commitment, tree.root, len(slots)))
        signature = crypto.sign(signer, header)
        partials = tuple(Partial(header, signature, slot, tree.proof(i), tickets[i]) for i, slot in enumerate(slots))
        self.outbox[era, sequence] = partials
        # No delta or encapsulation seed is retained in this outbox.
        return partials


def accept_partial(crypto, roster, client, inventory, partial):
    context, commitment, root, count = unpack(partial.header)
    group, era, producer, sequence, previous, config = unpack(context)
    if (group != client.group or group != roster.group or era != client.era or
            producer not in roster.by_name or (era, producer) in inventory.frozen or
            not crypto.verify(roster.by_name[producer].public, partial.header, partial.signature) or
            partial.proof.count != count or
            not Merkle.verify(partial.slot, partial.proof, root, context)):
        raise ValueError("invalid signed partial contribution")
    partial.ticket.verify(crypto, roster, era)
    d = partial.ticket.descriptor
    ticket_id, holders, ciphertext = unpack(partial.slot)
    event_id = digest(b"contribution", partial.header)
    if (ticket_id != d.identifier or holders != d.holders or producer != d.producer or
            inventory.holder not in holders):
        raise ValueError("partial slot recipient binding")
    sequence_key = era, producer, sequence
    prior = inventory.seen_sequences.get(sequence_key)
    if prior is not None and prior != event_id:
        inventory.frozen.add((era, producer))
        raise ValueError("signed contribution fork")
    if sequence == 0:
        if previous:
            raise ValueError("invalid contribution genesis")
    elif inventory.seen_sequences.get((era, producer, sequence - 1)) != previous:
        raise LookupError("missing contribution predecessor")
    consumed = client.consumed_tickets.get(ticket_id)
    if consumed is not None:
        if consumed != event_id:
            inventory.frozen.add((era, producer))
            raise ValueError("one-use ticket reused")
        return event_id
    if ticket_id not in inventory.secrets:
        raise LookupError("missing single-use delivery capability")
    aad = pack((context, commitment, ticket_id, holders))
    delta = crypto.open_with(inventory.secrets[ticket_id], ciphertext, aad)
    if digest(b"contribution value", context, delta) != commitment:
        raise ValueError("contribution commitment mismatch")
    staged = deepcopy(client)
    staged.consumed_tickets[ticket_id] = event_id
    staged.add_contribution(Contribution(era, event_id, delta, group, event_id))
    # One transaction in the persistence model: install restricted state and erase.
    client.__dict__.update(staged.__dict__)
    del inventory.secrets[ticket_id]
    inventory.seen_sequences[sequence_key] = event_id
    return event_id
