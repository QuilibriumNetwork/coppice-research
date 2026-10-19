"""EXPERIMENT: direct, presealed per-era entry for every member.

This is not the baseline shard-transition wire protocol. An authorized member
prepares O(n) independently encrypted entries at each membership boundary,
before any participant consumes the new sender tree. Online members MUST also
consume their entry tickets; otherwise the entry would be a retained backdoor.

A returning member fetches a fresh trusted-log head and its latest entry. It
downloads its own credential proof, not the full roster or intermediate eras.
Current-message reception from other senders still needs lane dependencies.
Missing entries, exhausted tickets or unavailable finality produce a pending
result, not restored roots, a live-peer requirement disguised as success, or
an identifying delivery fallback.
"""
from dataclasses import dataclass, field, replace
from core import Client, digest, kdf
from wire import pack, unpack, Proof
from membership import Checkpoint, Credential, verify_checkpoint
from service import Record


@dataclass(frozen=True)
class EntryTicket:
    group: bytes
    recipient: str
    preparer: bytes
    public: bytes
    nonce: bytes
    signature: bytes

    def body(self):
        return pack(("era entry", self.group, self.recipient, self.preparer, self.public, self.nonce))

    @property
    def identifier(self):
        return digest(b"entry ticket", self.body())


@dataclass
class Inbox:
    route: bytes
    capability: bytes
    secrets: dict = field(default_factory=dict)
    consumed: set = field(default_factory=set)

    @classmethod
    def create(cls, crypto, service):
        result = cls(crypto.fresh(b"mailbox route"), crypto.fresh(b"mailbox capability"))
        service.register(result.route, result.capability)
        return result

    def issue(self, crypto, group, credential, signer, preparer):
        if signer.public != credential.public:
            raise ValueError("ticket signer does not own recipient identity")
        key = crypto.kem_key()
        from dataclasses import replace
        ticket = EntryTicket(group, credential.name, preparer, key.public,
                             crypto.fresh(b"entry ticket nonce"), b"")
        ticket = replace(ticket, signature=crypto.sign(signer, ticket.body()))
        self.secrets[ticket.identifier] = key.secret
        return ticket


@dataclass
class Session:
    checkpoint: Checkpoint
    credential: Credential
    ratchet: Client
    metadata_key: bytes
    directory_key: bytes
    era_next: bytes
    route: bytes
    delivery_capability: bytes


class EntryBuilder:
    """Single-use endpoint builder, never a server role or persistent seed cache."""
    def __init__(self, crypto, group, roster, policy, previous, preparer, governance,
                 guardians, log, route, history_boundary=0):
        if preparer.public not in {c.public for c in roster.credentials}:
            raise ValueError("entry preparer is not a retained member")
        self.crypto, self.roster, self.preparer = crypto, roster, preparer
        self.values = {label: crypto.fresh(label.encode()) for label in
                       ("sender_seed", "era_next", "metadata_key", "directory_key", "delivery_capability")}
        self.values["route"] = route
        state_commitment = digest(b"research era entry state", pack(self.values))
        checkpoint = Checkpoint(group, 1 if previous is None else previous.number + 1,
                                b"" if previous is None else previous.identifier,
                                roster.tree.root, len(roster.credentials), policy,
                                state_commitment, crypto.fresh(b"membership nonce"), history_boundary)
        self.checkpoint = governance.authorize(crypto, checkpoint, guardians)
        self.log = log
        self.preparer_credential = next(c for c in roster.credentials if c.public == preparer.public)
        self.prepared, self.packets = set(), {}
        self.closed = False

    def prepare(self, ticket, reserved):
        if self.closed:
            raise ValueError("entry builder secrets already erased")
        recipient = self.roster.by_name.get(ticket.recipient)
        if (recipient is None or ticket.group != self.checkpoint.group or
                ticket.preparer != self.preparer.public or
                not self.crypto.verify(recipient.public, ticket.body(), ticket.signature)):
            raise ValueError("unauthorized entry ticket")
        if ticket.identifier in reserved or recipient.name in self.prepared:
            raise ValueError("entry ticket reserved or recipient already covered")
        reserved.add(ticket.identifier)  # Durable reservation assumption, before sealing.
        self.prepared.add(recipient.name)
        payload = pack(("era entry", self.checkpoint.identifier, recipient.body(),
                        self.roster.proof(recipient.name).wire(), self.values,
                        self.preparer_credential.body(),
                        self.roster.proof(self.preparer_credential.name).wire()))
        signature = self.crypto.sign(self.preparer, payload)
        context = pack((self.checkpoint.group, self.checkpoint.identifier, ticket.identifier))
        ciphertext = self.crypto.seal_to(ticket.public, (self.checkpoint.wire(), payload, signature), context)
        packet = pack((ticket.identifier, ciphertext))
        self.packets[recipient.name] = packet
        return packet

    def finish(self):
        if self.closed:
            return dict(self.packets)
        if self.prepared != set(self.roster.by_name):
            raise ValueError("entry coverage incomplete; membership entry unavailable")
        self.checkpoint = self.log.commit(self.checkpoint)
        # Finality covers the already fixed checkpoint ID. It adds no member
        # identity to the outer envelope and introduces no sealing/hash cycle.
        self.packets = {name: pack((*unpack(packet), self.checkpoint.finality))
                        for name, packet in self.packets.items()}
        self.values.clear()
        self.closed = True
        return dict(self.packets)


def entry_selector(inbox, checkpoint):
    return digest(b"private entry selector", inbox.route, checkpoint.identifier)


def publish_entries(service, builder, inboxes, meter=None, expires=30 * 86400):
    packets = builder.finish()
    checkpoint = builder.checkpoint
    # The shared route is an opaque destination. Its authorization rotates.
    # Read its new capability from an entry only at authorized endpoints; callers
    # register it separately after opening their entry.
    for name, packet in packets.items():
        inbox = inboxes[name]
        service.put(inbox.route, inbox.capability,
                    Record(entry_selector(inbox, checkpoint), packet, expires=expires), meter)
    return checkpoint


def accept_entry(crypto, governance, log_public, group, own_credential, inbox,
                 packet, latest_id, previous=None):
    ticket_id, ciphertext, finality = unpack(packet)
    if ticket_id in inbox.consumed or ticket_id not in inbox.secrets:
        raise ValueError("entry capability already consumed or unavailable")
    context = pack((group, latest_id, ticket_id))
    raw, body, signature = crypto.open_with(inbox.secrets[ticket_id], ciphertext, context)
    checkpoint = replace(Checkpoint.read(raw), finality=finality)
    verify_checkpoint(crypto, governance, log_public, checkpoint, group)
    if checkpoint.identifier != latest_id:
        raise ValueError("entry is not the authenticated current checkpoint")
    if previous is not None and checkpoint.number <= previous.checkpoint.number:
        raise ValueError("entry would restore a consumed era")
    kind, era, credential_raw, proof_raw, values, author_raw, author_proof_raw = unpack(body)
    credential, author = Credential.read(credential_raw), Credential.read(author_raw)
    proof, author_proof = Proof(*unpack(proof_raw)), Proof(*unpack(author_proof_raw))
    if (kind != "era entry" or era != checkpoint.identifier or
            (credential.name, credential.public) != (own_credential.name, own_credential.public) or
            not checkpoint.verify_credential(credential, proof) or
            not checkpoint.verify_credential(author, author_proof) or
            not crypto.verify(author.public, body, signature) or
            digest(b"research era entry state", pack(values)) != checkpoint.state_commitment):
        raise ValueError("invalid entry contents")
    # Only the new frontier retains the unconsumed sender seed. The Session has
    # no extra raw seed, packet plaintext, KEM key, or payload ancestor cache.
    ratchet = Client(values["sender_seed"], checkpoint.identifier,
                     members={credential.name: credential.index}, group=group,
                     leaf_count=checkpoint.count)
    result = Session(checkpoint, credential, ratchet, values["metadata_key"],
                     values["directory_key"], values["era_next"], values["route"],
                     values["delivery_capability"])
    # The caller's durable transaction must persist result and consumption together.
    del inbox.secrets[ticket_id]
    inbox.consumed.add(ticket_id)
    return result


def resume(crypto, governance, log, service, group, own_credential, inbox,
           previous=None, meter=None, latest_response=None):
    challenge = crypto.fresh(b"fresh finality challenge")
    response = log.latest(challenge) if latest_response is None else latest_response
    body, signature = response
    g, number, identifier, received_challenge = unpack(body)
    if meter is not None:
        meter.charge("finality", pack((group, challenge)), pack(response))
    if (g != group or received_challenge != challenge or
            not crypto.verify(log.signer.public, body, signature)):
        raise ValueError("stale or unauthenticated finality response")
    if previous is not None:
        if number < previous.checkpoint.number:
            raise ValueError("membership rollback")
        if number == previous.checkpoint.number:
            if identifier != previous.checkpoint.identifier:
                raise ValueError("conflicting final membership view")
            return previous
    selector = digest(b"private entry selector", inbox.route, identifier)
    packet = service.get(inbox.route, inbox.capability, selector, meter).ciphertext
    return accept_entry(crypto, governance, log.signer.public, group, own_credential,
                        inbox, packet, identifier, previous)


def authorize_sender(session, credential, proof):
    if not session.checkpoint.verify_credential(credential, proof):
        raise ValueError("invalid sender directory proof")
    session.ratchet.members[credential.name] = credential.index
