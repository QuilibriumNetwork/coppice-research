"""Experimental independently keyed archive records and recipient-bound grants.

Each record is a one-message segment, chosen to make range boundaries exact.
Larger segments and scalable grant manifests remain optimization work. Grant
creation is endpoint work. The service never sees an archive key or plaintext.
"""
from dataclasses import dataclass, field
from core import digest
from wire import pack, unpack, Proof
from membership import Checkpoint, Credential, verify_checkpoint
from service import Record


@dataclass(frozen=True)
class Segment:
    position: int
    selector: bytes
    key: bytes
    policy: object
    checkpoint: bytes


class ArchiveWriter:
    def __init__(self, group):
        self.group, self.segments = group, {}

    def append(self, crypto, checkpoint, roster, signer, position, payload,
               service, route, capability, meter=None, expires=30 * 86400):
        if checkpoint.group != self.group or checkpoint.policy.history == "NONE":
            raise ValueError("message policy does not permit archiving")
        if position in self.segments or type(position) is not int or position < checkpoint.history_boundary:
            raise ValueError("archive position already used or invalid")
        author = next((c for c in roster.credentials if c.public == signer.public), None)
        if author is None or not checkpoint.verify_credential(author, roster.proof(author.name)):
            raise ValueError("unauthorized archive author")
        context = pack(("archive message", self.group, checkpoint.identifier,
                        position, checkpoint.policy.value(), author.body(), payload))
        original_signature = crypto.sign(signer, context)
        key = crypto.fresh(b"independent archive segment")
        aad = pack(("archive segment", self.group, position))
        ciphertext = crypto.seal(key, (checkpoint.wire(), context,
                                      original_signature, roster.proof(author.name).wire()), aad)
        selector = digest(b"archive ciphertext", ciphertext)
        segment = Segment(position, selector, key, checkpoint.policy, checkpoint.identifier)
        service.put(route, capability, Record(selector, ciphertext, expires=expires), meter)
        self.segments[position] = segment
        return segment

    def grant(self, crypto, admission, roster, inviter, recipient, public_ticket,
              start, stop, admitted_at):
        if admission.group != self.group or admission.policy.history == "NONE":
            raise ValueError("admission policy does not permit history")
        if (admitted_at != admission.history_boundary or
                not 0 <= start < stop <= admitted_at or stop - start > 2048):
            raise ValueError("invalid or oversized history range")
        if recipient.name not in roster.by_name or roster.by_name[recipient.name] != recipient:
            raise ValueError("recipient is not admitted")
        author = next((c for c in roster.credentials if c.public == inviter.public), None)
        if author is None:
            raise ValueError("history inviter is not a current member")
        entries = []
        for position in range(start, stop):
            segment = self.segments.get(position)
            if segment is None:
                raise ValueError("history is unavailable; no live-root recovery")
            for policy in (segment.policy, admission.policy):
                if policy.history == "NONE" or (policy.history == "WINDOW" and position < admitted_at - policy.window):
                    raise ValueError("grant broadens authenticated history policy")
            entries.append((position, segment.selector, segment.key))
        body = pack(("history grant", self.group, admission.identifier, admission.policy.value(),
                     recipient.body(), start, stop, admitted_at, tuple(entries), author.body(),
                     roster.proof(author.name).wire(), roster.proof(recipient.name).wire()))
        signed = crypto.sign(inviter, body)
        aad = pack(("history grant", self.group, admission.identifier, recipient.name))
        return crypto.seal_to(public_ticket, (body, signed), aad)


@dataclass
class ArchiveReader:
    group: bytes
    recipient: Credential
    admission: Checkpoint
    private_ticket: bytes
    access: dict = field(default_factory=dict)
    consumed: bool = False

    def accept(self, crypto, ciphertext):
        if self.consumed:
            raise ValueError("history grant capability already consumed")
        aad = pack(("history grant", self.group, self.admission.identifier, self.recipient.name))
        body, signature = crypto.open_with(self.private_ticket, ciphertext, aad)
        (kind, group, admission_id, policy, recipient_raw, start, stop, admitted_at,
         entries, author_raw, author_proof, recipient_proof) = unpack(body)
        # The recipient's pinned profile selects the credential encoding; do
        # not guess a schema from untrusted input or drop blinded leaf fields.
        credential_type = type(self.recipient)
        recipient, author = credential_type.read(recipient_raw), credential_type.read(author_raw)
        if (kind != "history grant" or group != self.group or
                admission_id != self.admission.identifier or policy != self.admission.policy.value() or
                recipient != self.recipient or
                not self.admission.verify_credential(author, Proof(*unpack(author_proof))) or
                not self.admission.verify_credential(recipient, Proof(*unpack(recipient_proof))) or
                not crypto.verify(author.public, body, signature) or
                self.admission.policy.history == "NONE" or
                admitted_at != self.admission.history_boundary or
                not 0 <= start < stop <= admitted_at or stop - start > 2048 or
                tuple(e[0] for e in entries) != tuple(range(start, stop)) or
                any(len(key) != 32 or len(selector) != 32 for _, selector, key in entries) or
                (self.admission.policy.history == "WINDOW" and start < admitted_at - self.admission.policy.window)):
            raise ValueError("invalid or overbroad history grant")
        self.access.update((position, (selector, key, admitted_at)) for position, selector, key in entries)
        self.private_ticket = b""
        self.consumed = True

    def read(self, crypto, governance, log_public, service, route, capability, position, meter=None):
        if position not in self.access:
            raise ValueError("message outside granted range")
        selector, key, admitted_at = self.access[position]
        ciphertext = service.get(route, capability, selector, meter).ciphertext
        if digest(b"archive ciphertext", ciphertext) != selector:
            raise ValueError("wrong archive object")
        raw_checkpoint, context, signature, proof_raw = crypto.open(
            key, ciphertext, pack(("archive segment", self.group, position)))
        checkpoint = Checkpoint.read(raw_checkpoint)
        verify_checkpoint(crypto, governance, log_public, checkpoint, self.group)
        kind, group, era, pos, policy, author_raw, payload = unpack(context)
        author = type(self.recipient).read(author_raw)
        if (kind != "archive message" or group != self.group or era != checkpoint.identifier or
                pos != position or policy != checkpoint.policy.value() or
                not checkpoint.history_boundary <= position < admitted_at or
                checkpoint.number >= self.admission.number or
                not checkpoint.verify_credential(author, Proof(*unpack(proof_raw))) or
                not crypto.verify(author.public, context, signature) or
                checkpoint.policy.history == "NONE" or
                (checkpoint.policy.history == "WINDOW" and position < admitted_at - checkpoint.policy.window)):
            raise ValueError("invalid original authorship or historical policy")
        return author.name, payload
