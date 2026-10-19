"""Authenticated membership under an explicit trusted-finality model.

Authorization uses a fixed, pinned guardian policy independent of device
credentials. Finality is an ideal consistent log, not a new BFT algorithm.
Neither assumption grants the delivery service member-insertion authority.
"""
from dataclasses import dataclass, replace
from core import digest
from wire import pack, unpack, Merkle, Proof


@dataclass(frozen=True)
class Policy:
    protection: str = "FS"
    history: str = "NONE"
    window: int = 0  # Authenticated message positions, not service timestamps.

    def __post_init__(self):
        if (self.protection != "FS" or self.history not in ("NONE", "WINDOW", "ALL_RETAINED") or
                type(self.window) is not int or self.window < 0 or
                (self.history == "WINDOW") != (self.window > 0)):
            raise ValueError("unsupported or inconsistent policy")

    def value(self):
        return self.protection, self.history, self.window


@dataclass(frozen=True)
class Credential:
    name: str
    public: bytes
    index: int
    shard: str = "shard-0"

    def body(self):
        return pack((self.name, self.public, self.index, self.shard))

    @classmethod
    def read(cls, raw):
        return cls(*unpack(raw))


class Roster:
    def __init__(self, group, credentials):
        self.group = group
        self.credentials = tuple(sorted(credentials, key=lambda c: c.index))
        if (not self.credentials or
                [c.index for c in self.credentials] != list(range(len(self.credentials))) or
                len({c.name for c in self.credentials}) != len(self.credentials) or
                len({c.public for c in self.credentials}) != len(self.credentials)):
            raise ValueError("invalid roster")
        self.by_name = {c.name: c for c in self.credentials}
        self.context = pack(("credential roster", group))
        self.tree = Merkle([c.body() for c in self.credentials], self.context)

    def proof(self, name):
        return self.tree.proof(self.by_name[name].index)

    def indices(self):
        return {c.name: c.index for c in self.credentials}


@dataclass(frozen=True)
class Checkpoint:
    group: bytes
    number: int
    previous: bytes
    roster_root: bytes
    count: int
    policy: Policy
    state_commitment: bytes
    nonce: bytes
    history_boundary: int = 0
    approvals: tuple = ()
    finality: bytes = b""

    def core(self):
        return pack((self.group, self.number, self.previous, self.roster_root,
                     self.count, self.policy.value(), self.state_commitment, self.nonce,
                     self.history_boundary))

    @property
    def identifier(self):
        return digest(b"research membership checkpoint", self.core())

    def wire(self):
        return pack((self.core(), self.approvals, self.finality))

    @classmethod
    def read(cls, wire):
        core, approvals, finality = unpack(wire)
        group, number, previous, root, count, policy, state, nonce, history_boundary = unpack(core)
        return cls(group, number, previous, root, count, Policy(*policy), state,
                   nonce, history_boundary, approvals, finality)

    def verify_credential(self, credential, proof):
        return (credential.index == proof.index and proof.count == self.count and
                Merkle.verify(credential.body(), proof, self.roster_root,
                              pack(("credential roster", self.group))))


class Governance:
    def __init__(self, public_keys, threshold=1):
        self.keys = frozenset(public_keys)
        if not 1 <= threshold <= len(self.keys):
            raise ValueError("invalid authorization threshold")
        self.threshold = threshold

    def authorize(self, crypto, checkpoint, signers):
        signatures = tuple((s.public, crypto.sign(s, checkpoint.core())) for s in signers)
        result = replace(checkpoint, approvals=signatures)
        self.verify(crypto, result)
        return result

    def verify(self, crypto, checkpoint):
        if checkpoint.count < 1 or checkpoint.number < 1:
            raise ValueError("invalid checkpoint")
        seen = set()
        for public, signature in checkpoint.approvals:
            if public in seen or public not in self.keys or not crypto.verify(public, checkpoint.core(), signature):
                raise ValueError("invalid membership authorization")
            seen.add(public)
        if len(seen) < self.threshold:
            raise ValueError("insufficient membership authorization")


class FinalityLog:
    def __init__(self, crypto, governance, group):
        self.crypto, self.governance, self.group = crypto, governance, group
        self.signer = crypto.signer()
        self.head = None
        self.records = {}

    def commit(self, checkpoint):
        self.governance.verify(self.crypto, checkpoint)
        if checkpoint.group != self.group:
            raise ValueError("wrong log group")
        if checkpoint.identifier in self.records:
            return self.records[checkpoint.identifier]
        previous = b"" if self.head is None else self.head.identifier
        number = 1 if self.head is None else self.head.number + 1
        if checkpoint.previous != previous or checkpoint.number != number:
            raise ValueError("membership fork or missing predecessor")
        if self.head is not None and checkpoint.history_boundary < self.head.history_boundary:
            raise ValueError("archive boundary rollback")
        final = replace(checkpoint, finality=self.crypto.sign(self.signer, checkpoint.identifier))
        self.records[final.identifier] = final
        self.head = final
        return final

    def latest(self, challenge):
        if self.head is None or len(challenge) != 32:
            raise ValueError("uninitialized log or invalid freshness challenge")
        body = pack((self.group, self.head.number, self.head.identifier, challenge))
        return body, self.crypto.sign(self.signer, body)


def verify_checkpoint(crypto, governance, log_public, checkpoint, group):
    governance.verify(crypto, checkpoint)
    if (checkpoint.group != group or
            not crypto.verify(log_public, checkpoint.identifier, checkpoint.finality)):
        raise ValueError("invalid checkpoint finality")


@dataclass(frozen=True)
class Publication:
    group: bytes
    era: bytes
    author: bytes
    sequence: int
    previous: bytes
    payload: bytes
    signature: bytes = b""

    def body(self):
        return pack((self.group, self.era, self.author, self.sequence, self.previous, self.payload))

    @property
    def identifier(self):
        return digest(b"research publication", self.body())


class ForkMonitor:
    """Authenticated observations; detection needs eventual view comparison.

Gossip is sent inside the ordinary encrypted control channel. A permanent
partition is intentionally an undetected negative-control scenario.
"""
    def __init__(self, group, era, allowed):
        self.group, self.era, self.allowed = group, era, frozenset(allowed)
        self.seen, self.frozen, self.evidence = {}, set(), []

    def observe(self, crypto, publication):
        p = publication
        if (p.group != self.group or p.era != self.era or p.author not in self.allowed or
                not crypto.verify(p.author, p.body(), p.signature)):
            raise ValueError("unauthorized publication")
        key = p.author, p.sequence
        previous = self.seen.get(key)
        if previous is not None and previous.identifier != p.identifier:
            self.frozen.add(p.author)
            self.evidence.append((previous, p))
            return False
        self.seen.setdefault(key, p)
        return p.author not in self.frozen

    def merge(self, crypto, publications):
        for publication in publications:
            self.observe(crypto, publication)
