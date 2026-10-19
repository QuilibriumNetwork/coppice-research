"""Symbolic Coppice ratchets and single-use capabilities; not real cryptography.

All plaintext/key fields on Message, Contribution, DeliverySlot and TicketBox
are test oracles. They must never be serialized to the delivery service.
"""
from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import shake_256
import math

SUITE = b"COPPICE3_NTRUHPS2048677_FALCON512_PADDED_SHAKE256_CHACHA20POLY1305"
GROUP = b"test-group"
ERA = b"membership-era-1"
MEMBERS = {"alice": 0, "bob": 1, "carol": 2, "dave": 3}


def u64(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("invalid uint64")
    return value.to_bytes(8, "big")


def encode(*parts):
    return len(parts).to_bytes(4, "big") + b"".join(
        len(part).to_bytes(4, "big") + part for part in parts
    )


def digest(label, *parts):
    return shake_256(encode(b"Coppice/3 hash", label, *parts)).digest(32)


def kdf(secret, label, context, length=32):
    return shake_256(encode(
        b"Coppice/3 derive", SUITE, secret, label, context,
        length.to_bytes(4, "big"),
    )).digest(length)


class SecretFrontier:
    def __init__(self, seed, era, leaves, role=b"application"):
        if leaves < 1:
            raise ValueError("empty secret tree")
        self.era = era
        self.role = role
        self.leaves = leaves
        self.depth = math.ceil(math.log2(max(1, leaves)))
        self.nodes = {(0, 0): seed}
        self.opened = set()

    def open(self, index):
        if not 0 <= index < self.leaves or index in self.opened:
            raise ValueError("invalid or already consumed leaf")
        for depth in range(self.depth + 1):
            node_index = index >> (self.depth - depth)
            if (depth, node_index) in self.nodes:
                break
        else:
            raise ValueError("leaf has no remaining derivation capability")
        parent = self.nodes.pop((depth, node_index))
        while depth < self.depth:
            children = [kdf(parent, b"tree child", encode(
                self.era, self.role, u64(depth), u64(node_index), u64(bit),
            )) for bit in (0, 1)]
            wanted = (index >> (self.depth - depth - 1)) & 1
            sibling = node_index * 2 + (1 - wanted)
            # Padding-only subtrees must not survive after every real leaf is
            # consumed, nor inflate the frontier's useful-node storage bound.
            if sibling << (self.depth - depth - 1) < self.leaves:
                self.nodes[(depth + 1, sibling)] = children[1 - wanted]
            parent = children[wanted]
            node_index = node_index * 2 + wanted
            depth += 1
        self.opened.add(index)
        return parent

    def covers(self, leaf):
        return any(leaf >> (self.depth - depth) == index for depth, index in self.nodes)


@dataclass(frozen=True)
class Contribution:
    era: bytes
    name: bytes
    delta: bytes
    group: bytes = GROUP
    event_id: bytes = b""

    @property
    def identifier(self):
        if self.event_id:
            return self.event_id
        return digest(b"model contribution", self.group, self.era, self.name, self.delta)


@dataclass(frozen=True)
class Update:
    era: bytes
    sender: str
    generation: int
    previous: bytes
    final_counter: int
    references: tuple
    nonce: bytes
    group: bytes = GROUP

    @property
    def body(self):
        closing = b"\x00" if self.final_counter == -1 else b"\x01" + u64(self.final_counter)
        return encode(self.group, self.era, self.sender.encode(), u64(self.generation),
                      self.previous, closing, encode(*self.references), self.nonce)

    @property
    def identifier(self):
        return digest(b"sender update", self.body)


@dataclass
class Lane:
    init: bytes
    chain: bytes
    head: bytes
    generation: int = 0
    counter: int = 0
    incorporated: set = field(default_factory=set)


@dataclass(frozen=True)
class Message:
    era: bytes
    sender: str
    generation: int
    counter: int
    key: bytes  # Test oracle only; never a real wire field.
    group: bytes = GROUP


class DeferredUpdate(Exception):
    """A valid update currently exceeds local unconsumed-key capacity."""


class ReplayGap(LookupError):
    """Explicitly expired unread state; not evidence against a sender."""


class Client:
    def __init__(self, seed=b"s" * 32, era=ERA, max_skip=8, max_pending=32,
                 members=None, group=GROUP, leaf_count=None,
                 max_frontier_bytes=16 * 1024**2, max_pending_bytes=8 * 1024**2,
                 max_skip_sender=256, skip_ttl=1800):
        self.era = era
        self.group = group
        self.members = dict(MEMBERS if members is None else members)
        self.leaf_count = len(self.members) if leaf_count is None else leaf_count
        indices = list(self.members.values())
        if (not indices or len(set(indices)) != len(indices) or
                any(type(i) is not int or not 0 <= i < self.leaf_count for i in indices)):
            raise ValueError("invalid roster indices")
        self.frontier = SecretFrontier(seed, era, self.leaf_count)
        self.lanes = {}
        self.entropy = {}
        self.metadata = {}
        self.seen_entropy = set()
        self.tickets = {}
        self.consumed_tickets = {}
        self.known_updates = {}
        self.pending = {}
        self.frozen = set()
        self.control_errors = []
        self.skipped = {}
        self.skipped_at = {}
        self.expired_skipped = set()
        self.expired_entropy = set()
        self.replay_gaps = {}
        self.now = 0
        self.max_skip = max_skip
        self.max_pending = max_pending
        self.max_pending_bytes = max_pending_bytes
        self.max_frontier_bytes = max_frontier_bytes
        self.max_skip_sender = max_skip_sender
        self.skip_ttl = skip_ttl

    @property
    def frontier_bytes(self):
        return 32 * (len(self.frontier.nodes) +
                     sum(len(tree.nodes) for tree in self.entropy.values()))

    def check_frontier_budget(self):
        if self.frontier_bytes > self.max_frontier_bytes:
            raise DeferredUpdate("secret frontier quota")

    def expire_skipped(self, now):
        if now < self.now:
            raise ValueError("local clock moved backwards")
        self.now = now
        for position, created in list(self.skipped_at.items()):
            if now - created >= self.skip_ttl:
                self.skipped.pop(position, None)
                self.expired_skipped.add(position)
                del self.skipped_at[position]
        self.drain()

    def abandon_entropy(self, identifier):
        """Explicit operator/policy decision, sacrificing all remaining unread leaves."""
        if identifier not in self.entropy:
            raise ValueError("unknown entropy event")
        self.entropy[identifier].nodes.clear()
        self.expired_entropy.add(identifier)
        self.drain()

    def remember_skipped(self, position, key):
        self.skipped[position] = key
        self.skipped_at[position] = self.now

    def check_skipped_budget(self, sender, additional):
        if (len(self.skipped) + additional > self.max_skip or
                sum(p[0] == sender for p in self.skipped) + additional > self.max_skip_sender):
            raise DeferredUpdate("skipped-key quota")

    def context(self, sender, generation):
        return encode(self.group, self.era, sender.encode(), b"application", u64(generation))

    def lane(self, sender):
        if sender not in self.members:
            raise ValueError("unauthorized device")
        if sender not in self.lanes:
            tree = deepcopy(self.frontier)
            leaf = tree.open(self.members[sender])
            if self.frontier_bytes + 32 * (len(tree.nodes) - len(self.frontier.nodes)) > self.max_frontier_bytes:
                raise DeferredUpdate("secret frontier quota")
            self.frontier = tree
            context = self.context(sender, 0)
            self.lanes[sender] = Lane(
                kdf(leaf, b"lane init", context),
                kdf(leaf, b"message chain", context),
                digest(b"lane genesis", context),
            )
        return self.lanes[sender]

    def add_contribution(self, event):
        if event.era != self.era or event.group != self.group:
            raise ValueError("wrong contribution era")
        # Abstract authenticated delivery boundary. Real callers use a consumed
        # ticket; existing state-machine tests inject verified plaintext here.
        if event.identifier in self.seen_entropy:
            return
        if self.frontier_bytes + 32 > self.max_frontier_bytes:
            raise DeferredUpdate("secret frontier quota")
        self.seen_entropy.add(event.identifier)
        self.metadata[event.identifier] = kdf(
            event.delta, b"contribution metadata", event.identifier)
        seed = kdf(event.delta, b"contribution tree", event.identifier)
        self.entropy[event.identifier] = SecretFrontier(
            seed, event.identifier, self.leaf_count, b"group entropy")
        # No event object, raw delta, or separate seed copy is kept in state.
        self.drain()

    def install_ticket(self, ticket):
        if ticket.identifier in self.consumed_tickets:
            raise ValueError("cannot restore consumed ticket")
        if ticket.identifier in self.tickets:
            raise ValueError("duplicate ticket installation")
        self.tickets[ticket.identifier] = ticket

    def receive_slot(self, slot, signature_ok=True):
        if not signature_ok or slot.event.era != self.era:
            raise ValueError("unauthenticated or wrong-era delivery")
        prior = self.consumed_tickets.get(slot.ticket_id)
        if prior is not None:
            if prior != slot.event.identifier:
                raise ValueError("ticket reused for conflicting contribution")
            return  # Never reinstall a punctured frontier.
        ticket = self.tickets.get(slot.ticket_id)
        if ticket is None:
            raise ValueError("missing or erased ticket")
        if slot.author != ticket.owner or slot.purpose != ticket.purpose:
            raise ValueError("ticket assignment mismatch")
        value = slot.open(ticket.secret)
        staged = deepcopy(self)
        del staged.tickets[slot.ticket_id]
        staged.consumed_tickets[slot.ticket_id] = value.identifier
        staged.add_contribution(value)
        self.__dict__.update(staged.__dict__)

    def make_update(self, sender, references, nonce=b"test-update-nonce"):
        lane = self.lane(sender)
        references = tuple(sorted(references))
        return Update(self.era, sender, lane.generation + 1, lane.head,
                      lane.counter - 1, references, nonce, self.group)

    def receive_update(self, event):
        if event.group != self.group or event.era != self.era or event.sender not in self.members:
            raise ValueError("wrong era or unauthorized author")
        if not event.references or tuple(sorted(set(event.references))) != event.references:
            raise ValueError("noncanonical entropy set")
        if not 1 <= event.generation < 2**64 or not -1 <= event.final_counter < 2**64 - 1:
            raise ValueError("invalid generation or closing counter")
        key = (event.sender, event.generation)
        prior = self.known_updates.get(key)
        if prior is not None:
            if prior != event.identifier:
                self.frozen.add(event.sender)
                raise ValueError("producer equivocation")
            return  # Duplicate, including already-applied updates.
        if event.sender in self.frozen:
            raise ValueError("frozen producer")
        if len(self.pending) >= self.max_pending:
            raise ValueError("pending control quota")
        if sum(len(e.body) + 666 for e in self.pending.values()) + len(event.body) + 666 > self.max_pending_bytes:
            raise ValueError("pending control byte quota")
        self.known_updates[key] = event.identifier
        self.pending[key] = event
        self.drain()

    def drain(self):
        progress = True
        while progress:
            progress = False
            for key, event in list(self.pending.items()):
                if event.sender in self.frozen:
                    continue
                if any(ref not in self.entropy for ref in event.references):
                    continue
                current = self.lanes.get(event.sender)
                generation = 0 if current is None else current.generation
                if event.generation != generation + 1:
                    continue
                # Stage every derivation so failure cannot consume roots or keys.
                staged = deepcopy(self)
                try:
                    staged.apply_ready_update(event)
                except DeferredUpdate:
                    continue
                except ReplayGap as error:
                    self.replay_gaps[event.identifier] = str(error)
                    del self.pending[key]
                    progress = True
                    continue
                except ValueError as error:
                    self.frozen.add(event.sender)
                    self.control_errors.append((event.identifier, str(error)))
                    del self.pending[key]
                    progress = True
                    continue
                del staged.pending[key]
                self.__dict__.update(staged.__dict__)
                progress = True

    def apply_ready_update(self, event):
        lane = self.lane(event.sender)
        if event.previous != lane.head:
            raise ValueError("wrong predecessor")
        if lane.incorporated.intersection(event.references):
            raise ValueError("entropy repeated in same lane")
        if self.expired_entropy.intersection(event.references):
            raise ReplayGap("unused entropy explicitly expired")
        if event.final_counter < lane.counter - 1:
            raise ValueError("closing counter contradicts consumed messages")
        remaining = event.final_counter - lane.counter + 1
        self.check_skipped_budget(event.sender, remaining)
        while lane.counter <= event.final_counter:
            counter = lane.counter
            self.remember_skipped((event.sender, lane.generation, counter), self.step(event.sender))
        pairs = []
        for ref in event.references:
            leaf = self.entropy[ref].open(self.members[event.sender])
            lane_id = encode(self.group, self.era, event.sender.encode(), b"application")
            lane_input = kdf(leaf, b"lane entropy", encode(ref, lane_id))
            pairs.append(encode(ref, lane_input))
        mix = digest(b"entropy mix", encode(*pairs))
        root = kdf(encode(lane.init, mix), b"lane update", event.body)
        context = self.context(event.sender, event.generation)
        lane.init = kdf(root, b"lane init", context)
        lane.chain = kdf(root, b"message chain", context)
        lane.head = event.identifier
        lane.generation = event.generation
        lane.counter = 0
        lane.incorporated.update(event.references)
        self.check_frontier_budget()

    def step(self, sender):
        lane = self.lane(sender)
        if lane.counter >= 2**64 - 1:
            raise ValueError("counter exhausted; new lane required")
        context = encode(self.context(sender, lane.generation), u64(lane.counter))
        result = kdf(lane.chain, b"message key", context, 44)
        lane.chain = kdf(lane.chain, b"chain step", context)
        lane.counter += 1
        return result

    def send(self, sender):
        if sender in self.frozen:
            raise ValueError("frozen producer")
        lane = self.lane(sender)
        generation, counter = lane.generation, lane.counter
        return Message(self.era, sender, generation, counter, self.step(sender), self.group)

    def receive(self, message, signature_ok=True):
        staged = deepcopy(self)
        staged.receive_candidate(message, signature_ok)
        self.__dict__.update(staged.__dict__)
        self.drain()

    def receive_candidate(self, message, signature_ok):
        if message.era != self.era or message.group != self.group:
            raise ValueError("wrong message era")
        if not 0 <= message.counter < 2**64 - 1 or not 0 <= message.generation < 2**64:
            raise ValueError("invalid message position")
        if message.sender in self.frozen:
            raise ValueError("frozen producer")
        lane = self.lane(message.sender)
        position = (message.sender, message.generation, message.counter)
        if position in self.expired_skipped:
            raise ValueError("expired unread message key: explicit replay gap")
        if position in self.skipped:
            candidate = self.skipped.pop(position)
            self.skipped_at.pop(position, None)
        else:
            if message.generation != lane.generation or message.counter < lane.counter:
                raise ValueError("missing generation or consumed counter")
            gap = message.counter - lane.counter
            try:
                self.check_skipped_budget(message.sender, gap)
            except DeferredUpdate as error:
                raise ValueError(str(error)) from error
            while lane.counter < message.counter:
                skipped_position = (message.sender, lane.generation, lane.counter)
                self.remember_skipped(skipped_position, self.step(message.sender))
            candidate = self.step(message.sender)
        if candidate != message.key or not signature_ok:
            raise ValueError("authentication failed")


@dataclass(frozen=True)
class DeliveryTicket:
    owner: str
    index: int
    secret: bytes
    purpose: bytes = b"group entropy"

    @property
    def public_key(self):
        return digest(b"symbolic public key", self.secret)

    @property
    def identifier(self):
        return digest(b"ticket", self.owner.encode(), u64(self.index),
                      self.purpose, self.public_key)


@dataclass(frozen=True)
class DeliverySlot:
    ticket_id: bytes
    public_key: bytes
    author: str
    purpose: bytes
    event: Contribution  # Plaintext oracle, not a real wire field.
    valid: bool = True

    def open(self, capability):
        if (capability is None or not self.valid or
                digest(b"symbolic public key", capability) != self.public_key):
            raise ValueError("cannot open symbolic ciphertext")
        return self.event


class TicketOutbox:
    """Durable assignment/reservation model; no delivery-server allocator."""

    def __init__(self, author):
        self.author = author
        self.reserved = set()
        self.outbox = {}

    def seal(self, ticket, event, crash_after_reservation=False):
        if ticket.owner != self.author or ticket.identifier in self.reserved:
            raise ValueError("wrong producer or ticket already reserved")
        self.reserved.add(ticket.identifier)
        if crash_after_reservation:
            raise ValueError("simulated crash after durable reservation")
        slot = DeliverySlot(ticket.identifier, ticket.public_key,
                            self.author, ticket.purpose, event)
        self.outbox[event.identifier] = slot
        return slot

    def retry(self, event_id):
        return self.outbox[event_id]


class TicketBoxLane:
    """Symbolic shared-ticket box: wrap key and future state are siblings.

    The caller supplies a consumed producer-specific healing leaf. This models
    the box lifecycle only, not actual NTRU/Falcon or full shard consensus.
    """

    def __init__(self, init):
        self.init = init
        self.imported = set()
        self.tickets = {}

    def material(self, leaf, core):
        root = kdf(encode(self.init, leaf), b"model producer update", core)
        return (kdf(root, b"producer init", core),
                kdf(root, b"shard ticket box", core))

    def accept(self, box, leaf):
        if box.core in self.imported:
            return
        following, key = self.material(leaf, box.core)
        tickets = box.open(key)
        if any(t.identifier in self.tickets for t in tickets):
            raise ValueError("duplicate private ticket")
        self.tickets.update((t.identifier, t) for t in tickets)
        self.init = following
        self.imported.add(box.core)


@dataclass(frozen=True)
class TicketBox:
    core: bytes
    key_commitment: bytes
    tickets: tuple  # Oracle only, standing in for encrypted key-box plaintext.

    def open(self, key):
        if digest(b"symbolic box key", key) != self.key_commitment:
            raise ValueError("cannot reopen box")
        return self.tickets


class AdmissionCapability:
    """Symbolic single-use prekey lifecycle, without modeling its KEM."""

    def __init__(self, plan, seed):
        self.plan, self.seed = plan, seed

    def accept(self, plan):
        if plan != self.plan or self.seed is None:
            raise ValueError("wrong plan or consumed admission capability")
        result, self.seed = self.seed, None
        return result


def receiving_partition(members, published_holder_sets):
    """Model coverage and removal exclusion, not key/identity authentication."""
    uncovered = set(members)
    slots = []
    for holders in published_holder_sets:
        holders = frozenset(holders)
        if holders and holders <= uncovered:
            slots.append(holders)
            uncovered.difference_update(holders)
    slots.extend(frozenset([member]) for member in sorted(uncovered))
    return slots


def header_material(base, fields, ciphertext):
    return kdf(base, b"sender envelope", encode(
        fields, digest(b"body ciphertext", ciphertext),
    ), 44)


