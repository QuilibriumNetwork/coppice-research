"""Reproducible experiment harness. This object is NOT an endpoint or service.

It deliberately owns fixture identities, the ideal crypto oracle, and the
trusted log. Adversary snapshots must select endpoint state, not this harness.
"""
from ideal import IdealCrypto
from membership import Policy, Credential, Roster, Governance, FinalityLog
from resumption import Inbox, EntryBuilder, publish_entries, resume, authorize_sender
from service import DeliveryService, Meter, Record
from wire import pack
from core import digest


class Lab:
    def __init__(self, names=("alice", "bob", "carol", "dave"), seed=b"lab"):
        self.crypto = IdealCrypto(seed)
        self.group = self.crypto.fresh(b"group")
        self.route = self.crypto.fresh(b"group route")
        self.guardian = self.crypto.signer()
        self.governance = Governance([self.guardian.public])
        self.log = FinalityLog(self.crypto, self.governance, self.group)
        self.service = DeliveryService(quota=1_000_000)
        self.signers, self.inboxes, self.sessions = {}, {}, {}
        self.reserved = set()
        self.checkpoint, self.roster = None, None
        self.now = 0
        self.entry_upload, self.inventory_upload = Meter(), Meter()
        self.inventory_fetch = Meter()
        self.ticket_pools = {}
        self.directory_route = self.crypto.fresh(b"enrollment directory route")
        self.directory_cap = self.crypto.fresh(b"enrollment directory capability")
        self.directory_key = self.crypto.fresh(b"enrollment bootstrap secret")
        self.service.register(self.directory_route, self.directory_cap)
        for name in names:
            self.add_identity(name)

    def add_identity(self, name):
        self.signers[name] = self.crypto.signer()
        self.inboxes[name] = Inbox.create(self.crypto, self.service)

    def provision(self, name, count, preparer=None):
        """Explicit ONLINE action before an absence; never called for an offline member."""
        preparer = next(iter(self.signers)) if preparer is None else preparer
        issuer = self.signers[preparer].public
        pool = self.ticket_pools.setdefault((name, issuer), [])
        credential = Credential(name, self.signers[name].public, 0)
        for _ in range(count):
            ticket = self.inboxes[name].issue(self.crypto, self.group, credential,
                                             self.signers[name], issuer)
            aad = pack((self.group, "entry inventory"))
            opaque = self.crypto.seal(self.directory_key, (ticket.body(), ticket.signature), aad)
            selector = digest(b"ticket publication", opaque)
            self.service.put(self.directory_route, self.directory_cap,
                             Record(selector, opaque, expires=self.now + 30 * 86400), self.inventory_upload)
            pool.append((ticket, selector))

    def epoch(self, names=None, policy=None, online=None, history_boundary=None):
        names = tuple(self.signers) if names is None else tuple(names)
        policy = Policy() if policy is None else policy
        online = names if online is None else tuple(online)
        if history_boundary is None:
            history_boundary = 0 if self.checkpoint is None else self.checkpoint.history_boundary
        roster = Roster(self.group, [Credential(name, self.signers[name].public, i,
                                              f"shard-{i // 78}") for i, name in enumerate(names)])
        preparer = self.signers[names[0]]
        selected = {}
        for name in names:
            pool = self.ticket_pools.setdefault((name, preparer.public), [])
            if not pool and name in online:
                self.provision(name, 1, names[0])
            if not pool:
                raise LookupError("offline entry inventory exhausted")
            selected[name] = pool[0]
        builder = EntryBuilder(self.crypto, self.group, roster, policy, self.checkpoint,
                               preparer, self.governance, [self.guardian], self.log,
                               self.route, history_boundary)
        self.last_tickets = {}
        for name in names:
            ticket, selector = selected[name]
            self.ticket_pools[name, preparer.public].pop(0)
            self.last_tickets[name] = ticket
            self.service.get(self.directory_route, self.directory_cap, selector, self.inventory_fetch)
            builder.prepare(ticket, self.reserved)
        self.checkpoint = publish_entries(self.service, builder, self.inboxes, self.entry_upload,
                                         expires=self.now + 30 * 86400)
        self.roster = roster
        self.last_builder = builder
        for name in online:
            self.return_device(name)
        return self.checkpoint

    def return_device(self, name, meter=None):
        # Known identity is cached; membership proof and current index arrive in entry.
        own = Credential(name, self.signers[name].public, 0)
        result = resume(self.crypto, self.governance, self.log, self.service, self.group,
                        own, self.inboxes[name], self.sessions.get(name), meter)
        self.sessions[name] = result
        result.ratchet.expire_skipped(self.now)
        self.service.register(result.route, result.delivery_capability)
        return result

    def learn_sender(self, recipient, sender):
        authorize_sender(self.sessions[recipient], self.roster.by_name[sender], self.roster.proof(sender))

    def credentials(self):
        return {name: c.public for name, c in self.roster.by_name.items()}
