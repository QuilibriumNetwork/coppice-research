"""Opaque delivery/storage with explicit device-byte and retention accounting."""
from dataclasses import dataclass, field
from core import digest
from wire import pack, unpack, Proof


@dataclass
class Meter:
    upload: int = 0
    download: int = 0
    round_trips: int = 0
    categories: dict = field(default_factory=dict)

    def charge(self, category, request, response=b""):
        # Research request padding; the integration's IP-hiding costs excluded.
        up = ((len(request) + 127) // 128) * 128
        down = ((len(response) + 127) // 128) * 128 if response else 0
        self.upload += up
        self.download += down
        self.round_trips += 1
        old = self.categories.setdefault(category, [0, 0])
        old[0] += up
        old[1] += down

    def report(self):
        return dict(upload_bytes=self.upload, download_bytes=self.download,
                    round_trips=self.round_trips, categories=self.categories)


@dataclass(frozen=True)
class Record:
    selector: bytes
    ciphertext: bytes
    dependencies: tuple = ()
    expires: int = 30 * 86400


class DeliveryService:
    """Has no IdealCrypto reference, plaintext records, author keys or accounts.

Routes/capabilities may be linkable. They identify a destination, never a
unique submitting member. The harness associates meters with devices; that
association is not sent to or stored by the service.
"""
    def __init__(self, quota=100_000):
        self.routes, self.records, self.traces, self.withheld = {}, {}, [], set()
        self.quota, self.usage = quota, {}

    def register(self, route, capability):
        self.routes[route] = capability

    def authorize(self, route, capability, headers):
        # This API is also the model's client request boundary: identifying
        # headers are rejected BEFORE serialization/transmission. A real server
        # rejecting an already received identifying header would not hide it.
        if headers:
            raise ValueError("application identifying headers forbidden")
        if self.routes.get(route) != capability or capability is None:
            raise ValueError("missing delivery capability; no account fallback")

    def put(self, route, capability, record, meter=None, headers=None):
        self.authorize(route, capability, headers)
        key = (route, record.selector)
        if (not isinstance(record.ciphertext, bytes) or len(record.selector) != 32 or
                any(len(d) != 32 for d in record.dependencies)):
            raise ValueError("invalid opaque record")
        request = pack(("put", route, capability, record.selector,
                        record.ciphertext, record.dependencies, record.expires))
        if key in self.records:
            if self.records[key] != record:
                raise ValueError("immutable object conflict")
        else:
            if self.usage.get(route, 0) >= self.quota:
                raise ValueError("aggregate route quota")
            self.records[key] = record
            self.usage[route] = self.usage.get(route, 0) + 1
        self.traces.append(request)
        if meter is not None:
            meter.charge("publish", request)

    def get(self, route, capability, selector, meter=None, headers=None):
        self.authorize(route, capability, headers)
        request = pack(("get", route, capability, selector))
        self.traces.append(request)
        record = None if selector in self.withheld else self.records.get((route, selector))
        response = b"" if record is None else pack((record.selector, record.ciphertext, record.dependencies))
        if meter is not None:
            meter.charge("fetch", request, response)
        if record is None:
            raise LookupError("missing dependency")
        return record

    def get_many(self, route, capability, selectors, meter=None, headers=None):
        """One bounded request; missing objects are explicit, not silently filled.

        Selectors are opaque. This is batching, not PIR or access-pattern hiding.
        """
        self.authorize(route, capability, headers)
        if not 1 <= len(selectors) <= 256 or any(len(s) != 32 for s in selectors):
            raise ValueError("invalid batched lookup")
        request = pack(("get many", route, capability, tuple(selectors)))
        records = tuple(None if s in self.withheld else self.records.get((route, s))
                        for s in selectors)
        response = pack(tuple(None if r is None else (r.selector, r.ciphertext, r.dependencies)
                              for r in records))
        self.traces.append(request)
        if meter is not None:
            meter.charge("fetch batch", request, response)
        return records

    def merkle_proof(self, route, capability, root, index, count, meter=None):
        """Assemble a proof from public hashes of BLINDED credential leaves.

        The cover experiment uploads immutable hash nodes, never credential
        plaintexts. Root authentication and leaf checking remain client work.
        This reveals tree shape and requested positions; it is not PIR.
        """
        self.authorize(route, capability, None)
        if type(index) is not int or type(count) is not int or not 0 <= index < count <= 1_000_000:
            raise ValueError("invalid proof request")
        request = pack(("blinded roster proof", route, capability, root, index, count))
        self.traces.append(request)
        node, siblings = root, []
        try:
            for bit in reversed(range((count - 1).bit_length())):
                record = None if node in self.withheld else self.records.get((route, node))
                if record is None:
                    raise LookupError("missing directory node")
                left, right = unpack(record.ciphertext)
                if len(left) != 32 or len(right) != 32:
                    raise ValueError("invalid directory node")
                if (index >> bit) & 1:
                    siblings.append(left)
                    node = right
                else:
                    siblings.append(right)
                    node = left
            proof = Proof(index, count, tuple(reversed(siblings)))
        except (LookupError, ValueError):
            if meter is not None:
                meter.charge("roster proof", request)
            raise
        if meter is not None:
            meter.charge("roster proof", request, proof.wire())
        return proof

    def closure(self, route, selectors):
        pending, visited = list(selectors), set()
        while pending:
            item = pending.pop()
            if item in visited:
                continue
            record = self.records.get((route, item))
            if record is None:
                raise LookupError("dependency closure incomplete")
            visited.add(item)
            pending.extend(record.dependencies)
        return visited

    def collect(self, now):
        keep = set()
        for route in self.routes:
            roots = [selector for (r, selector), obj in self.records.items()
                     if r == route and obj.expires > now]
            keep.update((route, selector) for selector in self.closure(route, roots))
        self.records = {k: v for k, v in self.records.items() if k in keep}

    def public_view(self):
        return pack((tuple(self.traces), tuple((route, selector, value.ciphertext,
                    value.dependencies, value.expires)
                    for (route, selector), value in sorted(self.records.items()))))

    @property
    def storage_bytes(self):
        return sum(len(v.ciphertext) + 32 * (1 + len(v.dependencies)) for v in self.records.values())
