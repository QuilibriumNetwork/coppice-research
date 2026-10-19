"""Bounded canonical research encoding and context-bound Merkle proofs.

This is a candidate model schema, not the Coppice interoperability format.
Only explicit byte strings cross the simulated service boundary.
"""
from dataclasses import dataclass
from core import digest, u64

LIMIT = 8 * 1024**2
DEPTH = 24


def pack(value, depth=0):
    if depth > DEPTH:
        raise ValueError("encoding depth")
    if value is None:
        result = b"n"
    elif type(value) is bool:
        result = b"t" if value else b"f"
    elif type(value) is int:
        result = b"i" + u64(value)
    elif isinstance(value, (bytes, str)):
        data = value.encode("utf8") if isinstance(value, str) else value
        result = (b"s" if isinstance(value, str) else b"b") + len(data).to_bytes(4, "big") + data
    elif isinstance(value, (list, tuple)):
        result = b"l" + len(value).to_bytes(4, "big") + b"".join(pack(v, depth + 1) for v in value)
    elif isinstance(value, dict):
        items = sorted((pack(k, depth + 1), pack(v, depth + 1)) for k, v in value.items())
        result = b"d" + len(items).to_bytes(4, "big") + b"".join(k + v for k, v in items)
    else:
        raise ValueError("unsupported wire type")
    if len(result) > LIMIT:
        raise ValueError("encoding size")
    return result


def unpack(data, max_bytes=LIMIT):
    if not isinstance(data, bytes) or len(data) > max_bytes:
        raise ValueError("wire byte limit")
    cursor = 0

    def take(n):
        nonlocal cursor
        if n > len(data) - cursor:
            raise ValueError("truncated encoding")
        result = data[cursor:cursor + n]
        cursor += n
        return result

    def read(depth=0):
        if depth > DEPTH:
            raise ValueError("decoding depth")
        tag = take(1)
        if tag in (b"n", b"t", b"f"):
            return {b"n": None, b"t": True, b"f": False}[tag]
        if tag == b"i":
            return int.from_bytes(take(8), "big")
        if tag not in (b"b", b"s", b"l", b"d"):
            raise ValueError("unknown wire type")
        count = int.from_bytes(take(4), "big")
        if count > len(data) - cursor:
            raise ValueError("length/count exceeds remaining input")
        if tag in (b"b", b"s"):
            raw = take(count)
            try:
                return raw.decode("utf8") if tag == b"s" else raw
            except UnicodeDecodeError as error:
                raise ValueError("invalid UTF8") from error
        if tag == b"l":
            return tuple(read(depth + 1) for _ in range(count))
        values, previous = {}, None
        for _ in range(count):
            key = read(depth + 1)
            encoded = pack(key)
            if previous is not None and encoded <= previous:
                raise ValueError("duplicate or unordered map key")
            previous = encoded
            try:
                if key in values:
                    raise ValueError("ambiguous map key")
                values[key] = read(depth + 1)
            except TypeError as error:
                raise ValueError("unhashable map key") from error
        return values

    result = read()
    if cursor != len(data) or pack(result) != data:
        raise ValueError("noncanonical encoding")
    return result


@dataclass(frozen=True)
class Proof:
    index: int
    count: int
    siblings: tuple

    def wire(self):
        return pack((self.index, self.count, self.siblings))


class Merkle:
    def __init__(self, leaves, context):
        if not leaves or len(leaves) > 1_000_000:
            raise ValueError("invalid Merkle leaf count")
        self.count, self.context = len(leaves), context
        width = 1 << (self.count - 1).bit_length()
        level = [digest(b"merkle leaf", context, u64(i), u64(self.count), body)
                 for i, body in enumerate(leaves)]
        level.extend(digest(b"merkle padding", context, u64(i), u64(self.count))
                     for i in range(self.count, width))
        self.levels = [level]
        while len(level) > 1:
            level = [digest(b"merkle node", context, level[i], level[i + 1])
                     for i in range(0, len(level), 2)]
            self.levels.append(level)
        self.root = level[0]

    def proof(self, index):
        if not 0 <= index < self.count:
            raise ValueError("invalid proof index")
        position, path = index, []
        for level in self.levels[:-1]:
            path.append(level[position ^ 1])
            position //= 2
        return Proof(index, self.count, tuple(path))

    @staticmethod
    def verify(body, proof, root, context):
        if (not 0 < proof.count <= 1_000_000 or not 0 <= proof.index < proof.count or
                len(proof.siblings) != (proof.count - 1).bit_length() or
                any(len(s) != 32 for s in proof.siblings)):
            return False
        value = digest(b"merkle leaf", context, u64(proof.index), u64(proof.count), body)
        position = proof.index
        for sibling in proof.siblings:
            pair = (sibling, value) if position & 1 else (value, sibling)
            value = digest(b"merkle node", context, *pair)
            position //= 2
        return value == root
