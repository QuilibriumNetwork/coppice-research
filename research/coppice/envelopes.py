"""Sealed author/control records layered on the symbolic sender ratchet."""
from copy import deepcopy
from core import Message, digest, header_material
from wire import pack, unpack

CONTROL_TYPES = frozenset(("publication", "directory", "receipt", "attachment", "evidence", "update"))


def pad_body(value):
    raw = pack(value)
    framed = len(raw).to_bytes(4, "big") + raw
    size = len(framed)
    padded = ((size + 127) // 128) * 128 if size <= 2048 else 1 << (size - 1).bit_length()
    return framed + bytes(padded - size)


def unpad_body(body):
    if not isinstance(body, bytes) or len(body) < 4:
        raise ValueError("invalid padded body")
    size = int.from_bytes(body[:4], "big")
    if size > len(body) - 4 or any(body[4 + size:]):
        raise ValueError("invalid content padding")
    value = unpack(body[4:4 + size])
    if pad_body(value) != body:
        raise ValueError("noncanonical padding class")
    return value


def message_frame(crypto, client, sender, signer, metadata_key, payload, metadata_id=b""):
    staged = deepcopy(client)
    if metadata_id:
        if metadata_id not in staged.metadata:
            raise LookupError("missing contribution metadata dependency")
        metadata_key = staged.metadata[metadata_id]
    message = staged.send(sender)
    public = pack((client.group, client.era, "message", metadata_id))
    header = pack((sender, staged.lanes[sender].head, message.generation, message.counter))
    signed = pack((public, header, payload))
    signature = crypto.sign(signer, signed)
    body = crypto.seal(message.key, pad_body((payload, signature)), pack((public, header)))
    header_key = header_material(metadata_key, public, body)
    encrypted_header = crypto.seal(header_key, header, pack((public, digest(b"body ciphertext", body))))
    client.__dict__.update(staged.__dict__)
    return pack((public, encrypted_header, body))


def receive_frame(crypto, client, frame, metadata_key, credentials):
    public, encrypted_header, body = unpack(frame)
    group, era, kind, metadata_id = unpack(public)
    if (group, era, kind) != (client.group, client.era, "message"):
        raise ValueError("wrong application context")
    if metadata_id:
        if metadata_id not in client.metadata:
            raise LookupError("missing contribution metadata dependency")
        metadata_key = client.metadata[metadata_id]
    material = header_material(metadata_key, public, body)
    header = crypto.open(material, encrypted_header,
                         pack((public, digest(b"body ciphertext", body))))
    author, update_id, generation, counter = unpack(header)
    if author not in credentials or author not in client.members:
        raise LookupError("missing authenticated author credential")
    staged = deepcopy(client)
    position = author, generation, counter
    lane = staged.lane(author)
    if generation > lane.generation:
        raise LookupError("missing sender update dependency")
    expected = (digest(b"lane genesis", staged.context(author, 0)) if generation == 0
                else staged.known_updates.get((author, generation)))
    if update_id != expected:
        raise ValueError("sender update identifier mismatch")
    if position in staged.skipped:
        key = staged.skipped[position]
    else:
        if generation != lane.generation or counter < lane.counter:
            raise ValueError("missing dependency or consumed message")
        staged.check_skipped_budget(author, counter - lane.counter)
        while lane.counter < counter:
            pos = author, generation, lane.counter
            staged.remember_skipped(pos, staged.step(author))
        key = staged.step(author)
    payload, signature = unpad_body(crypto.open(key, body, pack((public, header))))
    if not crypto.verify(credentials[author], pack((public, header, payload)), signature):
        raise ValueError("invalid inner author signature")
    # Commit through the core receive transaction, retaining no decrypted copy.
    client.receive(Message(client.era, author, generation, counter, key, client.group))
    return author, payload


def seal_control(crypto, signer, metadata_key, group, era, kind, value):
    if kind not in CONTROL_TYPES:
        raise ValueError("unknown control type")
    nonce = crypto.fresh(b"control envelope nonce")
    context = pack((group, era, kind, nonce))
    inner = pack((signer.public, value))
    signature = crypto.sign(signer, pack((context, inner)))
    return pack((context, crypto.seal(metadata_key, (inner, signature), context)))


def open_control(crypto, blob, metadata_key, group, era, allowed):
    context, ciphertext = unpack(blob)
    g, e, kind, nonce = unpack(context)
    if (g, e) != (group, era) or len(nonce) != 32 or kind not in CONTROL_TYPES:
        raise ValueError("wrong control context")
    inner, signature = crypto.open(metadata_key, ciphertext, context)
    author, value = unpack(inner)
    if author not in allowed or not crypto.verify(author, pack((context, inner)), signature):
        raise ValueError("invalid control author")
    return author, kind, value
