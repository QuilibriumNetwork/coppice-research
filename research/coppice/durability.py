"""Atomic persistence/crash oracle, with a separately retained rollback witness.

No filesystem erasure or hardware monotonicity is implemented. This models
their required transaction semantics and exposes failure when the witness is
rolled back too. Outboxes store opaque frames, never plaintext message keys.
"""
from copy import deepcopy
from dataclasses import dataclass
from envelopes import message_frame


class Crash(Exception):
    pass


@dataclass
class Witness:
    revision: int = 0


class DurableDevice:
    def __init__(self, state, witness=None):
        self.witness = witness if witness is not None else Witness()
        self.revision = self.witness.revision
        self.state, self.outbox = deepcopy(state), {}

    def check(self):
        if self.revision != self.witness.revision:
            raise ValueError("rollback detected; fresh authorized re-entry required")

    def snapshot(self):
        self.check()
        return deepcopy((self.revision, self.state, self.outbox))

    def restore(self, snapshot):
        revision, state, outbox = deepcopy(snapshot)
        if revision != self.witness.revision:
            raise ValueError("rollback detected; fresh authorized re-entry required")
        self.revision, self.state, self.outbox = revision, state, outbox

    def transact(self, operation, crash=None):
        self.check()
        state, outbox = deepcopy(self.state), deepcopy(self.outbox)
        result = operation(state, outbox)
        if crash == "before_commit":
            raise Crash("before atomic commit; nothing released")
        # Atomic update and witness advancement are assumptions of this oracle.
        self.state, self.outbox = state, outbox
        self.revision += 1
        self.witness.revision = self.revision
        if crash == "after_commit":
            raise Crash("after atomic commit; retry committed bytes")
        return result

    def send(self, crypto, request_id, sender, signer, metadata_key, payload, crash=None):
        def operation(client, outbox):
            if request_id not in outbox:
                outbox[request_id] = message_frame(crypto, client, sender, signer, metadata_key, payload)
            return outbox[request_id]
        return self.transact(operation, crash)
