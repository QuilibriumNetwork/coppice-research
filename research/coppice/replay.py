"""Bounded dependency scheduler for already authenticated model objects.

Callers authenticate object identities before enqueueing; invalid network
signatures must not create permanent failed-object markers. Actions perform
transactional semantic validation/application of authenticated objects.
The queue retains no completed payload/action, only completion identifiers.
Arrival order and wall-clock time never invent a missing predecessor.
"""
from dataclasses import dataclass
from core import DeferredUpdate


def apply_sender_update(client, update):
    client.receive_update(update)
    client.drain()
    if update.identifier in client.replay_gaps:
        raise ValueError("explicit local replay gap")
    if update.sender in client.frozen:
        raise ValueError("authenticated sender update rejected")
    lane = client.lanes.get(update.sender)
    if lane is None or lane.generation < update.generation:
        raise DeferredUpdate("sender update is still pending")


@dataclass(frozen=True)
class Work:
    identifier: bytes
    dependencies: tuple
    size: int
    action: object


class ReplayQueue:
    def __init__(self, max_bytes=8 * 1024**2, max_objects=1024):
        self.max_bytes, self.max_objects = max_bytes, max_objects
        self.pending, self.completed, self.failed = {}, set(), {}

    @property
    def bytes(self):
        return sum(item.size for item in self.pending.values())

    def add(self, work):
        if work.identifier in self.completed:
            return
        if work.identifier in self.failed:
            raise ValueError("retired or invalid replay object")
        prior = self.pending.get(work.identifier)
        if prior is not None:
            if (prior.dependencies, prior.size) != (work.dependencies, work.size):
                raise ValueError("conflicting object metadata")
            return
        if (work.size < 0 or len(set(work.dependencies)) != len(work.dependencies) or
                len(self.pending) >= self.max_objects or self.bytes + work.size > self.max_bytes):
            raise ValueError("pending dependency quota or malformed work")
        # Detect cycles even if the predecessor arrived later than its child.
        stack, seen = list(work.dependencies), set()
        while stack:
            identifier = stack.pop()
            if identifier == work.identifier:
                raise ValueError("cyclic dependency graph")
            if identifier not in seen:
                seen.add(identifier)
                if identifier in self.pending:
                    stack.extend(self.pending[identifier].dependencies)
        self.pending[work.identifier] = work

    def drain(self, max_work=1024):
        applied, progress = 0, True
        while progress and applied < max_work:
            progress = False
            for identifier, work in list(self.pending.items()):
                if applied >= max_work:
                    break
                if not set(work.dependencies) <= self.completed:
                    continue
                try:
                    work.action()
                except (DeferredUpdate, LookupError):
                    continue
                except ValueError as error:
                    self.failed[identifier] = str(error)
                else:
                    self.completed.add(identifier)
                del self.pending[identifier]
                applied += 1
                progress = True
        return applied

    def abandon(self, identifier):
        self.pending.pop(identifier, None)
        self.failed[identifier] = "explicit replay gap"
