"""Analytical baseline subtotals, kept separate from serialized experiments."""
from dataclasses import dataclass, asdict
import math


@dataclass(frozen=True)
class Workload:
    devices: int = 10_000
    shards: int = 128
    shard_events: int = 144
    group_events: int = 144
    active_senders: int = 100
    updates_per_sender: int = 24
    messages_read: int = 1000
    plaintext_bytes: int = 100
    offline_days: int = 7

    def __post_init__(self):
        if (not 1 <= self.shards <= self.devices or not 0 <= self.active_senders <= self.devices or
                any(type(v) is not int or v < 0 for v in asdict(self).values())):
            raise ValueError("invalid workload")


def application_frame_bytes(plaintext):
    body = 4 + 666 + plaintext
    padded = ((body + 127) // 128) * 128 if body <= 2048 else 1 << (body - 1).bit_length()
    return 864 - 4 - 666 + padded


def estimate(workload):
    w = workload
    local_count = math.ceil(w.devices / w.shards)
    shard_path = (local_count - 1).bit_length() * 32
    group_path = (w.shards - 1).bit_length() * 32
    slots = w.shard_events * (1042 + 666 + shard_path) + w.group_events * (1042 + 666 + group_path)
    boxes = w.group_events * 2196
    slot_count = w.devices * w.shard_events + w.shards * w.group_events
    public_fetch_average = slot_count * 930 / w.devices
    upload_average = (slot_count * (1042 + 930) + w.shards * w.group_events * 2196) / w.devices
    updates = w.active_senders * w.updates_per_sender * 666
    applications = w.messages_read * application_frame_bytes(w.plaintext_bytes)
    return {
        "workload": asdict(w),
        "units": "bytes, decimal MB; daily values unless named otherwise",
        "recipient_refresh_download": slots + boxes,
        "own_ticket_publication_upload": w.shard_events * 930,
        "average_contributor_public_key_download": public_fetch_average,
        "average_total_control_upload": upload_average,
        "sender_update_signatures_download": updates,
        "application_frames_download": applications,
        "partial_daily_download": slots + boxes + public_fetch_average + updates + applications,
        "offline_control_replay_subtotal": w.offline_days * (slots + boxes + updates),
        "private_member_ticket_reserve": w.offline_days * w.shard_events * 1234,
        "all_signing_public_keys": w.devices * 897,
        "all_lane_and_message_heads": w.devices * 64,
        "unmodeled": ["complete baseline control and privacy envelope formats",
                      "sender-update bodies and variable dependency closure", "history and attachments",
                      "membership churn and fallback traffic", "inventory imbalance and abandonment",
                      "existing IP-hiding transport overhead"],
    }
