"""Ideal cryptographic functionality for experiments, NEVER deployable crypto.

The private oracle tables are part of the test harness, excluded from both
device snapshots and service views. Opaque ciphertexts have modeled PQ sizes;
they are not NTRU, Falcon or AEAD outputs. Deterministic fixture randomness is
not an endpoint RNG and supplies no real-world secrecy or erasure guarantee.
"""
from dataclasses import dataclass
from hashlib import shake_256
from core import digest, u64
from wire import pack, unpack


@dataclass(frozen=True)
class Signer:
    public: bytes
    secret: bytes


@dataclass(frozen=True)
class KemKey:
    public: bytes
    secret: bytes


class IdealCrypto:
    def __init__(self, fixture_seed=b"coppice research fixtures"):
        self.seed, self.counter = fixture_seed, 0
        self._signers, self._signatures, self._kem, self._sealed = {}, {}, {}, {}

    def fresh(self, label=b"secret", size=32):
        self.counter += 1
        return shake_256(pack((self.seed, label, self.counter))).digest(size)

    def signer(self):
        secret = self.fresh(b"signing secret", 1281)
        public = shake_256(secret + b"signing public").digest(897)
        self._signers[public] = digest(b"signing capability", secret)
        return Signer(public, secret)

    def sign(self, signer, body):
        if self._signers.get(signer.public) != digest(b"signing capability", signer.secret):
            raise ValueError("missing signing capability")
        signature = self.fresh(b"signature", 666)
        self._signatures[signature] = (signer.public, bytes(body))
        return signature

    def verify(self, public, body, signature):
        return self._signatures.get(signature) == (public, bytes(body))

    def kem_key(self):
        secret = self.fresh(b"KEM secret", 1234)
        public = shake_256(secret + b"KEM public").digest(930)
        self._kem[public] = digest(b"KEM capability", secret)
        return KemKey(public, secret)

    def _seal(self, capability, value, aad, overhead):
        raw = pack(value)
        blob = self.fresh(b"opaque ciphertext", len(raw) + overhead)
        self._sealed[blob] = (capability, bytes(aad), raw)
        return blob

    def _open(self, capability, blob, aad):
        entry = self._sealed.get(blob)
        if entry is None or entry[:2] != (capability, bytes(aad)):
            raise ValueError("ciphertext authentication failed")
        return unpack(entry[2])

    def seal(self, key, value, aad):
        return self._seal(digest(b"symmetric capability", key), value, aad, 16)

    def open(self, key, blob, aad):
        return self._open(digest(b"symmetric capability", key), blob, aad)

    def seal_to(self, public, value, aad):
        if public not in self._kem:
            raise ValueError("unknown KEM public key")
        return self._seal(self._kem[public], value, aad, 930 + 16)

    def open_with(self, secret, blob, aad):
        return self._open(digest(b"KEM capability", secret), blob, aad)
