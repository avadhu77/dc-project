"""Security primitives used by the distributed-system simulation."""

import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class AuthResult:
    success: bool
    elapsed_ms: float


class AuthenticationManager:
    def __init__(self):
        self.users = {
            "admin": ("admin123", "admin"),
            "analyst": ("analyst123", "analyst"),
            "viewer": ("viewer123", "viewer"),
        }

    def authenticate(self, username: str, password: str) -> AuthResult:
        start = time.perf_counter()
        record = self.users.get(username)
        success = bool(record and hmac.compare_digest(record[0], password))
        return AuthResult(success, (time.perf_counter() - start) * 1000)

    def role(self, username: str):
        record = self.users.get(username)
        return record[1] if record else None


class AccessControl:
    """Simple RBAC policy used by the simulation."""

    POLICY = {
        "admin": {"read", "write", "delete"},
        "analyst": {"read", "write"},
        "viewer": {"read"},
    }

    def authorize(self, role: str, action: str):
        start = time.perf_counter()
        allowed = action in self.POLICY.get(role, set())
        elapsed_ms = (time.perf_counter() - start) * 1000
        return allowed, elapsed_ms


class CryptoManager:
    """Fernet authenticated encryption used for protected messages."""

    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, plaintext: bytes):
        start = time.perf_counter()
        ciphertext = self.cipher.encrypt(plaintext)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return ciphertext, elapsed_ms

    def decrypt(self, ciphertext: bytes):
        start = time.perf_counter()
        plaintext = self.cipher.decrypt(ciphertext)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return plaintext, elapsed_ms


class DigitalSignature:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def sign(self, message: bytes):
        start = time.perf_counter()
        signature = self.private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return signature, (time.perf_counter() - start) * 1000

    def verify(self, message: bytes, signature: bytes):
        start = time.perf_counter()
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            valid = True
        except Exception:
            valid = False
        return valid, (time.perf_counter() - start) * 1000


class HashIntegrity:
    @staticmethod
    def generate(data: bytes):
        start = time.perf_counter()
        digest = sha256_hex(data)
        return digest, (time.perf_counter() - start) * 1000

    @staticmethod
    def verify(data: bytes, expected_digest: str):
        start = time.perf_counter()
        actual = sha256_hex(data)
        valid = hmac.compare_digest(actual, expected_digest)
        return valid, (time.perf_counter() - start) * 1000


class ConsistentHashRing:
    """Small educational consistent-hashing implementation."""

    def __init__(self, replicas=3):
        self.replicas = replicas
        self.ring = {}
        self.nodes = set()

    def _hash(self, value: str):
        return int(hashlib.sha256(value.encode()).hexdigest(), 16)

    def add_node(self, node_id: str):
        self.nodes.add(node_id)
        for replica in range(self.replicas):
            self.ring[self._hash(f"{node_id}:{replica}")] = node_id

    def remove_node(self, node_id: str):
        self.nodes.discard(node_id)
        for replica in range(self.replicas):
            self.ring.pop(self._hash(f"{node_id}:{replica}"), None)

    def locate(self, key: str):
        if not self.ring:
            raise ValueError("Hash ring is empty")
        point = self._hash(key)
        ordered = sorted(self.ring)
        for ring_point in ordered:
            if point <= ring_point:
                return self.ring[ring_point]
        return self.ring[ordered[0]]
