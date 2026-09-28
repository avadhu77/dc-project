"""Distributed node and message simulation."""

from dataclasses import dataclass
from security_modules import (
    AuthenticationManager, AccessControl, CryptoManager,
    DigitalSignature, HashIntegrity, ConsistentHashRing
)


@dataclass
class Node:
    node_id: str
    resources: dict


class DistributedSystem:
    def __init__(self, node_count: int, secure: bool, hash_replicas: int = 3):
        self.secure = secure
        self.nodes = [
            Node(f"node-{i+1}", {"resource": f"data-{i+1}"})
            for i in range(node_count)
        ]
        self.auth = AuthenticationManager()
        self.acl = AccessControl()
        self.crypto = CryptoManager() if secure else None
        self.signature = DigitalSignature() if secure else None
        self.hashing = HashIntegrity()
        self.ring = ConsistentHashRing(hash_replicas)
        for node in self.nodes:
            self.ring.add_node(node.node_id)

    def authenticate(self, username, password):
        if not self.secure:
            # Baseline: no additional authentication mechanism.
            return True, 0.0
        result = self.auth.authenticate(username, password)
        return result.success, result.elapsed_ms

    def authorize(self, username, action):
        if not self.secure:
            return True, 0.0
        role = self.auth.role(username)
        return self.acl.authorize(role, action)

    def send_message(self, message: bytes):
        """Return a protected packet for secure mode, or plain bytes for baseline."""
        if not self.secure:
            return {
                "payload": message,
                "encrypted": False,
                "digest": None,
                "signature": None,
                "enc_ms": 0.0,
                "dec_ms": 0.0,
                "sign_ms": 0.0,
                "verify_ms": 0.0,
                "hash_ms": 0.0,
            }

        ciphertext, enc_ms = self.crypto.encrypt(message)
        digest, hash_ms = self.hashing.generate(ciphertext)
        signature, sign_ms = self.signature.sign(ciphertext)
        return {
            "payload": ciphertext,
            "encrypted": True,
            "digest": digest,
            "signature": signature,
            "enc_ms": enc_ms,
            "dec_ms": 0.0,
            "sign_ms": sign_ms,
            "verify_ms": 0.0,
            "hash_ms": hash_ms,
        }

    def receive_message(self, packet):
        if not self.secure:
            return packet["payload"], {
                "dec_ms": 0.0, "verify_ms": 0.0, "hash_verify_ms": 0.0,
                "integrity_ok": True, "signature_ok": True
            }

        payload = packet["payload"]
        digest_ok, hash_verify_ms = self.hashing.verify(payload, packet["digest"])
        signature_ok, verify_ms = self.signature.verify(payload, packet["signature"])

        if not (digest_ok and signature_ok):
            return None, {
                "dec_ms": 0.0, "verify_ms": verify_ms,
                "hash_verify_ms": hash_verify_ms,
                "integrity_ok": digest_ok, "signature_ok": signature_ok
            }

        plaintext, dec_ms = self.crypto.decrypt(payload)
        return plaintext, {
            "dec_ms": dec_ms, "verify_ms": verify_ms,
            "hash_verify_ms": hash_verify_ms,
            "integrity_ok": digest_ok, "signature_ok": signature_ok
        }

    def lookup(self, key: str):
        import time
        start = time.perf_counter()
        node = self.ring.locate(key)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return node, elapsed_ms
