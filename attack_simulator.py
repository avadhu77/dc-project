"""Controlled, non-destructive attack simulation."""

from dataclasses import dataclass
import random


@dataclass
class AttackResult:
    attack_type: str
    attempted: bool
    detected: bool
    prevented: bool


class AttackSimulator:
    TYPES = [
        "unauthorized_access",
        "message_modification",
        "replay_attempt",
        "interception",
        "invalid_authentication",
    ]

    def __init__(self, rng: random.Random):
        self.rng = rng

    def choose(self, attack_level: float):
        return self.rng.random() < attack_level

    def unauthorized_access(self, secure: bool, authorized: bool):
        attempted = True
        prevented = secure and not authorized
        detected = prevented
        if not secure:
            prevented = False
            detected = False
        return AttackResult("unauthorized_access", attempted, detected, prevented)

    def message_modification(self, secure: bool, packet: dict):
        attempted = True
        if secure:
            # Flip one byte in the simulated packet.
            data = bytearray(packet["payload"])
            if data:
                data[0] ^= 1
            packet["payload"] = bytes(data)
            return AttackResult("message_modification", True, True, True)
        return AttackResult("message_modification", True, False, False)

    def replay(self, secure: bool, seen_ids: set, message_id: str):
        attempted = True
        if secure and message_id in seen_ids:
            return AttackResult("replay_attempt", True, True, True)
        seen_ids.add(message_id)
        return AttackResult("replay_attempt", True, False, False)

    def interception(self, secure: bool, packet: dict):
        attempted = True
        # In secure mode, ciphertext is not directly readable as plaintext.
        prevented = secure and packet.get("encrypted", False)
        detected = prevented
        return AttackResult("interception", attempted, detected, prevented)

    def invalid_authentication(self, secure: bool):
        attempted = True
        prevented = secure
        detected = secure
        return AttackResult("invalid_authentication", attempted, detected, prevented)
