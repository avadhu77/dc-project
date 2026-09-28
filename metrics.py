"""Metrics and CSV export helpers."""

from dataclasses import dataclass, asdict
from pathlib import Path
import csv
import statistics


@dataclass
class MetricRecord:
    nodes: int
    attack_level: float
    configuration: str
    repetition: int
    authentication_time_ms: float
    authorization_time_ms: float
    encryption_time_ms: float
    decryption_time_ms: float
    hash_time_ms: float
    signature_generation_ms: float
    signature_verification_ms: float
    attack_detection_rate: float
    unauthorized_access_prevention_rate: float
    integrity_detection_rate: float
    communication_overhead_bytes: int
    computational_overhead_ms: float
    false_acceptance_rate: float
    false_rejection_rate: float
    data_lookup_time_ms: float
    execution_time_ms: float
    attacks_attempted: int
    attacks_detected: int


def write_csv(records, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    rows = [asdict(r) for r in records]
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def summary(records):
    """Return mean and population std for numeric fields grouped by configuration/nodes/attack."""
    from collections import defaultdict
    groups = defaultdict(list)
    for r in records:
        groups[(r.configuration, r.nodes, r.attack_level)].append(r)

    output = []
    for (config, nodes, attack), rows in sorted(groups.items()):
        base = {
            "configuration": config,
            "nodes": nodes,
            "attack_level": attack,
            "repetitions": len(rows),
        }
        numeric = [
            "authentication_time_ms", "authorization_time_ms",
            "encryption_time_ms", "decryption_time_ms", "hash_time_ms",
            "signature_generation_ms", "signature_verification_ms",
            "attack_detection_rate", "unauthorized_access_prevention_rate",
            "integrity_detection_rate", "communication_overhead_bytes",
            "computational_overhead_ms", "false_acceptance_rate",
            "false_rejection_rate", "data_lookup_time_ms", "execution_time_ms",
        ]
        for field in numeric:
            values = [getattr(x, field) for x in rows]
            base[field + "_mean"] = statistics.mean(values)
            base[field + "_std"] = statistics.pstdev(values) if len(values) > 1 else 0.0
        output.append(base)
    return output


def write_summary_csv(summary_rows, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if not summary_rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary_rows[0].keys())
        writer.writeheader()
        writer.writerows(summary_rows)
