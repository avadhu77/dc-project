"""Experiment runner and graph generation."""

import argparse
import random
import time
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

import config
from distributed_system import DistributedSystem
from attack_simulator import AttackSimulator
from metrics import MetricRecord, write_csv, summary, write_summary_csv


def run_one(node_count, attack_level, secure, repetition, seed):
    rng = random.Random(seed)
    system = DistributedSystem(node_count, secure, config.HASH_RING_REPLICAS)
    attacks = AttackSimulator(rng)
    start_all = time.perf_counter()

    auth_times, auth_successes = [], []
    authz_times = []
    enc_times, dec_times, hash_times = [], [], []
    sign_times, verify_times = [], []
    lookup_times = []

    attacks_attempted = attacks_detected = 0
    unauthorized_attempted = unauthorized_blocked = 0
    modification_attempted = modification_detected = 0
    false_accept = false_reject = 0
    communication_overhead = 0
    seen_messages = set()

    usernames = ["admin", "analyst", "viewer"]
    for i in range(max(1, node_count * config.MESSAGES_PER_NODE)):
        username = usernames[i % len(usernames)]
        password = {
            "admin": "admin123",
            "analyst": "analyst123",
            "viewer": "viewer123",
        }[username]

        ok, t = system.authenticate(username, password)
        auth_times.append(t)
        auth_successes.append(ok)

        allowed, t = system.authorize(username, "write")
        authz_times.append(t)

        # Simulate an unauthorized request at a selected rate.
        if attacks.choose(attack_level):
            unauthorized_attempted += 1
            bad_allowed, _ = system.authorize("unknown", "write")
            result = attacks.unauthorized_access(secure, bad_allowed)
            unauthorized_blocked += int(result.prevented)
            attacks_attempted += 1
            attacks_detected += int(result.detected)

        payload = (f"node={i % node_count};message={i};" + "X" * config.MESSAGE_SIZE).encode()
        packet = system.send_message(payload)
        enc_times.append(packet["enc_ms"])
        hash_times.append(packet["hash_ms"])
        sign_times.append(packet["sign_ms"])
        communication_overhead += len(packet["payload"]) - len(payload)

        # Message modification attack
        if attacks.choose(attack_level):
            modification_attempted += 1
            result = attacks.message_modification(secure, packet)
            plaintext, rx = system.receive_message(packet)
            detected = secure and (plaintext is None or not rx["integrity_ok"] or not rx["signature_ok"])
            attacks_attempted += 1
            attacks_detected += int(detected)
            modification_detected += int(detected)
        else:
            plaintext, rx = system.receive_message(packet)

        dec_times.append(rx["dec_ms"])
        verify_times.append(rx["verify_ms"])
        hash_times.append(rx["hash_verify_ms"])

        # Replay simulation
        if attacks.choose(attack_level):
            message_id = f"message-{i}"
            first = attacks.replay(secure, seen_messages, message_id)
            second = attacks.replay(secure, seen_messages, message_id)
            attacks_attempted += 1
            attacks_detected += int(second.detected)

        # Interception simulation
        if attacks.choose(attack_level):
            result = attacks.interception(secure, packet)
            attacks_attempted += 1
            attacks_detected += int(result.detected)

        # Invalid authentication simulation
        if attacks.choose(attack_level):
            result = attacks.invalid_authentication(secure)
            attacks_attempted += 1
            attacks_detected += int(result.detected)

        _, lookup_ms = system.lookup(f"key-{i}")
        lookup_times.append(lookup_ms)

    total_ms = (time.perf_counter() - start_all) * 1000
    total_ops = len(auth_times)
    attack_detection_rate = attacks_detected / attacks_attempted if attacks_attempted else 0.0
    prevention_rate = unauthorized_blocked / unauthorized_attempted if unauthorized_attempted else 0.0
    integrity_rate = modification_detected / modification_attempted if modification_attempted else 0.0

    # In this simulation, baseline has no authentication/authorization checks.
    # Therefore false acceptance reflects attempted unknown access that would pass.
    if not secure:
        false_accept = unauthorized_attempted
    false_accept_rate = false_accept / unauthorized_attempted if unauthorized_attempted else 0.0
    false_reject_rate = 0.0

    crypto_overhead = (
        sum(enc_times) + sum(dec_times) + sum(hash_times) +
        sum(sign_times) + sum(verify_times) + sum(auth_times) + sum(authz_times)
    )

    return MetricRecord(
        nodes=node_count,
        attack_level=attack_level,
        configuration="security_enabled" if secure else "unsecured",
        repetition=repetition,
        authentication_time_ms=sum(auth_times) / total_ops,
        authorization_time_ms=sum(authz_times) / total_ops,
        encryption_time_ms=sum(enc_times) / total_ops,
        decryption_time_ms=sum(dec_times) / total_ops,
        hash_time_ms=sum(hash_times) / (2 * total_ops),
        signature_generation_ms=sum(sign_times) / total_ops,
        signature_verification_ms=sum(verify_times) / total_ops,
        attack_detection_rate=attack_detection_rate,
        unauthorized_access_prevention_rate=prevention_rate,
        integrity_detection_rate=integrity_rate,
        communication_overhead_bytes=max(0, communication_overhead),
        computational_overhead_ms=crypto_overhead,
        false_acceptance_rate=false_accept_rate,
        false_rejection_rate=false_reject_rate,
        data_lookup_time_ms=sum(lookup_times) / len(lookup_times),
        execution_time_ms=total_ms,
        attacks_attempted=attacks_attempted,
        attacks_detected=attacks_detected,
    )


def make_plots(summary_csv, result_dir):
    df = pd.read_csv(summary_csv)
    result_dir = Path(result_dir)
    result_dir.mkdir(exist_ok=True)

    for metric, ylabel, filename in [
        ("execution_time_ms_mean", "Execution time (ms)", "execution_time_vs_nodes.png"),
        ("attack_detection_rate_mean", "Attack detection rate", "attack_detection_vs_nodes.png"),
        ("data_lookup_time_ms_mean", "Lookup time (ms)", "lookup_time_vs_nodes.png"),
        ("computational_overhead_ms_mean", "Computational overhead (ms)", "overhead_vs_nodes.png"),
    ]:
        plt.figure(figsize=(8, 5))
        for config_name, group in df.groupby("configuration"):
            group = group[group["attack_level"] == group["attack_level"].min()]
            group = group.sort_values("nodes")
            plt.plot(group["nodes"], group[metric], marker="o", label=config_name)
        plt.xlabel("Number of distributed nodes")
        plt.ylabel(ylabel)
        plt.title(metric.replace("_", " ").title())
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.savefig(result_dir / filename, dpi=160)
        plt.close()

    # Attack-level comparison for detection
    plt.figure(figsize=(8, 5))
    for config_name, group in df.groupby("configuration"):
        group = group.sort_values("attack_level")
        # Use largest node count to isolate attack-level effect.
        group = group[group["nodes"] == group["nodes"].max()]
        plt.plot(group["attack_level"] * 100, group["attack_detection_rate_mean"],
                 marker="o", label=config_name)
    plt.xlabel("Attack level (%)")
    plt.ylabel("Attack detection rate")
    plt.title("Attack Detection vs Attack Level")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(result_dir / "attack_level_comparison.png", dpi=160)
    plt.close()


def run_experiments(node_sizes, attack_levels, repetitions, result_dir):
    result_dir = Path(result_dir)
    result_dir.mkdir(parents=True, exist_ok=True)
    records = []
    seed = config.BASE_SEED

    for nodes in node_sizes:
        for attack in attack_levels:
            for secure in [False, True]:
                for rep in range(1, repetitions + 1):
                    records.append(run_one(nodes, attack, secure, rep, seed))
                    seed += 1

    raw_csv = result_dir / "experiment_results.csv"
    summary_csv = result_dir / "summary_results.csv"
    write_csv(records, raw_csv)
    summary_rows = summary(records)
    write_summary_csv(summary_rows, summary_csv)
    make_plots(summary_csv, result_dir)
    return raw_csv, summary_csv


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="Run a small demo experiment.")
    args = parser.parse_args()

    if args.quick:
        node_sizes = [10, 25]
        attack_levels = [0.0, 0.20]
        repetitions = 1
    else:
        node_sizes = config.NODE_SIZES
        attack_levels = config.ATTACK_LEVELS
        repetitions = config.REPETITIONS

    raw, summary_csv = run_experiments(node_sizes, attack_levels, repetitions, config.RESULT_DIR)
    print(f"Raw results: {raw}")
    print(f"Summary results: {summary_csv}")
    print("Graphs generated in the results/ directory.")


if __name__ == "__main__":
    main()
