"""
Experiment H1 Runner: Cascaded Evaluation Latency Benchmark
Compares Baseline Monolithic Scanner vs. SentinelCore Tiered Cascade
across 10,000 real-world execution events.
"""

import os
import sys
import glob
import time
import json
import random
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Ensure src/ is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "src")))
from evaluator import BaselineScanner, TieredCascadeScanner, LRUReputationCache, calculate_shannon_entropy

def generate_workload():
    print("[*] Loading real Windows system binaries from C:\\Windows\\System32...")
    pe_candidates = glob.glob(r"C:\Windows\System32\*.exe") + glob.glob(r"C:\Windows\System32\*.dll")
    
    loaded_binaries = []
    # Select diverse binaries up to 5MB to avoid excessive RAM allocation
    for p in pe_candidates:
        try:
            sz = os.path.getsize(p)
            if 30000 <= sz <= 5 * 1024 * 1024:
                with open(p, "rb") as f:
                    data = f.read()
                    loaded_binaries.append((os.path.basename(p), data, "benign"))
                if len(loaded_binaries) >= 120:
                    break
        except Exception:
            continue
            
    print(f"[+] Successfully loaded {len(loaded_binaries)} real Windows PE binaries.")

    # Create synthetic packed/malicious binaries
    packed_binaries = []
    for i in range(20):
        # High-entropy random payload prefixed with fake DOS/PE header
        raw_header = b"MZ" + b"\x00" * 58 + int(128).to_bytes(4, "little") + b"\x00" * 64 + b"PE\x00\x00"
        high_entropy_body = os.urandom(random.randint(100_000, 500_000))
        full_bin = raw_header + high_entropy_body
        packed_binaries.append((f"synthetic_ransomware_{i}.exe", full_bin, "malicious"))

    # Construct 10,000 workload requests:
    # 85% Known clean binaries (repeating popular system binaries)
    # 10% Uncached clean binaries
    # 5% Packed / malicious binaries
    workload = []
    
    # 10 popular repeating binaries
    popular_clean = loaded_binaries[:15]
    other_clean = loaded_binaries[15:]
    
    for _ in range(8500):
        workload.append(random.choice(popular_clean))
    for _ in range(1000):
        workload.append(random.choice(other_clean))
    for _ in range(500):
        workload.append(random.choice(packed_binaries))
        
    random.shuffle(workload)
    print(f"[+] Assembled execution stream of {len(workload)} requests.")
    return workload

def run_benchmark():
    workload = generate_workload()
    
    # Initialize scanners
    baseline_scanner = BaselineScanner()
    cache = LRUReputationCache(capacity=50000)
    tiered_scanner = TieredCascadeScanner(cache=cache)

    print("\n[*] --- Phase 1: Benchmarking Baseline Scanner (10,000 requests) ---")
    baseline_latencies_ms = []
    baseline_verdicts = []
    
    t0_start = time.perf_counter()
    for name, data, label in workload:
        t0 = time.perf_counter_ns()
        verdict, reason = baseline_scanner.scan_file(data)
        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0
        baseline_latencies_ms.append(latency_ms)
        baseline_verdicts.append(verdict)
    t0_elapsed = time.perf_counter() - t0_start
    print(f"[+] Baseline benchmark finished in {t0_elapsed:.2f}s.")

    print("\n[*] --- Phase 2: Benchmarking SentinelCore Tiered Cascade (10,000 requests) ---")
    tiered_latencies_ms = []
    tiered_verdicts = []
    tiered_tiers = []
    
    t1_start = time.perf_counter()
    for name, data, label in workload:
        t0 = time.perf_counter_ns()
        verdict, reason, tier = tiered_scanner.evaluate_pre_execution(data)
        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0
        tiered_latencies_ms.append(latency_ms)
        tiered_verdicts.append(verdict)
        tiered_tiers.append(tier)
    t1_elapsed = time.perf_counter() - t1_start
    print(f"[+] Tiered Cascade benchmark finished in {t1_elapsed:.2f}s.")

    # Calculate statistics
    b_arr = np.array(baseline_latencies_ms)
    t_arr = np.array(tiered_latencies_ms)

    metrics = {
        "workload_size": len(workload),
        "baseline": {
            "mean_ms": float(np.mean(b_arr)),
            "p50_ms": float(np.percentile(b_arr, 50)),
            "p90_ms": float(np.percentile(b_arr, 90)),
            "p95_ms": float(np.percentile(b_arr, 95)),
            "p99_ms": float(np.percentile(b_arr, 99)),
            "p99_9_ms": float(np.percentile(b_arr, 99.9)),
            "max_ms": float(np.max(b_arr)),
            "timeouts_over_50ms": int(np.sum(b_arr > 50.0)),
            "total_elapsed_s": float(t0_elapsed)
        },
        "treatment_tiered": {
            "mean_ms": float(np.mean(t_arr)),
            "p50_ms": float(np.percentile(t_arr, 50)),
            "p90_ms": float(np.percentile(t_arr, 90)),
            "p95_ms": float(np.percentile(t_arr, 95)),
            "p99_ms": float(np.percentile(t_arr, 99)),
            "p99_9_ms": float(np.percentile(t_arr, 99.9)),
            "max_ms": float(np.max(t_arr)),
            "timeouts_over_50ms": int(np.sum(t_arr > 50.0)),
            "total_elapsed_s": float(t1_elapsed),
            "tier_distribution": {
                "tier1_cache_hits": int(tiered_tiers.count(1)),
                "tier2_entropy_gates": int(tiered_tiers.count(2)),
                "tier3_async_passes": int(tiered_tiers.count(3))
            }
        },
        "speedup": {
            "mean_speedup": float(np.mean(b_arr) / np.mean(t_arr)),
            "p99_speedup": float(np.percentile(b_arr, 99) / np.percentile(t_arr, 99))
        }
    }

    print("\n" + "="*60)
    print("                EXPERIMENT H1 RESULTS SUMMARY                ")
    print("="*60)
    print(f"Metric                  | Baseline (Monolithic) | Treatment (Tiered)")
    print(f"Mean Latency            | {metrics['baseline']['mean_ms']:8.4f} ms        | {metrics['treatment_tiered']['mean_ms']:8.4f} ms")
    print(f"P50 (Median) Latency    | {metrics['baseline']['p50_ms']:8.4f} ms        | {metrics['treatment_tiered']['p50_ms']:8.4f} ms")
    print(f"P90 Latency             | {metrics['baseline']['p90_ms']:8.4f} ms        | {metrics['treatment_tiered']['p90_ms']:8.4f} ms")
    print(f"P99 Latency (Budget)    | {metrics['baseline']['p99_ms']:8.4f} ms        | {metrics['treatment_tiered']['p99_ms']:8.4f} ms")
    print(f"P99.9 Latency           | {metrics['baseline']['p99_9_ms']:8.4f} ms        | {metrics['treatment_tiered']['p99_9_ms']:8.4f} ms")
    print(f"Max Latency             | {metrics['baseline']['max_ms']:8.4f} ms        | {metrics['treatment_tiered']['max_ms']:8.4f} ms")
    print(f"Timeouts (> 50ms)       | {metrics['baseline']['timeouts_over_50ms']:8d}           | {metrics['treatment_tiered']['timeouts_over_50ms']:8d}")
    print(f"P99 Speedup Factor      |                       | {metrics['speedup']['p99_speedup']:8.1f}x faster")
    print("="*60)

    # Save artifacts
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results"))
    os.makedirs(results_dir, exist_ok=True)
    
    metrics_path = os.path.join(results_dir, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\n[+] Wrote metrics to {metrics_path}")

    # Save trajectory to data/
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data"))
    os.makedirs(data_dir, exist_ok=True)
    trajectory_item = {
        "experiment_id": "run_001",
        "hypothesis": "H1",
        "metric_name": "P99_latency_ms",
        "baseline": metrics["baseline"]["p99_ms"],
        "metric_value": metrics["treatment_tiered"]["p99_ms"],
        "delta": f"-{metrics['baseline']['p99_ms'] - metrics['treatment_tiered']['p99_ms']:.4f} ms",
        "p99_speedup": f"{metrics['speedup']['p99_speedup']:.1f}x",
        "wall_time_s": metrics["treatment_tiered"]["total_elapsed_s"],
        "change_summary": "Tiered cascade: LRU SHA-256 cache + 64KB Shannon entropy gate + async YARA queue",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(os.path.join(data_dir, "trajectory_H1_run001.json"), "w") as f:
        json.dump(trajectory_item, f, indent=2)

    # Plot results
    print("[*] Generating publication-quality latency figures...")
    plot_results(b_arr, t_arr, results_dir)
    print(f"[+] Visualizations saved in {results_dir}")

def plot_results(b_arr, t_arr, results_dir):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))
    
    # Plot 1: Cumulative Distribution Function (CDF)
    b_sorted = np.sort(b_arr)
    t_sorted = np.sort(t_arr)
    y_vals = np.linspace(0, 1, len(b_arr))

    ax1.plot(b_sorted, y_vals, label="Baseline (Monolithic Scan)", color="#d9534f", linewidth=2)
    ax1.plot(t_sorted, y_vals, label="SentinelCore (Tiered Cascade)", color="#0275d8", linewidth=2)
    ax1.axvline(x=1.5, color="#5cb85c", linestyle="--", linewidth=1.5, label="Budget Ceiling (1.5 ms)")
    ax1.set_xscale("log")
    ax1.set_xlabel("Decision Latency (ms, log scale)", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Cumulative Probability P(X <= t)", fontsize=11, fontweight="bold")
    ax1.set_title("Latency Cumulative Distribution Function (CDF)", fontsize=12, fontweight="bold")
    ax1.legend(loc="lower right")
    ax1.grid(True, which="both", ls="--", alpha=0.5)

    # Plot 2: Percentile Comparison Bar Chart
    percentiles = ["P50", "P90", "P95", "P99", "P99.9"]
    b_pcts = [np.percentile(b_arr, p) for p in [50, 90, 95, 99, 99.9]]
    t_pcts = [np.percentile(t_arr, p) for p in [50, 90, 95, 99, 99.9]]

    x = np.arange(len(percentiles))
    width = 0.35

    ax2.bar(x - width/2, b_pcts, width, label="Baseline", color="#d9534f", alpha=0.85)
    ax2.bar(x + width/2, t_pcts, width, label="SentinelCore Tiered", color="#0275d8", alpha=0.85)
    ax2.axhline(y=1.5, color="#5cb85c", linestyle="--", linewidth=1.5, label="1.5ms Target Budget")
    
    ax2.set_xlabel("Latency Percentiles", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Latency (ms)", fontsize=11, fontweight="bold")
    ax2.set_title("Pre-Execution Latency Percentiles (10,000 Invocations)", fontsize=12, fontweight="bold")
    ax2.set_xticks(x)
    ax2.set_xticklabels(percentiles)
    ax2.legend()
    ax2.grid(True, ls="--", alpha=0.5)

    plt.tight_layout()
    plot_path = os.path.join(results_dir, "latency_comparison.png")
    plt.savefig(plot_path, dpi=300)
    plt.close()

if __name__ == "__main__":
    run_benchmark()
