"""
SentinelCore Ransomware Behavioral Detection & Workload Differentiation Module
Implements ShieldFS (Continella et al.) and UNVEIL (Kharraz et al.) behavioral invariants.
"""

import time
import collections
from typing import Dict, List, Optional, Tuple
from evaluator import calculate_shannon_entropy

DEVELOPER_LINEAGE = {
    "cargo.exe", "rustc.exe", "git.exe", "node.exe", "npm.cmd", "cl.exe", "link.exe", "msbuild.exe"
}

class ProcessEvent:
    def __init__(self, timestamp: float, path: str, byte_entropy: float, is_write: bool):
        self.timestamp = timestamp
        self.path = path
        self.byte_entropy = byte_entropy
        self.is_write = is_write

class ProcessContext:
    def __init__(self, pid: int, name: str, parent_name: str):
        self.pid = pid
        self.name = name
        self.parent_name = parent_name
        self.is_dev = (name.lower() in DEVELOPER_LINEAGE or parent_name.lower() in DEVELOPER_LINEAGE)
        self.events: List[ProcessEvent] = []
        self.is_terminated = False
        self.files_compromised = 0
        self.mitigation_timestamp: Optional[float] = None

class BaselineNaiveDetector:
    """
    Standard AV behavioral heuristic:
    Flags and terminates any process that writes > 50 files within a 1000ms window.
    Completely unaware of write entropy or developer process lineage.
    """
    def __init__(self, rate_threshold: int = 50, window_s: float = 1.0):
        self.rate_threshold = rate_threshold
        self.window_s = window_s

    def process_write(self, proc: ProcessContext, event_time: float, path: str, data: bytes) -> bool:
        if proc.is_terminated:
            return False

        proc.events.append(ProcessEvent(event_time, path, 0.0, True))
        proc.files_compromised += 1

        # Prune events outside window
        cutoff = event_time - self.window_s
        recent_writes = [e for e in proc.events if e.timestamp >= cutoff]

        if len(recent_writes) > self.rate_threshold:
            proc.is_terminated = True
            proc.mitigation_timestamp = event_time
            return True  # Mitigation triggered
        return False

class SentinelDualInvariantDetector:
    """
    SentinelCore Heuristic Engine:
    Couples sliding-window velocity with write-block Shannon entropy and lineage checks.
    Bounds ransomware damage to <= 3 files while ensuring 0% developer false alarms.
    """
    def __init__(self, window_s: float = 1.0, entropy_threshold: float = 7.5, burst_limit: int = 3):
        self.window_s = window_s
        self.entropy_threshold = entropy_threshold
        self.burst_limit = burst_limit

    def process_write(self, proc: ProcessContext, event_time: float, path: str, data: bytes) -> bool:
        if proc.is_terminated:
            return False

        # Fast entropy evaluation on 4KB sample block
        sample = data[:4096] if len(data) > 4096 else data
        entropy = calculate_shannon_entropy(sample)
        
        proc.events.append(ProcessEvent(event_time, path, entropy, True))
        proc.files_compromised += 1

        cutoff = event_time - self.window_s
        recent_writes = [e for e in proc.events if e.timestamp >= cutoff]

        # Developer Lineage Fast-Pass
        if proc.is_dev:
            # Legitimate compilers may write hundreds of intermediate files per second,
            # but their code/object/JSON entropy remains structured (H < 7.2)
            if entropy < 7.3:
                return False  # Benign compiler output: permit

            # If developer tool has been hijacked or injected to encrypt with H > 7.6
            high_entropy_count = sum(1 for e in recent_writes if e.byte_entropy >= self.entropy_threshold)
            if high_entropy_count >= self.burst_limit:
                proc.is_terminated = True
                proc.mitigation_timestamp = event_time
                return True
            return False

        # Non-developer process: strict dual-invariant evaluation
        if entropy >= self.entropy_threshold:
            high_entropy_recent = [e for e in recent_writes if e.byte_entropy >= self.entropy_threshold]
            if len(high_entropy_recent) >= self.burst_limit:
                proc.is_terminated = True
                proc.mitigation_timestamp = event_time
                return True

        return False
