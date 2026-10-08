"""
Network Socket & C2 Outbound Connection Monitor for SentinelCore
Inspects active TCP/UDP socket connections across all local processes.
Flags known malware C2 beacon ports, suspicious LOLBin network activity,
and anomalous outbound connections.
"""

import time
import threading
import collections
from typing import List, Dict, Any, Optional, Callable, Set
import psutil

SUSPICIOUS_C2_PORTS = {
    4444: "Metasploit.DefaultListener",
    1337: "Hacktool.ElitePort",
    3333: "Cryptominer.StratumDefault",
    5555: "Adware.AdbRemoteMining",
    6667: "Botnet.IRCDialer",
    9001: "Tor.DirectoryOrBridge",
    44444: "Metasploit.AlternateC2"
}

SUSPICIOUS_NET_BINARIES = {
    "cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "cscript.exe", "wscript.exe"
}

class NetworkMonitor:
    def __init__(
        self,
        poll_interval: float = 2.0,
        on_threat_detected: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.poll_interval = poll_interval
        self.on_threat_detected = on_threat_detected
        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        self.recent_events = collections.deque(maxlen=100)
        self.flagged_pids: Set[int] = set()

    def audit_connections(self) -> List[Dict[str, Any]]:
        """Returns snapshot of current network connections with risk analysis."""
        records = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return []

        for conn in conns:
            pid = conn.pid
            if not pid or pid == 0:
                continue

            proc_name = "Unknown"
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            l_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            r_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            r_port = conn.raddr.port if conn.raddr else 0
            status = conn.status

            is_suspicious = False
            reason = "Benign"

            # Check 1: Known C2 Port
            if r_port in SUSPICIOUS_C2_PORTS:
                is_suspicious = True
                reason = f"C2Port:{SUSPICIOUS_C2_PORTS[r_port]}"

            # Check 2: Scripting host or LOLBin establishing outbound network session
            if not is_suspicious and proc_name.lower() in SUSPICIOUS_NET_BINARIES and status in ("ESTABLISHED", "SYN_SENT"):
                # Permit local loopback
                if conn.raddr and not conn.raddr.ip.startswith("127."):
                    is_suspicious = True
                    reason = f"SuspiciousLOLBinNetworkSession({proc_name})"

            import socket
            proto = "UDP" if getattr(conn, "type", 0) == socket.SOCK_DGRAM else "TCP"
            threat_level = "HIGH_RISK" if is_suspicious else "CLEAN"

            record = {
                "pid": pid,
                "process": proc_name,
                "protocol": proto,
                "local_address": l_addr,
                "remote_address": r_addr,
                "status": status,
                "is_suspicious": is_suspicious,
                "threat_level": threat_level,
                "reason": reason
            }
            records.append(record)

        return records

    def start(self):
        """Starts background network monitoring thread."""
        self.is_running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Stops network monitor."""
        self.is_running = False

    def _monitor_loop(self):
        while self.is_running:
            try:
                conns = self.audit_connections()
                for c in conns:
                    if c["is_suspicious"] and c["pid"] not in self.flagged_pids:
                        self.flagged_pids.add(c["pid"])
                        ev = {
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "C2_NETWORK_BEACON_DETECTED",
                            "pid": c["pid"],
                            "process": c["process"],
                            "remote": c["remote_address"],
                            "reason": c["reason"]
                        }
                        self.recent_events.append(ev)
                        if self.on_threat_detected:
                            self.on_threat_detected(ev)
            except Exception:
                pass
            time.sleep(self.poll_interval)
