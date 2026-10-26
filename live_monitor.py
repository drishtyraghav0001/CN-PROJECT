import threading
import time

import pandas as pd
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP

COLS = ["protocol", "packets", "bytes", "duration", "source_port", "dest_port", "src_ip", "dst_ip"]


def get_available_interfaces():
    """
    Auto-discovers network interfaces available on the system.
    Returns a list of dicts: [{'name': '...', 'desc': '...', 'label': '...'}]
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        ifs = get_windows_if_list()
        res = []
        for i in ifs:
            name = str(i.get("name", "")).strip()
            desc = str(i.get("description", "")).strip()
            if name:
                res.append({
                    "name": name,
                    "desc": desc,
                    "label": f"{name} ({desc})" if desc else name,
                })
        if res:
            return res
    except Exception:
        pass

    try:
        from scapy.all import get_if_list
        return [{"name": i, "desc": "", "label": i} for i in get_if_list() if i]
    except Exception:
        return []


class LiveMonitor:
    """Continuous background capture. Aggregates flows only; payloads are never stored."""

    def __init__(self, max_flows=20000, max_alerts=2000, max_history=120):
        self.lock = threading.Lock()
        self.flows = {}
        self.sniffer = None
        self.active = False
        self.total_packets = 0
        self.total_bytes = 0
        self.max_flows = max_flows
        self.max_alerts = max_alerts
        self.max_history = max_history

        # Persistent live monitoring session tracking
        self.alert_log = []
        self.seen_alert_keys = set()
        self.time_series = []
        self.last_snap_time = None
        self.last_snap_packets = 0
        self.last_snap_bytes = 0

    @property
    def running(self):
        return self.active and self.sniffer is not None

    def start(self, iface=None):
        if self.running:
            return
        sniffer = AsyncSniffer(iface=iface or None, prn=self._handle, store=False)
        sniffer.start()
        time.sleep(0.5)
        if not sniffer.thread.is_alive():
            raise RuntimeError("Could not start capture. Check Npcap, the interface name and Administrator rights.")
        self.sniffer, self.active = sniffer, True
        self.last_snap_time = time.time()
        self.last_snap_packets = self.total_packets
        self.last_snap_bytes = self.total_bytes

    def stop(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self.sniffer, self.active = None, False

    def _handle(self, pkt):
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return
        ts, n = float(pkt.time), len(pkt)
        sport = dport = 0
        if pkt.haslayer(TCP):
            proto, layer = "TCP", pkt[TCP]
        elif pkt.haslayer(UDP):
            proto, layer = "UDP", pkt[UDP]
        elif pkt.haslayer(ICMP):
            proto, layer = "ICMP", None
        else:
            proto, layer = "Other", None
        if layer is not None:
            sport, dport = int(layer.sport), int(layer.dport)
            if proto == "UDP" and 53 in (sport, dport):
                proto = "DNS"
        key = (ip.src, ip.dst, sport, dport, proto)
        with self.lock:
            self.total_packets += 1
            self.total_bytes += n
            f = self.flows.get(key)
            if f is None:
                if len(self.flows) >= self.max_flows:
                    oldest = sorted(self.flows, key=lambda k: self.flows[k]["last"])
                    for k in oldest[: self.max_flows // 10]:
                        del self.flows[k]
                self.flows[key] = {"packets": 1, "bytes": n, "start": ts, "last": ts}
            else:
                f["packets"] += 1
                f["bytes"] += n
                f["last"] = max(f["last"], ts)

    def snapshot(self, window=120):
        """Flows active in the last `window` seconds. Older flows are discarded."""
        now = time.time()
        cutoff = now - window
        rows = []
        with self.lock:
            for key in list(self.flows):
                f = self.flows[key]
                if f["last"] < cutoff:
                    del self.flows[key]
                    continue
                src, dst, sport, dport, proto = key
                dur = max(0.0, f["last"] - f["start"]) if f["packets"] > 1 else 0.0
                rows.append({
                    "protocol": proto,
                    "packets": f["packets"],
                    "bytes": f["bytes"],
                    "duration": dur,
                    "source_port": sport,
                    "dest_port": dport,
                    "src_ip": src,
                    "dst_ip": dst,
                })

            # Track time-series rate metrics
            dt = (now - self.last_snap_time) if self.last_snap_time else float(window)
            if dt > 0.5:
                dpkts = max(0, self.total_packets - self.last_snap_packets)
                dbytes = max(0, self.total_bytes - self.last_snap_bytes)
                pps = dpkts / dt
                bps = dbytes / dt
                self.time_series.append({
                    "time": time.strftime("%H:%M:%S", time.localtime(now)),
                    "packets_per_sec": round(pps, 1),
                    "bytes_per_sec": round(bps, 1),
                    "active_flows": len(rows),
                    "total_packets": self.total_packets,
                })
                if len(self.time_series) > self.max_history:
                    self.time_series = self.time_series[-self.max_history :]
                self.last_snap_time = now
                self.last_snap_packets = self.total_packets
                self.last_snap_bytes = self.total_bytes

            stats = {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "num_flows": len(rows),
            }
        return pd.DataFrame(rows, columns=COLS), stats

    def record_alerts(self, flagged_df):
        """Appends flagged anomaly records to the persistent session alert log."""
        if flagged_df.empty:
            return
        now_str = time.strftime("%H:%M:%S")
        with self.lock:
            for _, row in flagged_df.iterrows():
                # Deduplicate repeated alerts for ongoing flow in short window
                key = (
                    row.get("src_ip", ""),
                    row.get("dst_ip", ""),
                    row.get("source_port", 0),
                    row.get("dest_port", 0),
                    row.get("protocol", ""),
                    row.get("packets", 0),
                )
                if key in self.seen_alert_keys:
                    continue
                self.seen_alert_keys.add(key)
                if len(self.seen_alert_keys) > 5000:
                    self.seen_alert_keys.clear()

                entry = {
                    "Time": now_str,
                    "Protocol": row.get("protocol", ""),
                    "Source IP": row.get("src_ip", ""),
                    "Dest IP": row.get("dst_ip", ""),
                    "Src Port": row.get("source_port", 0),
                    "Dst Port": row.get("dest_port", 0),
                    "Packets": row.get("packets", 0),
                    "Bytes": row.get("bytes", 0),
                    "Flagged By": row.get("Flagged By", ""),
                    "Severity": row.get("Severity", ""),
                    "Reasons": row.get("Reasons", ""),
                }
                self.alert_log.append(entry)
                if len(self.alert_log) > self.max_alerts:
                    self.alert_log = self.alert_log[-self.max_alerts :]

    def get_alert_log(self):
        """Returns the full session alert log as a DataFrame."""
        with self.lock:
            return pd.DataFrame(self.alert_log)

    def get_time_series(self):
        """Returns the rolling traffic time-series DataFrame."""
        with self.lock:
            return pd.DataFrame(self.time_series)