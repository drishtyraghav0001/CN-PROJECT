import threading
import time

import pandas as pd
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP

COLS = ["protocol", "packets", "bytes", "duration", "source_port", "dest_port", "src_ip", "dst_ip"]


class LiveMonitor:
    """Continuous background capture. Aggregates flows only; payloads are never stored."""

    def __init__(self, max_flows=20000):
        self.lock = threading.Lock()
        self.flows = {}
        self.sniffer = None
        self.active = False
        self.total_packets = 0
        self.max_flows = max_flows

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
        cutoff = time.time() - window
        rows = []
        with self.lock:
            for key in list(self.flows):
                f = self.flows[key]
                if f["last"] < cutoff:
                    del self.flows[key]
                    continue
                src, dst, sport, dport, proto = key
                dur = max(0.0, f["last"] - f["start"]) if f["packets"] > 1 else 0.0
                rows.append({"protocol": proto, "packets": f["packets"], "bytes": f["bytes"],
                             "duration": dur, "source_port": sport, "dest_port": dport,
                             "src_ip": src, "dst_ip": dst})
            stats = {"total_packets": self.total_packets, "num_flows": len(rows)}
        return pd.DataFrame(rows, columns=COLS), stats