import os
import tempfile

from scapy.all import sniff, wrpcap

from pcap_loader import load_pcap_data


def capture_live(seconds=10, iface=None, max_packets=20000):
    """Capture for `seconds`, aggregate into flows, delete the temp file.
    Returns (df, stats). Only capture traffic you are authorized to monitor."""
    packets = sniff(timeout=seconds, iface=iface or None, count=max_packets, store=True)
    if len(packets) == 0:
        raise ValueError("No packets captured. Check the interface name and run as Administrator.")
    path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            path = tmp.name
        wrpcap(path, packets)
        return load_pcap_data(path, max_packets=max_packets)
    finally:
        if path and os.path.exists(path):
            os.remove(path)