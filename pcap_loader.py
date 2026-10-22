import os
import tempfile
from pathlib import Path
import pandas as pd
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS


def load_pcap_data(source, max_packets=200000):
    """
    Reads an offline .pcap or .pcapng file streaming with Scapy's PcapReader,
    aggregates packets into network flows, and returns (df, stats).

    Output DataFrame columns:
      - protocol: 'TCP', 'UDP', 'ICMP', 'DNS', or 'Other'
      - packets: number of packets in the flow
      - bytes: total bytes in the flow (sum of packet lengths)
      - duration: end_time - start_time in seconds (0.0 for single-packet flows)
      - source_port: source port (0 for ICMP/non-port protocols)
      - dest_port: destination port (0 for ICMP/non-port protocols)
      - src_ip: source IP address
      - dst_ip: destination IP address

    Flow key:
      (src_ip, dst_ip, src_port, dst_port, protocol)

    Constraints:
      - Does NOT store or export packet payloads.
      - Caps processing at max_packets (default 200,000).
      - Handles empty or corrupted files with clear ValueError messages.
    """
    temp_path = None

    try:
        # Handle Streamlit UploadedFile or file-like buffer by writing to a temporary file
        if hasattr(source, "read"):
            suffix = ".pcap"
            if hasattr(source, "name") and str(source.name).lower().endswith(".pcapng"):
                suffix = ".pcapng"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                if hasattr(source, "seek"):
                    source.seek(0)
                tmp.write(source.read())
                temp_path = tmp.name
            file_path = temp_path
        else:
            file_path = str(source)
            if not os.path.exists(file_path):
                raise ValueError(f"PCAP file not found: {file_path}")

        # Check if file is completely empty (0 bytes)
        if os.path.getsize(file_path) == 0:
            raise ValueError("The PCAP file is empty (0 bytes).")

        flows = {}
        total_packets = 0
        cap_hit = False
        earliest_time = None
        latest_time = None

        try:
            with PcapReader(file_path) as reader:
                for packet in reader:
                    total_packets += 1

                    # Extract timestamp and wire length (without payloads)
                    ts = float(packet.time)
                    pkt_len = len(packet)

                    if earliest_time is None or ts < earliest_time:
                        earliest_time = ts
                    if latest_time is None or ts > latest_time:
                        latest_time = ts

                    # Extract IPs
                    src_ip = "0.0.0.0"
                    dst_ip = "0.0.0.0"
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                    elif IPv6 in packet:
                        src_ip = packet[IPv6].src
                        dst_ip = packet[IPv6].dst

                    # Extract protocol and ports
                    sport = 0
                    dport = 0
                    if packet.haslayer(DNS) or (
                        UDP in packet and (packet[UDP].sport == 53 or packet[UDP].dport == 53)
                    ) or (
                        TCP in packet and (packet[TCP].sport == 53 or packet[TCP].dport == 53)
                    ):
                        proto = "DNS"
                        if UDP in packet:
                            sport = int(packet[UDP].sport)
                            dport = int(packet[UDP].dport)
                        elif TCP in packet:
                            sport = int(packet[TCP].sport)
                            dport = int(packet[TCP].dport)
                    elif TCP in packet:
                        proto = "TCP"
                        sport = int(packet[TCP].sport)
                        dport = int(packet[TCP].dport)
                    elif UDP in packet:
                        proto = "UDP"
                        sport = int(packet[UDP].sport)
                        dport = int(packet[UDP].dport)
                    elif ICMP in packet:
                        proto = "ICMP"
                    else:
                        proto = "Other"

                    flow_key = (src_ip, dst_ip, sport, dport, proto)

                    if flow_key not in flows:
                        flows[flow_key] = {
                            "packets": 1,
                            "bytes": pkt_len,
                            "start_time": ts,
                            "end_time": ts,
                        }
                    else:
                        flow_entry = flows[flow_key]
                        flow_entry["packets"] += 1
                        flow_entry["bytes"] += pkt_len
                        if ts < flow_entry["start_time"]:
                            flow_entry["start_time"] = ts
                        if ts > flow_entry["end_time"]:
                            flow_entry["end_time"] = ts

                    if total_packets >= max_packets:
                        cap_hit = True
                        break

        except Exception as error:
            # Handle corrupted or unreadable PCAP files gracefully
            raise ValueError(f"Error reading PCAP file: {error}")

        if total_packets == 0:
            raise ValueError("No valid network packets found in the PCAP file.")

        records = []
        for (src_ip, dst_ip, sport, dport, proto), f_data in flows.items():
            pkts = f_data["packets"]
            # Single-packet flows have duration 0.0 (leads to NaN rates in Phase 3)
            duration = max(0.0, f_data["end_time"] - f_data["start_time"]) if pkts > 1 else 0.0
            records.append({
                "protocol": proto,
                "packets": pkts,
                "bytes": f_data["bytes"],
                "duration": duration,
                "source_port": sport,
                "dest_port": dport,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            })

        df = pd.DataFrame(records)

        time_span = (latest_time - earliest_time) if (earliest_time and latest_time) else 0.0
        stats = {
            "total_packets": total_packets,
            "num_flows": len(records),
            "time_span": time_span,
            "cap_hit": cap_hit,
            "max_packets": max_packets,
        }

        return df, stats

    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
