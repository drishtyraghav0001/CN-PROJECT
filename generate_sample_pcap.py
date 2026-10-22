import time
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap


def generate_sample_pcap(output_path="sample_traffic.pcap"):
    """
    Generates a synthetic offline PCAP capture containing:
      - Normal synthetic TCP, UDP, DNS, and ICMP flows
      - Single-packet flows (e.g. probes) to test duration=0 handling
      - One burst of high-rate anomalous traffic (SYN/data flood)
    All IP addresses and payloads are strictly synthetic.
    """
    packets = []
    base_time = 1700000000.0  # Synthetic epoch reference timestamp

    # 1. Normal TCP web traffic flow (Client 192.168.1.10 -> Web Server 10.0.0.5:443)
    # 20 packets across 10 seconds
    src_ip = "192.168.1.10"
    dst_ip = "10.0.0.5"
    src_port = 49152
    dst_port = 443
    for i in range(20):
        t = base_time + (i * 0.5)
        # Synthetic TCP payload
        p = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1000 + i * 500) / (b"X" * 450)
        p.time = t
        packets.append(p)

    # 2. Normal DNS queries/responses (Client 192.168.1.10 -> DNS Server 8.8.8.8:53)
    # 4 packets across 2 seconds
    for i in range(4):
        t = base_time + 1.0 + (i * 0.5)
        dns_req = IP(src=src_ip, dst="8.8.8.8") / UDP(sport=53001, dport=53) / DNS(rd=1, qd=DNSQR(qname="test.local"))
        dns_req.time = t
        packets.append(dns_req)

    # 3. Normal UDP traffic (Client 192.168.1.20 -> Media Server 10.0.0.8:5004)
    # 30 packets across 6 seconds
    for i in range(30):
        t = base_time + 2.0 + (i * 0.2)
        p = IP(src="192.168.1.20", dst="10.0.0.8") / UDP(sport=51234, dport=5004) / (b"U" * 200)
        p.time = t
        packets.append(p)

    # 4. Normal ICMP echo (Client 192.168.1.30 -> Gateway 10.0.0.1)
    # 5 packets across 4 seconds
    for i in range(5):
        t = base_time + 0.5 + (i * 1.0)
        p = IP(src="192.168.1.30", dst="10.0.0.1") / ICMP(type=8, code=0) / (b"ping" * 8)
        p.time = t
        packets.append(p)

    # 5. Single-packet flow (tests single-packet duration=0 and rate NaN handling)
    single_p = IP(src="192.168.1.99", dst="10.0.0.99") / TCP(sport=60001, dport=22, flags="S")
    single_p.time = base_time + 3.0
    packets.append(single_p)

    # 6. Another normal TCP flow (Client 192.168.1.40:55555 -> 10.0.0.20:80)
    for i in range(15):
        t = base_time + 3.5 + (i * 0.4)
        p = IP(src="192.168.1.40", dst="10.0.0.20") / TCP(sport=55555, dport=80, flags="A") / (b"GET / HTTP/1.1\r\n" + b"H" * 300)
        p.time = t
        packets.append(p)

    # 7. High-rate anomalous burst traffic (Flooder 192.168.1.250 -> Target 10.0.0.100:8080)
    # 500 packets squeezed into 0.25 seconds (2000 pkts/sec!)
    burst_src = "192.168.1.250"
    burst_dst = "10.0.0.100"
    burst_port = 44444
    for i in range(500):
        t = base_time + 7.0 + (i * 0.0005)
        p = IP(src=burst_src, dst=burst_dst) / TCP(sport=burst_port, dport=8080, flags="PA") / (b"B" * 600)
        p.time = t
        packets.append(p)

    # Sort packets chronologically
    packets.sort(key=lambda x: x.time)

    # Write pcap file
    wrpcap(output_path, packets)
    print(f"Successfully generated synthetic PCAP with {len(packets)} packets at {output_path}")
    return output_path


if __name__ == "__main__":
    generate_sample_pcap()
