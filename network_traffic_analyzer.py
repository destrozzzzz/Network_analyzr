import scapy.all as scapy
import time
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import threading

# Print available network interfaces
interfaces = scapy.get_if_list()
print("Available network interfaces:")
for idx, iface in enumerate(interfaces):
    print(f"{idx + 1}: {iface}")

# Let the user select an interface by number
interface_num = int(input("Enter the number of the network interface you want to use: "))
selected_interface = interfaces[interface_num - 1]
print(f"Selected interface: {selected_interface}")

# List to store captured packet data
packets_data = []

# Dictionary to track source IP traffic
ip_traffic = {}

# Thresholds for anomaly detection
PACKET_THRESHOLD = 100  # Threshold for DDoS detection
TRAFFIC_VOLUME_THRESHOLD = 100  # Threshold for traffic volume spike (in packets per second)
RTT_THRESHOLD = 0.5  # Threshold for RTT (in seconds)

# Function to capture packets and extract useful info
def capture_packets(packet):
    if packet.haslayer(scapy.IP):  # Only process IP packets
        ip_src = packet[scapy.IP].src  # Source IP address
        ip_dst = packet[scapy.IP].dst  # Destination IP address
        protocol = packet.proto  # Protocol (e.g., TCP, UDP)
        packet_length = len(packet)  # Length of the packet in bytes
        timestamp = time.time()  # Timestamp when packet was captured
        
        # Detect anomalies based on traffic volume from one IP
        if ip_src not in ip_traffic:
            ip_traffic[ip_src] = {'count': 0, 'last_seen': timestamp, 'protocol_count': {}}
        
        # Increment packet count and protocol count
        ip_traffic[ip_src]['count'] += 1
        ip_traffic[ip_src]['last_seen'] = timestamp
        
        # Detect anomalies like too many packets from one source (possible DDoS)
        if ip_traffic[ip_src]['count'] > PACKET_THRESHOLD:  # Threshold for anomaly detection (e.g., more than 100 packets from one IP)
            print(f"Anomaly Detected! IP {ip_src} sent {ip_traffic[ip_src]['count']} packets.")
        
        # Track protocol usage per source IP
        if protocol not in ip_traffic[ip_src]['protocol_count']:
            ip_traffic[ip_src]['protocol_count'][protocol] = 0
        ip_traffic[ip_src]['protocol_count'][protocol] += 1

        # Detect unusual protocol usage
        if ip_traffic[ip_src]['protocol_count'][protocol] > 50:  # Threshold for unusual protocol usage
            print(f"Unusual Protocol Usage! IP {ip_src} is using Protocol {protocol} unusually often.")

        # Detect traffic spikes within a short time frame (e.g., 100 packets within 1 second)
        if ip_traffic[ip_src]['count'] > TRAFFIC_VOLUME_THRESHOLD and (timestamp - ip_traffic[ip_src]['last_seen']) < 1:
            print(f"Traffic Spike Detected! IP {ip_src} sent {ip_traffic[ip_src]['count']} packets in the last second.")

        # Performance analysis - calculate RTT (Round Trip Time) based on SYN and ACK packets
        if packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].flags == 'S':  # SYN packet
                timestamp_syn = time.time()
                ip_src = packet[scapy.IP].src
                if ip_src not in ip_traffic:
                    ip_traffic[ip_src] = {}
                ip_traffic[ip_src]['SYN_timestamp'] = timestamp_syn
            elif packet[scapy.TCP].flags == 'A':  # ACK packet
                if ip_src in ip_traffic and 'SYN_timestamp' in ip_traffic[ip_src]:
                    rtt = time.time() - ip_traffic[ip_src]['SYN_timestamp']
                    if rtt > RTT_THRESHOLD:
                        print(f"High RTT Detected! IP {ip_src} has an RTT of {rtt} seconds.")

        # Store the captured packet details in a dictionary
        packet_data = {
            'Source IP': ip_src,
            'Destination IP': ip_dst,
            'Protocol': protocol,
            'Packet Length': packet_length,
            'Timestamp': timestamp  # Timestamp when packet was captured
        }

        # Add packet data to the list
        packets_data.append(packet_data)

# Function to start capturing packets on a given network interface
def start_capture(interface="eth0", packet_count=100):
    print(f"Starting packet capture on {interface} for {packet_count} packets...")
    scapy.sniff(iface=interface, prn=capture_packets, store=False, count=packet_count)  # Capture a fixed number of packets

# Function to detect traffic anomalies (e.g., DDoS, too many packets from one IP)
def detect_anomalies(packets_data):
    ip_counts = Counter([pkt['Source IP'] for pkt in packets_data])
    for ip, count in ip_counts.items():
        if count > PACKET_THRESHOLD:  # Threshold for anomaly detection (e.g., more than 100 packets from one IP)
            print(f"Anomaly Detected! IP {ip} sent {count} packets.")

# Function to detect suspicious traffic patterns (e.g., port scanning, SYN floods)
def detect_suspicious_traffic(packets_data):
    tcp_packets = [pkt for pkt in packets_data if pkt['Protocol'] == 6]  # Filter for TCP packets
    src_ports = [pkt['Source IP'] for pkt in tcp_packets]
    dst_ports = [pkt['Destination IP'] for pkt in tcp_packets]

    # Detect port scanning behavior by counting distinct destination ports from a source IP
    src_port_counts = Counter(src_ports)
    for ip, count in src_port_counts.items():
        if count > 20:  # If the source IP attempts connections to more than 20 ports
            print(f"Suspicious Traffic: IP {ip} is scanning multiple ports.")

# Function to visualize packet protocol distribution
def plot_protocol_distribution(packets_data):
    protocols = [pkt['Protocol'] for pkt in packets_data]
    protocol_counts = Counter(protocols)
    plt.bar(protocol_counts.keys(), protocol_counts.values())
    plt.xlabel('Protocol')
    plt.ylabel('Packet Count')
    plt.title('Protocol Distribution in Network Traffic')
    plt.show()

# Function to periodically capture packets and analyze them
def analyze_traffic(interface="eth0"):
    try:
        print("Network Traffic Analyzer started...")

        while True:
            # Capture packets in batches
            start_capture(interface, packet_count=100)  # Capture 100 packets at a time
            
            # Perform anomaly detection, performance analysis, and visualization every batch
            if len(packets_data) > 0:
                print(f"Analyzing {len(packets_data)} captured packets...")
                detect_anomalies(packets_data)
                detect_suspicious_traffic(packets_data)  # Detect suspicious traffic patterns
                plot_protocol_distribution(packets_data)  # Visualize the protocol distribution
                packets_data.clear()  # Clear the list after analysis
            
            # Add a small delay to prevent excessive CPU usage (give some time for capture)
            time.sleep(5)

    except KeyboardInterrupt:
        print("\nTraffic capture stopped by user.")
        # When the user interrupts the capture, save the packet data
        print(f"Captured {len(packets_data)} packets in total.")
        print("Exiting program...")

# Run the script if this file is executed directly
if __name__ == "__main__":
    interface = input("Enter the network interface (e.g., Ethernet, Wi-Fi): ").strip()
    analyze_traffic(interface)
