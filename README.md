Network Traffic Analyzer
A real-time network traffic monitoring system designed to capture and analyze network packets. This project helps detect anomalies, visualize network protocol distribution, and enhance network security by identifying potential threats or performance bottlenecks.

Features
Real-time packet capture: Continuously captures network traffic.
Anomaly detection: Identifies unusual traffic patterns (e.g., excessive packets from a single IP).
Protocol distribution visualization: Displays a bar chart of the protocol distribution (e.g., TCP, UDP, ICMP).
Packet analysis: Extracts details like source IP, destination IP, protocol, and packet size.
Performance monitoring: Detects potential performance bottlenecks based on packet volume.
Requirements
Python 3.x
scapy library
matplotlib for data visualization
pandas for data handling (optional, based on your project needs)
To install the required libraries, you can use pip:

bash
Copy code
pip install scapy matplotlib pandas
Optional: For Windows Users
If you're using Windows, you may need to install Npcap to enable packet sniffing capabilities. You can download it here.

Usage
Clone the repository to your local machine:

bash
Copy code
git clone https://github.com/your-username/network-traffic-analyzer.git
cd network-traffic-analyzer
Run the script:

bash
Copy code
python network_traffic_analyzer.py
Enter the network interface you want to use (e.g., Ethernet, Wi-Fi, or eth0). The script will start capturing and analyzing network packets.

Anomaly detection: After capturing a certain number of packets, the script will check for any anomalies, such as an unusually high number of packets from a single source IP.

Protocol distribution chart: The script will periodically display a bar chart of the different network protocols (e.g., TCP, UDP, ICMP) in the captured traffic.

To stop the capture, simply press Ctrl+C.

Example Output
During execution, the following information will be printed to the console for each captured packet:

yaml
Copy code
Source IP: 192.168.1.1, Destination IP: 192.168.1.2, Protocol: 6 (TCP), Packet Length: 64 bytes
Additionally, a protocol distribution chart will be displayed, showing the count of different protocols.

Anomaly Detection
If a specific IP address sends more than a set number of packets (e.g., 100 packets), the system will flag it as an anomaly:

Copy code
Anomaly Detected! IP 192.168.1.1 sent 120 packets.
Contributing
Fork the repository.
Create a new branch (git checkout -b feature-name).
Make your changes.
Commit your changes (git commit -m 'Add feature').
Push to your branch (git push origin feature-name).
Open a pull request.


How to Customize
Threshold for Anomalies: The script currently flags IPs sending more than 100 packets as anomalies. You can adjust this threshold in the detect_anomalies function.

Network Interface: The script will ask you for the network interface to capture traffic from (e.g., Wi-Fi, Ethernet). You can modify the default interface in the code if needed.

