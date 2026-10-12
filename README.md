# 🦈 Network Traffic Sniffer

A Python-based network traffic sniffer and analyzer built with [Scapy](https://scapy.net/). Designed as a cybersecurity learning project to capture, inspect, classify, and analyze network traffic.

## 🚀 Features

- **Packet Capture:** Capture IPv4 network packets in real time.
- **Protocol Analysis:** Identify TCP, UDP, ICMP, and other IPv4 traffic.
- **Service Identification:** Recognize common services based on transport protocol and port.
- **Port Analysis:** Display frequently observed destination ports and associated services.
- **Traffic Statistics:** Summarize packet counts by protocol.
- **Source Analysis:** Identify the most frequent source IP addresses.
- **Destination Analysis:** Identify the most frequent destination IP addresses.
- **Service Statistics:** Display the most frequently observed services.
- **CSV Export:** Save packet metadata for later analysis.
- **Packet Filtering:** Filter captures by protocol, host, or port.
- **Command-Line Interface:** Configure captures using command-line arguments.

## 🔎 Supported Services

The analyzer can identify common services using known TCP/UDP port mappings.

| Service | Transport | Default Port |
|---|---|---:|
| FTP | TCP | 21 |
| SSH / SFTP | TCP | 22 |
| Telnet | TCP | 23 |
| SMTP | TCP | 25 |
| DNS | TCP / UDP | 53 |
| DHCP Server | UDP | 67 |
| DHCP Client | UDP | 68 |
| TFTP | UDP | 69 |
| HTTP | TCP | 80 |
| POP3 | TCP | 110 |
| NTP | UDP | 123 |
| IMAP | TCP | 143 |
| HTTPS | TCP | 443 |
| SMB | TCP | 445 |
| SMTPS | TCP | 465 |
| SMTP Submission | TCP | 587 |
| POP3S | TCP | 995 |
| IMAPS | TCP | 993 |
| OpenVPN | TCP / UDP | 1194 |
| MySQL | TCP | 3306 |
| RDP | TCP | 3389 |
| PostgreSQL | TCP | 5432 |
| Redis | TCP | 6379 |
| HTTP Alternative | TCP | 8080 |
| HTTPS Alternative | TCP | 8443 |
| QUIC / HTTP/3 | UDP | 443 |
| mDNS | UDP | 5353 |
| SNMP | UDP | 161 |

**Note:** Port-based identification is an estimate, not proof of the application or service running on a connection. Custom ports and encrypted traffic may require deeper analysis.

## 🛠️ Technologies

- Python 3
- Scapy
- Socket programming
- `argparse`
- `collections.Counter`
- CSV
- Git and GitHub

## 📋 Requirements

- Python 3.12 or newer
- Scapy
- Linux recommended for packet capture
- Appropriate permissions to capture traffic

## 📥 Installation

Clone the repository:

```bash
git clone https://github.com/carlosarauz578-source/network-traffic-sniffer.git
cd network-traffic-sniffer
```

Install the dependencies:

```bash
python3 -m pip install -r requirements.txt
```

On Kali Linux, you can also use a virtual environment if your system Python restricts global package installation.

## ▶️ Usage

### Capture traffic

```bash
sudo python3 sniffer.py
```

Stop continuous capture with `Ctrl+C`.

### Capture 100 packets

```bash
sudo python3 sniffer.py --count 100
```

### Capture TCP traffic only

```bash
sudo python3 sniffer.py --protocol tcp
```

### Capture UDP traffic only

```bash
sudo python3 sniffer.py --protocol udp
```

### Filter by port

Capture traffic involving HTTPS's standard port:

```bash
sudo python3 sniffer.py --port 443
```

Capture traffic involving DNS's standard port:

```bash
sudo python3 sniffer.py --port 53
```

Capture traffic involving SSH's standard port:

```bash
sudo python3 sniffer.py --port 22
```

### Filter by host

```bash
sudo python3 sniffer.py --host 192.168.1.10
```

Replace the example address with an IP address appropriate for your authorized test environment.

### Export packet metadata to CSV

```bash
sudo python3 sniffer.py --count 1000 --output capture.csv
```

### Select a network interface

If supported by the installed version of `sniffer.py`, select an interface explicitly:

```bash
sudo python3 sniffer.py --interface eth0 --count 100
```

Check the actual command-line options supported by your version before using optional arguments.

## 📊 Example Output

The following is illustrative output, not a live capture:

```text
2026-10-12T10:30:00 | TCP   | 192.168.1.10:52341 -> 142.251.214.238:443 | Service: HTTPS
2026-10-12T10:30:01 | UDP   | 192.168.1.10:53012 -> 8.8.8.8:53           | Service: DNS
2026-10-12T10:30:02 | TCP   | 192.168.1.10:51234 -> 192.168.1.20:22    | Service: SSH
2026-10-12T10:30:03 | ICMP  | 192.168.1.10 -> 8.8.8.8                 | Service: N/A
```

Actual output depends on the implementation, the selected interface, and the traffic visible during capture.

## 📈 Statistics

When the capture ends, the analyzer can display:

- Packet counts and percentages by protocol.
- Top source IP addresses.
- Top destination IP addresses.
- Frequently observed destination ports.
- Frequently observed services.

## 📁 Project Structure

```text
network-traffic-sniffer/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── sniffer.py
```

## 🔐 Ethical Use

This project is intended for cybersecurity education, authorized troubleshooting, and network traffic analysis.

- Capture traffic only on systems and networks you own or have permission to monitor.
- Respect privacy and applicable laws.
- Remember that packet visibility depends on the network interface, capture permissions, and network configuration.

## 🎯 Project Goals

This project demonstrates practical skills in:

- Python scripting
- Network protocols and port identification
- Packet capture with Scapy
- Command-line argument handling
- Traffic statistics and CSV reporting
- Basic network troubleshooting

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

## 👨‍💻 Author

**Carlos Rodríguez Araúz**

GitHub: [@carlosarauz578-source](https://github.com/carlosarauz578-source)
