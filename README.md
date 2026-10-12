# 🦈 Network Traffic Sniffer

Network Traffic Sniffer and Analyzer developed in Python using Scapy.

## Features

- TCP Analysis
- UDP Analysis
- ICMP Analysis
- Top Sources
- Top Destinations
- Top Ports
- Top Services
- Traffic Statistics
- CSV Export
- Protocol Filtering
- Host Filtering
- Port Filtering

## Requirements

- Python 3.12+
- Scapy

## Installation

Clone repository:

```bash
git clone https://github.com/carlosarauz578-source/network-traffic-sniffer.git

cd network-traffic-sniffer
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Capture traffic:

```bash
sudo python3 sniffer.py
```

Capture 100 packets:

```bash
sudo python3 sniffer.py --count 100
```

Capture TCP only:

```bash
sudo python3 sniffer.py --protocol tcp
```

Capture HTTPS traffic:

```bash
sudo python3 sniffer.py --port 443
```

Export results:

```bash
sudo python3 sniffer.py --count 1000 --output capture.csv
```

## Example Output

```text
TCP | 192.168.1.10:52341 -> 142.251.214.238:443 | HTTPS

UDP | 192.168.1.10:53012 -> 8.8.8.8:53 | DNS

ICMP | 192.168.1.10 -> 8.8.8.8
```

## Statistics

The application generates:

- Protocol statistics
- Top source IPs
- Top destination IPs
- Top destination ports
- Top detected services

## Technologies

- Python
- Scapy
- Socket Programming
- argparse
- CSV
- GitHub

## License

This project is licensed under the MIT License.
