
#!/usr/bin/env python3
"""
Network Traffic Sniffer v3.0
Proyecto educativo de análisis de tráfico con Scapy.

Funciones:
- Captura de paquetes IPv4.
- Identificación de TCP, UDP e ICMP.
- Identificación de servicios y puertos conocidos.
- Estadísticas de protocolos, orígenes y destinos.
- Filtros por protocolo, IP y puerto.
- Exportación CSV.
"""

import argparse
import csv
import socket
import sys
from collections import Counter
from datetime import datetime

from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP


class NetworkSniffer:

    # Servicios conocidos: (protocolo de transporte, puerto)
    SERVICES = {
        # Transferencia de archivos
        ("TCP", 20): "FTP-DATA",
        ("TCP", 21): "FTP",
        ("TCP", 22): "SSH/SFTP",
        ("TCP", 69): "TFTP",

        # Acceso remoto y administración
        ("TCP", 23): "TELNET",
        ("TCP", 3389): "RDP",
        ("TCP", 5900): "VNC",
        ("TCP", 5985): "WINRM-HTTP",
        ("TCP", 5986): "WINRM-HTTPS",

        # Web
        ("TCP", 80): "HTTP",
        ("TCP", 443): "HTTPS",
        ("TCP", 8080): "HTTP-ALT",
        ("TCP", 8000): "HTTP-ALT",
        ("TCP", 8443): "HTTPS-ALT",
        ("UDP", 443): "QUIC/HTTP3",

        # DNS y resolución de nombres
        ("TCP", 53): "DNS",
        ("UDP", 53): "DNS",
        ("UDP", 5353): "MDNS",
        ("UDP", 5355): "LLMNR",

        # Correo electrónico
        ("TCP", 25): "SMTP",
        ("TCP", 465): "SMTPS",
        ("TCP", 587): "SMTP-SUBMISSION",
        ("TCP", 110): "POP3",
        ("TCP", 995): "POP3S",
        ("TCP", 143): "IMAP",
        ("TCP", 993): "IMAPS",

        # Asignación de direcciones y tiempo
        ("UDP", 67): "DHCP-SERVER",
        ("UDP", 68): "DHCP-CLIENT",
        ("UDP", 123): "NTP",

        # Servicios de archivos y Windows
        ("TCP", 135): "MS-RPC",
        ("TCP", 139): "NETBIOS-SESSION",
        ("TCP", 445): "SMB",
        ("UDP", 137): "NETBIOS-NS",
        ("UDP", 138): "NETBIOS-DGM",

        # Administración de red
        ("UDP", 161): "SNMP",
        ("UDP", 162): "SNMP-TRAP",
        ("UDP", 514): "SYSLOG",
        ("UDP", 1900): "SSDP",

        # VPN y comunicaciones
        ("UDP", 500): "IKE/IPSEC",
        ("UDP", 4500): "IPSEC-NAT-T",
        ("UDP", 1194): "OPENVPN",
        ("TCP", 1194): "OPENVPN",

        # Bases de datos
        ("TCP", 1433): "MSSQL",
        ("TCP", 1521): "ORACLE-DB",
        ("TCP", 3306): "MYSQL",
        ("TCP", 5432): "POSTGRESQL",
        ("TCP", 27017): "MONGODB",
        ("TCP", 6379): "REDIS",
        ("TCP", 9200): "ELASTICSEARCH",

        # Otros servicios
        ("TCP", 873): "RSYNC",
        ("TCP", 2049): "NFS",
        ("TCP", 2375): "DOCKER-API",
        ("TCP", 2376): "DOCKER-TLS",
        ("TCP", 6443): "KUBERNETES-API",
    }

    def __init__(self, output=None):
        self.protocols = Counter()
        self.sources = Counter()
        self.destinations = Counter()
        self.ports = Counter()
        self.services = Counter()

        self.csv_file = None
        self.csv_writer = None

        if output:
            self.setup_csv(output)

    def setup_csv(self, filename):
        self.csv_file = open(
            filename,
            "w",
            newline="",
            encoding="utf-8"
        )

        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow([
            "timestamp",
            "protocol",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "service"
        ])

    @classmethod
    def get_service(cls, protocol, port):
        """Identifica un servicio usando protocolo y puerto."""
        if port in ("", None):
            return "N/A"

        port = int(port)
        service = cls.SERVICES.get((protocol, port))

        if service:
            return service

        try:
            return socket.getservbyport(
                port, protocol.lower()
            ).upper()
        except (OSError, ValueError):
            return "UNKNOWN"

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        timestamp = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

        protocol = "OTHER"
        src_port = ""
        dst_port = ""
        service = "N/A"

        self.sources[ip.src] += 1
        self.destinations[ip.dst] += 1

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        if protocol in ("TCP", "UDP"):
            # Primero identifica el puerto de destino.
            service = self.get_service(protocol, dst_port)

            # Si no lo reconoce, revisa el puerto de origen.
            if service == "UNKNOWN":
                source_service = self.get_service(
                    protocol, src_port
                )
                if source_service != "UNKNOWN":
                    service = source_service

            self.ports[(protocol, dst_port, service)] += 1
            self.services[service] += 1

        self.protocols[protocol] += 1

        source = (
            f"{ip.src}:{src_port}"
            if src_port != "" else ip.src
        )
        destination = (
            f"{ip.dst}:{dst_port}"
            if dst_port != "" else ip.dst
        )

        print(
            f"{timestamp} | {protocol:<5} | "
            f"{source:<22} -> {destination:<22} | "
            f"Servicio: {service}",
            flush=True
        )

        if self.csv_writer:
            self.csv_writer.writerow([
                timestamp,
                protocol,
                ip.src,
                ip.dst,
                src_port,
                dst_port,
                service
            ])
            self.csv_file.flush()

    def show_protocol_statistics(self):
        total = sum(self.protocols.values())

        print("\n" + "=" * 70)
        print("ESTADÍSTICAS POR PROTOCOLO")
        print("=" * 70)

        for proto, count in self.protocols.most_common():
            percentage = count * 100 / total if total else 0
            print(
                f"{proto:<10} {count:>8} "
                f"({percentage:.2f}%)"
            )

        print(f"\nTOTAL: {total} paquetes")

    def show_top_sources(self):
        print("\n" + "=" * 70)
        print("TOP ORÍGENES")
        print("=" * 70)

        for ip, count in self.sources.most_common(10):
            print(f"{ip:<40} {count:>8} paquetes")

    def show_top_destinations(self):
        print("\n" + "=" * 70)
        print("TOP DESTINOS")
        print("=" * 70)

        for ip, count in self.destinations.most_common(10):
            print(f"{ip:<40} {count:>8} paquetes")

    def show_top_ports(self):
        print("\n" + "=" * 78)
        print("PUERTOS Y SERVICIOS DETECTADOS")
        print("=" * 78)
        print(
            f"{'PROTOCOLO':<12}"
            f"{'PUERTO DESTINO':<17}"
            f"{'SERVICIO':<25}"
            f"{'PAQUETES':>10}"
        )
        print("-" * 64)

        for (protocol, port, service), count in (
            self.ports.most_common(15)
        ):
            print(
                f"{protocol:<12}"
                f"{port:<17}"
                f"{service:<25}"
                f"{count:>10}"
            )

        if not self.ports:
            print("No se detectaron puertos TCP/UDP.")

    def show_top_services(self):
        print("\n" + "=" * 70)
        print("TOP SERVICIOS")
        print("=" * 70)

        for service, count in self.services.most_common(10):
            print(f"{service:<28} {count:>8} paquetes")

        if not self.services:
            print("No se detectaron servicios TCP/UDP.")

    def close(self):
        if self.csv_file:
            self.csv_file.close()


def build_filter(args):
    filters = []

    if args.protocol:
        filters.append(args.protocol)

    if args.host:
        filters.append(f"host {args.host}")

    if args.port:
        filters.append(f"port {args.port}")

    return " and ".join(filters) if filters else None


def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Sniffer v3.0"
    )

    parser.add_argument(
        "-i", "--interface",
        help="Interfaz de captura, por ejemplo eth0 o lo"
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Mostrar interfaces disponibles"
    )
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp", "icmp"],
        help="Filtrar por protocolo"
    )
    parser.add_argument(
        "--host",
        help="Filtrar por IP o nombre de host"
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Filtrar por puerto"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Paquetes a capturar; 0 significa captura continua"
    )
    parser.add_argument(
        "--output",
        help="Guardar resultados en CSV"
    )

    args = parser.parse_args()

    if args.list_interfaces:
        print("Interfaces disponibles:")
        for interface in get_if_list():
            print(f"  {interface}")
        return

    if args.count < 0:
        parser.error("--count no puede ser negativo")

    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port debe estar entre 1 y 65535")

    if args.interface and args.interface not in get_if_list():
        parser.error(
            "Interfaz no encontrada. Usa --list-interfaces."
        )

    sniffer = None
    bpf_filter = build_filter(args)

    print("=" * 78)
    print("NETWORK TRAFFIC SNIFFER v3.0")
    print("=" * 78)
    print(f"Interfaz: {args.interface or 'predeterminada'}")
    print(f"Filtro: {bpf_filter or 'ninguno'}")
    print(f"Límite: {args.count or 'sin límite'}")
    print(f"CSV: {args.output or 'desactivado'}")
    print("Pulsa Ctrl+C para detener la captura.")
    print("=" * 78)

    try:
        sniffer = NetworkSniffer(args.output)

        sniff(
            iface=args.interface,
            filter=bpf_filter,
            prn=sniffer.process_packet,
            store=False,
            count=args.count
        )

    except KeyboardInterrupt:
        print("\nCaptura detenida.")

    except (OSError, ValueError) as exc:
        print(f"\nError de captura: {exc}", file=sys.stderr)
        sys.exit(1)

    finally:
        if sniffer:
            sniffer.show_protocol_statistics()
            sniffer.show_top_sources()
            sniffer.show_top_destinations()
            sniffer.show_top_ports()
            sniffer.show_top_services()
            sniffer.close()


if __name__ == "__main__":
    main()
