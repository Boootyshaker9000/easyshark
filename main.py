import os
import sys
import subprocess
import socket
import argparse
from datetime import datetime


def check_npcap():
    if os.name == 'nt':
        path_to_dll = [
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\System32\wpcap.dll"
        ]

        if not any(os.path.exists(path) for path in path_to_dll):
            print("\n" + "!" * 60)
            print("[!] CRITICAL ERROR: Driver for network card missing (Npcap)!")
            print("[*] It must be installed in order to function properly.")
            print("[*] During installation, be sure to check 'WinPcap API-compatible Mode'.")
            print("!" * 60 + "\n")

            installer = "npcap-installer.exe"
            if os.path.exists(installer):
                answer = input("Installer found. Do you want to run it? (y/n): ")
                if answer.lower() == 'y':
                    print("[*] Running installation...")
                    subprocess.run(installer)
                    print("[*] After completing the installation, restart the program.")
            else:
                print(f"[-] Please download it from the website or place '{installer}' in this folder.")

            sys.exit(1)


check_npcap()

import ipaddress
from scapy.all import srp, sniff, conf
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether, ARP

conf.verb = 0
dns_cache = {}
known_arp_records = {}

def write_to_log(text, filename="log.txt", max_mb=5):
    max_bytes = max_mb * 1024 * 1024

    if os.path.exists(filename):
        if os.path.getsize(filename) >= max_bytes:
            backup_name = filename + ".bak"
            if os.path.exists(backup_name):
                os.remove(backup_name)
            os.rename(filename, backup_name)

    with open(filename, "a", encoding="utf-8") as file:
        file.write(text)


def get_network_ip():
    print("\n--- Network settings ---")
    return input("Enter the network range for scanning (e.g., 192.168.1.0/24): ")


def translate_ip_to_domain(ip_address):
    if ip_address in dns_cache:
        return dns_cache[ip_address]
    try:
        domain = socket.gethostbyaddr(ip_address)[0]
        result = f"{domain} ({ip_address})"
    except (socket.herror, Exception):
        result = ip_address

    dns_cache[ip_address] = result
    return result


def scan_network(target_ip=None):
    if not target_ip:
        target_ip = get_network_ip()

    print(f"\n[*] Scanning network: {target_ip} ... please wait.")

    try:
        network = ipaddress.ip_network(target_ip, strict=False)

        if network.version == 4:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            result = srp(packet, timeout=3, verbose=0)[0]

            print("\nFound devices (IPv4):")
            print("IP Address\t\tMAC Address")
            print("-" * 40)

            clients = []
            for sent, received in result:
                clients.append(received.psrc)
                print(f"{received.psrc}\t\t{received.hwsrc}")

            if not clients:
                print("No device found.")

        elif network.version == 6:
            print("[*] IPv6 network detected. Using ICMPv6 Multicast (All-Nodes) discovery.")
            packet = Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest()
            result = srp(packet, timeout=3, verbose=0)[0]

            print("\nFound devices (IPv6):")
            print("IP Address\t\t\t\tMAC Address")
            print("-" * 65)

            clients = []
            for sent, received in result:
                ip_src = received[IPv6].src
                if ip_src not in clients:
                    clients.append(ip_src)
                    print(f"{ip_src}\t\t{received[Ether].src}")

            if not clients:
                print("No device found.")

    except ValueError:
        print(f"[!] Invalid IP address or network format: {target_ip}")
    except Exception as exception:
        print(f"[!] Error while scanning: {exception}")


def packet_callback(packet):
    log_text = "\n" + "=" * 70 + "\n"
    readable_time = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S')

    source = "Unknown"
    destination = "Unknown"
    communication_type = "Unknown"

    if packet.haslayer(IP):
        source = translate_ip_to_domain(packet[IP].src)
        destination = translate_ip_to_domain(packet[IP].dst)
        communication_type = "IPv4"
    elif packet.haslayer(IPv6):
        source = translate_ip_to_domain(packet[IPv6].src)
        destination = translate_ip_to_domain(packet[IPv6].dst)
        communication_type = "IPv6"
    elif packet.haslayer(ARP):
        source = f"{packet[ARP].hwsrc} (IP: {packet[ARP].psrc})"
        destination = f"{packet[ARP].hwdst} (IP: {packet[ARP].pdst})"
        communication_type = "ARP"
    elif packet.haslayer(Ether):
        source = f"MAC: {packet[Ether].src}"
        destination = f"MAC: {packet[Ether].dst}"
        communication_type = "L2/MAC"

    log_text += f"Time: {readable_time} | Protocol: {communication_type}\n"
    log_text += f"From: {source}  --->  To: {destination}\n"
    log_text += f"Info: {packet.summary()}\n"

    if packet.haslayer('Raw'):
        raw_data = packet['Raw'].load
        try:
            text_data = raw_data.decode('utf-8')
            log_text += f"Text data: {text_data.strip()}...\n"
        except UnicodeDecodeError:
            log_text += f"Data: [Cyphered/binary content, size: {len(raw_data)} bytes]\n"

    print(log_text, end="")
    write_to_log(log_text)


def monitor_traffic(ip_filter=None, port_filter=None, count=0):
    print("\n--- Network monitoring (Sniffer) ---")

    if ip_filter is None and port_filter is None and count == 0:
        ip_filter = input("Enter IP address to filter (leave empty for all): ").strip()
        port_filter = input("Enter port number to filter (leave empty for all): ").strip()
        packet_count = input("How many packets? (Leave empty or '0' for infinite scanning): ").strip()
        try:
            count = int(packet_count) if packet_count else 0
        except ValueError:
            count = 0

    bpf_parts = []
    if ip_filter:
        bpf_parts.append(f"host {ip_filter}")
    if port_filter:
        bpf_parts.append(f"port {port_filter}")

    bpf_filter = " and ".join(bpf_parts)

    regime_text = "Infinite scanning" if count == 0 else f"{count} packets"
    print(f"\n[*] Listening... (Filter: {bpf_filter if bpf_filter else 'All'} | Regime: {regime_text})")

    if count == 0:
        print("[!] To shut down and return to the menu press Ctrl+C")

    try:
        sniff(filter=bpf_filter, prn=packet_callback, count=count)
    except KeyboardInterrupt:
        print("\n\n[*] Monitoring was ended. Returning...")
    except Exception as exception:
        print(f"\n[!] Error while listening: {exception}")


def check_arp_spoofing(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip_address = packet[ARP].psrc
        new_mac = packet[ARP].hwsrc

        if ip_address in known_arp_records:
            old_mac = known_arp_records[ip_address]
            if old_mac != new_mac:
                warning = (f"\n{'!' * 60}\n"
                           f"[!!!] SECURITY WARNING: Possible ARP spoofing detected! [!!!]\n"
                           f"[*] IP {ip_address} changed it's MAC address!\n"
                           f"[*] Previous MAC: {old_mac} | New MAC: {new_mac}\n"
                           f"{'!' * 60}\n")
                print(warning)
                write_to_log(warning)
        else:
            known_arp_records[ip_address] = new_mac


def run_arp_spoofing_check():
    print("\n--- Security check: ARP spoofing detection ---")
    print("[*] Listening and learning current network status...")
    print("[!] To shut down and return to the menu press Ctrl+C")

    known_arp_records.clear()

    try:
        sniff(filter="arp", prn=check_arp_spoofing, store=0)
    except KeyboardInterrupt:
        print("\n\n[*] Security check was ended.")
    except Exception as exception:
        print(f"\n[!] Error while checking: {exception}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Easyshark Network Analyzer & IDS")
    parser.add_argument("--mode", choices=['menu', 'scan', 'sniff', 'ids'], default='menu',
                        help="Run mode (default: menu). Use this to run as a background service.")
    parser.add_argument("--target", help="Target IP/CIDR for scanning (e.g., 192.168.1.0/24)")
    parser.add_argument("--ip", help="Filter traffic by specific IP address (IPv4 or IPv6)")
    parser.add_argument("--port", help="Filter traffic by specific port number")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")

    return parser.parse_args()


def interactive_menu():
    while True:
        print("\n" + "#" * 45)
        print(" Easyshark network analyzer & IDS")
        print("#" * 45)
        print("1. Scan network (Find devices)")
        print("2. Listen to traffic (Sniffer & Filtering)")
        print("3. Security check (intrusion detection)")
        print("4. Shut down")

        try:
            choice = input("\nSelect an option (1-4): ")
        except KeyboardInterrupt:
            break

        if choice == '1':
            scan_network()
        elif choice == '2':
            monitor_traffic()
        elif choice == '3':
            run_arp_spoofing_check()
        elif choice == '4':
            print("Shutting down application. You will find records in 'log.txt'.")
            break
        else:
            print("Invalid choice, try again.")


def main():
    args = parse_arguments()

    if args.mode == 'scan':
        if not args.target:
            print("[!] Please specify --target for scanning mode.")
            sys.exit(1)
        scan_network(target_ip=args.target)

    elif args.mode == 'sniff':
        monitor_traffic(ip_filter=args.ip, port_filter=args.port, count=args.count)

    elif args.mode == 'ids':
        run_arp_spoofing_check()

    else:
        interactive_menu()


if __name__ == "__main__":
    main()