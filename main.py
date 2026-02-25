import socket
from datetime import datetime
from scapy.all import srp, sniff, conf
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

conf.verb = 0

dns_cache = {}
known_arp_records = {}


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

def scan_network():
    target_ip = get_network_ip()
    print(f"\n[*] Scanning network: {target_ip} ... please wait.")

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    result = srp(packet, timeout=3, verbose=0)[0]

    print("\nFound devices:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)

    clients = []
    for sent, received in result:
        clients.append(received.psrc)
        print(f"{received.psrc}\t\t{received.hwsrc}")

    if not clients:
        print("No device found.")


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

    with open("log.txt", "a", encoding="utf-8") as soubor:
        soubor.write(log_text)


def monitor_traffic():
    print("\n--- Network monitoring (Sniffer) ---")
    user_filter = input("Enter a filter ('tcp', 'udp', 'icmp', etc. - leave empty for all): ")
    packet_count = input("How many packets? (Leave empty or '0' for infinite scanning): ")

    try:
        count = int(packet_count)
    except ValueError:
        count = 0

    regime_text = "Infinite scanning" if count == 0 else f"{count} packets"
    print(f"\n[*] Listening... (Filter: {user_filter if user_filter else 'All'} | Regime: {regime_text})")

    if count == 0:
        print("[!] To shut down a return to the menu press Ctrl+C")

    try:
        sniff(filter=user_filter, prn=packet_callback, count=count)
    except KeyboardInterrupt:
        print("\n\n[*] Monitoring was ended. Returning to main menu...")
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
                with open("network_log.txt", "a", encoding="utf-8") as file:
                    file.write(warning)
        else:
            known_arp_records[ip_address] = new_mac


def run_arp_spoofing_check():
    print("\n--- Security check: ARP spoofing detection ---")
    print("[*] Listening and learning current network status...")
    print("[!] To shut down a return to the menu press Ctrl+C")

    known_arp_records.clear()

    try:
        sniff(filter="arp", prn=check_arp_spoofing, store=0)
    except KeyboardInterrupt:
        print("\n\n[*] Security check was ended.")
    except Exception as exception:
        print(f"\n[!] Error while checking: {exception}")


def main():
    while True:
        print("\n" + "#" * 45)
        print(" Easyshark network analyzer & IDS (Scapy)")
        print("#" * 45)
        print("1. Scan network (Find devices)")
        print("2. Listen to traffic (Sniffer & Filtering)")
        print("3. Security check (intrusion detection)")
        print("4. Shut down")

        choice = input("\nSelect an option (1-4): ")

        if choice == '1':
            scan_network()
        elif choice == '2':
            monitor_traffic()
        elif choice == '3':
            run_arp_spoofing_check()
        elif choice == '4':
            print("Shutting down application. You will find records in 'network_log.txt'.")
            break
        else:
            print("Invalid choice, try again.")


if __name__ == "__main__":
    main()