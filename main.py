import socket
from datetime import datetime
from scapy.all import srp, sniff, conf
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

conf.verb = 0

dns_cache = {}
zname_arp_zaznamy = {}


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
    print(f"\n[*] Skenuji síť: {target_ip} ... čekejte prosím.")

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    result = srp(packet, timeout=3, verbose=0)[0]

    print("\nNalezená zařízení:")
    print("IP Adresa\t\tMAC Adresa")
    print("-" * 40)

    clients = []
    for sent, received in result:
        clients.append(received.psrc)
        print(f"{received.psrc}\t\t{received.hwsrc}")

    if not clients:
        print("Žádná zařízení nebyla nalezena.")


def packet_callback(packet):
    """Funkce pro detailní výpis paketů a logování do souboru."""
    log_text = "\n" + "=" * 70 + "\n"
    citelny_cas = datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S')

    zdroj = "Neznámý"
    cil = "Neznámý"
    typ_komunikace = "Neznámý typ"

    if packet.haslayer(IP):
        zdroj = translate_ip_to_domain(packet[IP].src)
        cil = translate_ip_to_domain(packet[IP].dst)
        typ_komunikace = "IPv4"
    elif packet.haslayer(IPv6):
        zdroj = translate_ip_to_domain(packet[IPv6].src)
        cil = translate_ip_to_domain(packet[IPv6].dst)
        typ_komunikace = "IPv6"
    elif packet.haslayer(ARP):
        zdroj = f"{packet[ARP].hwsrc} (IP: {packet[ARP].psrc})"
        cil = f"{packet[ARP].hwdst} (IP: {packet[ARP].pdst})"
        typ_komunikace = "ARP"
    elif packet.haslayer(Ether):
        zdroj = f"MAC: {packet[Ether].src}"
        cil = f"MAC: {packet[Ether].dst}"
        typ_komunikace = "L2/MAC"

    log_text += f"Čas: {citelny_cas} | Protokol: {typ_komunikace}\n"
    log_text += f"Z: {zdroj}  --->  Do: {cil}\n"
    log_text += f"Info: {packet.summary()}\n"

    if packet.haslayer('Raw'):
        surova_data = packet['Raw'].load
        try:
            textova_data = surova_data.decode('utf-8')
            log_text += f"Textová data: {textova_data.strip()}...\n"
        except UnicodeDecodeError:
            log_text += f"Data: [Šifrovaný/binární obsah, velikost: {len(surova_data)} bytů]\n"

    print(log_text, end="")

    with open("log.txt", "a", encoding="utf-8") as soubor:
        soubor.write(log_text)


def sledovani_dopravy():
    """Požadavek: Sledování dopravy a filtrování podle uživatelského vstupu."""
    print("\n--- Sledování sítě (Sniffer) ---")
    user_filter = input("Zadejte filtr (např. 'tcp', 'udp', 'icmp' - nechte prázdné pro vše): ")
    packet_count = input("Kolik packetů zachytit? (Nechte prázdné nebo '0' pro NEKONEČNÉ sledování): ")

    try:
        count = int(packet_count)
    except ValueError:
        count = 0

    režim_text = "Nekonečné sledování" if count == 0 else f"{count} packetů"
    print(f"\n[*] Spouštím odposlech... (Filtr: {user_filter if user_filter else 'Vše'} | Režim: {režim_text})")

    if count == 0:
        print("[!] Pro UKONČENÍ a návrat do menu stiskněte Ctrl+C")

    try:
        sniff(filter=user_filter, prn=packet_callback, count=count)
    except KeyboardInterrupt:
        print("\n\n[*] Sledování bylo ručně ukončeno. Vracím se do hlavního menu...")
    except Exception as e:
        print(f"\n[!] Chyba při odposlechu: {e}")


# ==========================================
# 3. BEZPEČNOSTNÍ MONITOR (IDS)
# ==========================================

def bezpecnostni_kontrola_arp(packet):
    """Hledá anomálie (změnu MAC adresy za běhu - ARP Spoofing)."""
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip_adresa = packet[ARP].psrc
        mac_adresa = packet[ARP].hwsrc

        if ip_adresa in zname_arp_zaznamy:
            stara_mac = zname_arp_zaznamy[ip_adresa]
            if stara_mac != mac_adresa:
                varovani = (f"\n{'!' * 60}\n"
                            f"[!!!] BEZPEČNOSTNÍ VAROVÁNÍ: Detekován možný ARP Spoofing! [!!!]\n"
                            f"[*] IP {ip_adresa} změnila MAC adresu!\n"
                            f"[*] Původní MAC: {stara_mac} | Nová MAC: {mac_adresa}\n"
                            f"{'!' * 60}\n")
                print(varovani)
                with open("sitovy_log.txt", "a", encoding="utf-8") as soubor:
                    soubor.write(varovani)
        else:
            zname_arp_zaznamy[ip_adresa] = mac_adresa


def spustit_bezpecnostni_monitor():
    """Spustí monitorování útoků v lokální síti."""
    print("\n--- Bezpečnostní monitor: Detekce ARP Spoofingu ---")
    print("[*] Naslouchám a učím se aktuální stav sítě...")
    print("[!] Pro UKONČENÍ a návrat do menu stiskněte Ctrl+C")

    zname_arp_zaznamy.clear()

    try:
        sniff(filter="arp", prn=bezpecnostni_kontrola_arp, store=0)
    except KeyboardInterrupt:
        print("\n\n[*] Bezpečnostní monitor byl ukončen.")
    except Exception as e:
        print(f"\n[!] Chyba při spuštění monitoru: {e}")


# ==========================================
# 4. HLAVNÍ MENU
# ==========================================

def main():
    while True:
        print("\n" + "#" * 45)
        print(" JEDNODUCHÝ SÍŤOVÝ ANALYZÁTOR & IDS (Scapy)")
        print("#" * 45)
        print("1. Skenovat síť (Najít zařízení)")
        print("2. Sledovat provoz (Sniffer & Filtrování)")
        print("3. Bezpečnostní monitor (Detekce útoků)")
        print("4. Konec")

        volba = input("\nVyberte možnost (1-4): ")

        if volba == '1':
            skenovani_site()
        elif volba == '2':
            sledovani_dopravy()
        elif volba == '3':
            spustit_bezpecnostni_monitor()
        elif volba == '4':
            print("Ukončuji program. Záznamy najdete v 'sitovy_log.txt'.")
            break
        else:
            print("Neplatná volba, zkuste to znovu.")


if __name__ == "__main__":
    main()