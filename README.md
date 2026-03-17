# EasyShark Network Analyzer & IDS

EasyShark is a lightweight, Python-based network analysis and Intrusion Detection System (IDS) tool. It is designed to be user-friendly for beginners in IT while offering powerful background-service capabilities for advanced users. It utilizes the `scapy` library for low-level packet manipulation.

## Features
* **Network Scanning:** ARP scanning to discover active devices and their MAC addresses on the local network.
* **Traffic Sniffing:** Monitor network traffic in real-time with automatic DNS resolution (IP to Domain) and smart payload decoding.
* **Traffic Filtering:** Filter captured packets by specific IPv4/IPv6 addresses, ports, or protocol types using BPF syntax.
* **Security Monitor (IDS):** Detects ARP Spoofing (Man-in-the-Middle) attacks by monitoring unexpected MAC address changes.
* **Log Rotation:** Automatically logs captured data to `log.txt` and rotates the file when it reaches 5 MB.

---

## Prerequisites and Installation

1. **Python 3.x** must be installed on your system.
2. Install the required Python library:
   ```bash
   pip install scapy
   ```
3. **For Windows Users Only:** Low-level packet sniffing requires the **Npcap** driver. 
   * The script automatically checks for its presence upon startup.
   * If missing, it will prompt you to install it using the bundled `npcap-installer.exe` (make sure to check the **"Install Npcap in WinPcap API-compatible Mode"** option during installation).

---

## How to Run the Application

**⚠️ IMPORTANT: This application requires administrative privileges to access network interfaces!**
* **Windows:** Run Command Prompt (CMD) or PowerShell as Administrator.
* **Linux / macOS:** Run the script using `sudo`.

### 1. Interactive Menu Mode (Default)
Simply run the script without any parameters to launch the interactive, user-friendly menu:
```bash
python main.py
```

### 2. Command Line Interface (CLI) Mode
You can bypass the menu and run specific features directly (useful for running the script as a background service).

**Arguments:**
* `--mode`: Choose the mode (`scan`, `sniff`, `ids`).
* `--target`: Specify the IP/CIDR range for the scanner (e.g., `192.168.1.0/24`).
* `--ip`: Filter traffic by a specific IP address (IPv4 or IPv6).
* `--port`: Filter traffic by a specific port (e.g., `80`, `443`, `53`).
* `--count`: Number of packets to capture (default is `0`, which means infinite capturing).

---

## Usage Examples

**Scan a specific local network:**
```bash
python main.py --mode scan --target 192.168.1.0/24
```

**Sniff all traffic infinitely:**
```bash
python main.py --mode sniff
```

**Sniff only DNS traffic (Port 53) to a specific server (e.g., Google DNS) and stop after 20 packets:**
```bash
python main.py --mode sniff --ip 8.8.8.8 --port 53 --count 20
```
*(Note: Do not use the `--port` parameter if you want to capture ICMP/Ping traffic, as ICMP does not use ports.)*

**Run the Intrusion Detection System (ARP Spoofing monitor):**
```bash
python main.py --mode ids
```

---

## Troubleshooting: How to forcefully stop the program

When using infinite sniffing (`--count 0`), the standard `Ctrl+C` interrupt might be ignored if the network driver is blocked waiting for a packet that matches a very strict filter. Here is how to resolve this on different operating systems:

### Windows
1. **Generate Traffic:** The safest way to wake up the script is to generate traffic that matches your filter (e.g., ping the filtered IP address from another terminal). Once a packet is captured, the `Ctrl+C` signal will be processed.
2. **Hard Interrupt:** Use the `Ctrl+Break` or `Ctrl+Pause` key combination in the CMD/PowerShell window.
3. **Kill Process:** If running in the background (`pythonw`), open the **Task Manager**, find the `python.exe` or `pythonw.exe` process, and click "End Task". Alternatively, simply close the CMD window.

### Linux
1. **Generate Traffic:** Same as Windows, send a packet (like a ping) that matches your active filter.
2. **Suspend & Kill:** Press `Ctrl+Z` to suspend the process to the background, then type `kill %1` to terminate it.
3. **Killall:** Open a second terminal window and type `sudo killall python` or `sudo killall python3`.

### macOS
1. **Generate Traffic:** Ping the target address to trigger a packet capture and release the block.
2. **Hard Interrupt:** Try pressing `Cmd + .` or `Ctrl + C`.
3. **Activity Monitor:** Open the "Activity Monitor" app, search for `python`, and force quit the process. Alternatively, open a new terminal and run `sudo pkill -f main.py`.