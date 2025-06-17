# dos Detector - Real-Time Network Anomaly & DoS Detection Tool

**dos Detector** is a powerful, real-time network traffic analysis and anomaly detection script written in Python. Developed by **Giovanni**, this tool monitors network traffic on a specified interface to detect a wide range of potential security threats, including various Denial of Service (DoS) attacks and reconnaissance scans. It provides detailed, color-coded alerts to the console and logs all incidents to a file for later review.

This project was developed to fulfill tasks related to **Network Traffic Analysis** and **Denial of Service (DoS) Detection**.

-----

## Features

  - **Real-Time Packet Sniffing:** Captures and analyzes network packets live without storing them in memory for high performance.
  - **Multi-Vector Attack Detection:**
      - **High Volume (Flood) Detection:** Alerts on unusually high volumes of general traffic from a single source.
      - **TCP SYN Flood Detection:** Identifies classic SYN flood attacks.
      - **UDP Flood Detection:** Detects high volumes of UDP packets.
      - **ICMP Echo (Ping) Flood Detection:** Catches ping flood attacks.
  - **Reconnaissance Detection:**
      - **Port Scanning (TCP & UDP):** Detects when a source IP scans a large number of unique ports.
      - **Stealthy TCP Scans:** Identifies common reconnaissance techniques including **NULL**, **FIN**, and **XMAS** scans.
  - **Detailed & Color-Coded Alerts:**
      - Uses `colorama` for a highly readable, color-coded console output (INFO, WARNING, ERROR).
      - Alerts include detailed context like source IP, attack type, packet counts, and targeted ports.
  - **Persistent Logging:** All alerts are logged to a file (`dos_detector.log`) with timestamps for forensic analysis.
  - **Configurable Thresholds:** Easily tune all detection thresholds and time windows within the script.
  - **Alert Cooldown System:** Prevents the same alert from spamming the console and log file.
  - **Smart Interface Detection:** Can automatically select Scapy's default network interface or allow a specific one to be configured, and reports which interface is being used.

-----

## Requirements

  - Python 3.x
  - Npcap (for Windows users) or libpcap (for Linux/macOS users)
  - The following Python libraries:
      - `scapy`
      - `colorama`

-----

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Giovanni-Farid/Python-Dos-Detector.git
    cd Python-Dos-Detector-main
    ```

2.  **(Windows Users) Install Npcap:**
    Download and install Npcap from the [official website](https://npcap.com/#download)). Make sure to install it in "WinPcap API-compatible mode".

3.  **Install Python dependencies:**
    It is highly recommended to create a virtual environment first.

    ```bash
    # Create and activate a virtual environment (optional but recommended)
    python -m venv venv
    source venv/Scripts/activate  # On Windows
    # source venv/bin/activate    # On Linux/macOS

    # Install required libraries
    pip install scapy colorama
    ```

-----

## Usage

The script must be run with administrator or root privileges to allow for raw packet sniffing.

1.  **(Optional but Recommended) Configure Network Interface:**
    Open the `dos_detector.py` script and find the line near the bottom:

    ```python
    network_interface_to_use = None
    ```

    Change `None` to the name of the network interface you want to monitor (e.g., `"Ethernet"`, `"Wi-Fi"`, `"eth0"`). If you leave it as `None`, the script will try to use Scapy's default and will print which one it chose.

2.  **Run the script:**

      - **On Windows:** Open Command Prompt or PowerShell **as Administrator** and run:
        ```powershell
        python dos_detector.py
        ```
      - **On Linux/macOS:** Use `sudo`:
        ```bash
        sudo python3 dos_detector.py
        ```

3.  **Monitor the Output:**
    The script will start displaying real-time status and alerts on the console. All alerts will also be saved to `dos_detector.log`. Press `Ctrl+C` to stop the script gracefully.

-----

## Disclaimer

This is an educational tool created for learning about network security and Python programming. It is **not** a replacement for professional-grade, enterprise-level Intrusion Detection Systems (IDS) or firewalls. Use responsibly and only on networks you own or have explicit permission to test.

-----

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
