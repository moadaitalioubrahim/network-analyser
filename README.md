# Network Analyzer - SSH Brute Force Detector

A lightweight Python script designed to detect SSH brute-force attacks in real-time. This project was built to apply advanced networking and cybersecurity concepts.

## Description

This tool listens to network traffic on a specific interface using the `Scapy` library. It specifically filters for TCP packets targeting port 22 (SSH) with the SYN flag activated (connection attempts). 

If a single source IP address makes 5 or more connection attempts within a 10-second window, the script triggers an alert.

## How it works

The script uses a **Sliding Window Algorithm**:
1. Captures incoming TCP SYN packets.
2. Records the timestamp of each attempt per IP address.
3. Cleans the log by removing attempts older than 10 seconds.
4. If the number of attempts from the same IP exceeds the threshold (5), it prints a security alert.

## Tech Stack

*   **Language:** Python 3
*   **Libraries:** Scapy (Packet manipulation)
*   **System dependency:** Npcap (for Windows packet capture)

## Installation & Usage

1. Install the required Python library:
   ```bash
   pip install scapy
2. Run the script as Administrator (required for network sniffing):
   ```bash
   python network_analyzer.py
3. To test it, generate traffic to port 22 from another terminal:
   ```bash
   Test-NetConnection -ComputerName 8.8.8.8 -Port 22
