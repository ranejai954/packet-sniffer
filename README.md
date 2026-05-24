# 🔍 Network Packet Sniffer with Web Dashboard

[![GitHub Pages](https://img.shields.io/badge/Demo-GitHub_Pages-brightgreen)](https://ranejai954.github.io/packet-sniffer)
[![Python](https://img.shields.io/badge/Python-3.7+-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

A real-time network packet capture tool with a beautiful web interface. Monitor TCP, UDP, and ICMP traffic live with interactive statistics.

---

## 📊 Two Versions Available

| Version | Purpose | Link |
|---------|---------|------|
| **🌐 Live Demo** | Simulated traffic - Try instantly in browser | [https://ranejai954.github.io/packet-sniffer](https://ranejai954.github.io/packet-sniffer) |
| **💻 Local App** | Real packet capture - Run on your machine | Clone and run locally |

---

## 🌐 Live Demo (GitHub Pages)

> **No installation required!** Works directly in your browser.

The live demo shows **simulated network traffic** to demonstrate the UI and export features.

### Features in Demo:
- ✅ Auto-starting packet simulation
- ✅ Live statistics (TCP/UDP/ICMP counts)
- ✅ Export packets as **JSON, CSV, or TXT**
- ✅ Filter packets by IP/protocol
- ✅ Beautiful dark-themed dashboard

### Try It Now:
👉 [https://ranejai954.github.io/packet-sniffer](https://ranejai954.github.io/packet-sniffer)

---

## 💻 Local Application (Real Packet Sniffer)

> **Capture REAL network traffic** from your own machine.

### Prerequisites
- Python 3.7 or higher
- Administrator/root privileges (required for packet capture)
- Network interface with internet traffic

### Quick Start

**1. Clone the repository**

git clone https://github.com/ranejai954/packet-sniffer.git

cd packet-sniffer

### 2. Install dependencies
pip install -r requirements.txt

### 3. Run the application

OS	- Command
Linux/Mac	- sudo python sniffer.py
Windows	- Run as Administrator: python sniffer.py

### 4. Open your browser

http://localhost:5000

### Features in Local App:
✅ Real packet capture from your network interface
✅ Live WebSocket updates
✅ Export captured data as JSON, CSV, or TXT
✅ Filter packets by IP, protocol, or port
✅ Start/Stop/Clear controls
✅ Color-coded protocol display
✅ Keyboard shortcuts (Ctrl+S Start, Ctrl+X Stop, Esc Clear)

