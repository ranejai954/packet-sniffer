# 🔍 Network Packet Sniffer with Web Dashboard

[![GitHub Pages](https://img.shields.io/badge/Demo-GitHub_Pages-brightgreen)](https://ranejai954.github.io/packet-sniffer)
[![Python](https://img.shields.io/badge/Python-3.7+-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

A real-time network packet capture tool with a beautiful web interface. Monitor TCP, UDP, and ICMP traffic live with interactive statistics.

---

# 📊 Two Versions Available

| Version | Purpose | Link |
|---------|---------|------|
| 🌐 Live Demo | Simulated traffic - Try instantly in browser | https://ranejai954.github.io/packet-sniffer |
| 💻 Local App | Real packet capture - Run on your machine | Clone and run locally |

---

# 🌐 Live Demo (GitHub Pages)

No installation required. Works directly in your browser. Shows simulated network traffic.

## Features
- Auto-starting packet simulation
- Live statistics (TCP/UDP/ICMP counts)
- Export packets as JSON, CSV, or TXT
- Filter packets by IP/protocol

## Try it
https://ranejai954.github.io/packet-sniffer

---

# 💻 Local Application (Real Packet Sniffer)

Capture REAL network traffic from your own machine.

## Prerequisites
- Python 3.7+
- Admin/root privileges
- Active network connection

---

# ⚙️ Installation Steps

```bash
# 1. Clone
git clone https://github.com/ranejai954/packet-sniffer.git
cd packet-sniffer

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run

# Linux/Mac:
sudo python sniffer.py

# Windows (Run as Administrator):
python sniffer.py

# 4. Open browser to:
http://localhost:5000
```

---

# 🚀 Features in Local App

- Real packet capture from your network interface
- Live WebSocket updates (no page refresh)
- Export captured data as JSON, CSV, or TXT
- Filter packets by IP, protocol, or port
- Start/Stop/Clear controls
- Color-coded protocol display
  - TCP → Green
  - UDP → Blue
  - ICMP → Orange
- Keyboard shortcuts
  - `Ctrl + S` → Start
  - `Ctrl + X` → Stop
  - `Esc` → Clear
- Toast notifications for actions
- Auto-refresh statistics every 2 seconds

---

# 📁 Project Structure

```text
packet-sniffer/
├── sniffer.py              # Flask backend (real packet capture)
├── templates/
│   └── dashboard.html      # Web dashboard UI
├── index.html              # GitHub Pages demo (simulated traffic)
├── requirements.txt        # Python dependencies
├── LICENSE                 # MIT License
└── README.md               # Documentation
```

---

# ⚖️ Demo vs Local - Key Differences

| Feature | Live Demo | Local App |
|---------|------------|------------|
| Traffic Source | Simulated (fake packets) | Your REAL network |
| Installation | None - works in browser | Python + dependencies required |
| Privileges | None required | Admin/root required |
| Export Formats | JSON, CSV, TXT | JSON, CSV, TXT |
| Real-time Updates | Yes (simulated) | Yes (real) |
| Filtering | Yes | Yes |
| Where it runs | GitHub Pages | Your local machine |
| Network Required | Internet to load page | Active network interface |
| Data Accuracy | Demo purposes only | 100% real traffic |

---

# 🛠️ Tech Stack Used

| Technology | Purpose |
|------------|----------|
| Python | Backend logic and packet processing |
| Flask | Web server framework |
| Scapy | Packet capture and analysis library |
| Socket.IO | Real-time WebSocket communication |
| HTML5 | Structure of web dashboard |
| CSS3 | Styling and animations |
| JavaScript | Frontend interactivity |
| jQuery | DOM manipulation and AJAX |

---

# 🧩 Troubleshooting

## Q1: Permission denied error?

Run with sudo/administrator privileges:

```bash
# Linux/Mac
sudo python sniffer.py

# Windows
Run Command Prompt as Administrator
```

---

## Q2: No packets showing?

Make sure you have active network traffic.

Example:

```bash
ping google.com
```

---

## Q3: Scapy installation fails on Windows?

Install Npcap first:

https://npcap.com

Then run:

```bash
pip install scapy
```

---

## Q4: Scapy installation fails on Linux?

```bash
sudo apt-get install python3-scapy
```

---

## Q5: Scapy installation fails on Mac?

```bash
brew install scapy
pip install scapy
```

---

## Q6: Port 5000 already in use?

Change the port in `sniffer.py`:

```python
socketio.run(app, debug=True, port=5001)
```

---

## Q7: Demo not auto-starting?

Click the **Start** button in the demo window.

---

## Q8: Export not working in demo?

Make sure packets are already captured first.

---

# 📜 License

MIT License - Free to use, modify, and distribute.

```text
MIT License

Copyright (c) 2026 Jai Rane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

# 👨‍💻 Connect With Me

[![GitHub](https://img.shields.io/badge/GitHub-ranejai954-181717?style=flat&logo=github)](https://github.com/ranejai954) [![LinkedIn](https://img.shields.io/badge/LinkedIn-Jai_Rane-0A66C2?style=flat&logo=linkedin)](https://www.linkedin.com/in/jai-rane-62ba58352) [![Email](https://img.shields.io/badge/Email-ranejai954@gmail.com-D14836?style=flat&logo=gmail)](mailto:ranejai954@gmail.com)

---

⭐ Star this repository if you found it useful!

Made with Python ❤️  
Built for cybersecurity enthusiasts
