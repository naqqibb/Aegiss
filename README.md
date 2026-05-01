# AEGIS CyberNet - Neural Timed Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> A cutting-edge cybersecurity threat intelligence platform featuring real-time APT C2 (Command & Control) detection and continuous threat feed monitoring.

## 🎯 Overview

**AEGIS CyberNet** is an advanced threat intelligence and security operations platform designed to track and monitor global Advanced Persistent Threat (APT) activities. The platform provides real-time streaming intelligence on command & control infrastructure associated with state-sponsored and criminal threat actors.

## 🚀 Features

- **Real-Time Threat Feed**: Continuous streaming of detected APT C2 infrastructure
- **Global APT Tracking**: Monitors multiple threat actors including:
  - 🔴 **LAZARUS** - North Korean state-sponsored group
  - 🟡 **PLA** - Chinese state-sponsored operations
  - 🟠 **GRU** - Russian military intelligence
  - 🟣 **APT41** - Chinese cybercriminal enterprise group

- **Live Statistics**: Track threat actor activity metrics in real-time
- **Threaded Architecture**: Asynchronous feed generation for continuous monitoring
- **Colored Terminal Output**: Visual indicators for threat severity and quick identification
- **Sinkhole & Mitigation Tracking**: Monitor blocked and sinkholed C2 connections

## 📋 Project Structure

```
Aegiss/
├── README.md           # This file
├── LICENSE            # MIT License
├── OPERATOR           # Main threat feed engine
└── .github/           # GitHub configuration
```

## 🔧 Installation

### Requirements
- Python 3.7+
- No external dependencies required

### Setup

```bash
# Clone the repository
git clone https://github.com/naqqibb/Aegiss.git
cd Aegiss

# Run the threat feed
python OPERATOR
```

## 📊 Usage

Simply execute the OPERATOR script to launch the continuous threat intelligence feed:

```bash
python OPERATOR
```

### Output Example
```
🔥 AEGIS CONTINUOUS FEED v13.1 - GLOBAL C2 HUNT LIVE
Ctrl+C to stop stream
--------------------------------------------------------------------------------
14:32:15 | LAZARUS | 45.130.105.120  | BLOCKED
14:32:16 |     PLA | 103.228.45.180  | SINKHOLE
14:32:17 |     GRU | 91.207.12.95    | DDoSd
14:32:18 |   APT41 | 45.142.60.140   | BLOCKED

LAZ: 45 PLA: 38 GRU: 42 APT41: 35 | TOTAL: 160
```

### Controls
- **Ctrl+C**: Stop the threat feed stream

## 🛠️ How It Works

The OPERATOR continuously:
1. Generates realistic APT C2 IP addresses from known threat actor ranges
2. Streams detection events with timestamps
3. Tracks blocking/sinkholing actions (BLOCKED, SINKHOLE, DDoSd)
4. Maintains live statistics of threat actor activity
5. Displays colored terminal output for quick threat assessment

## 📚 Threat Actors

| Actor | Type | Known Ranges |
|-------|------|--------------|
| **LAZARUS** | State-Sponsored (DPRK) | 45.13x.xxx.xxx, 185.22x.xxx.xxx |
| **PLA** | State-Sponsored (China) | 103.xxx.xxx.xxx, 114.xxx.xxx.xxx |
| **GRU** | State-Sponsored (Russia) | 91.207.xxx.xxx, 185.234.xxx.xxx |
| **APT41** | Cybercriminal Enterprise | 45.142.xxx.xxx |

## 🔒 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests to help improve AEGIS CyberNet.

## ⚖️ Legal & Ethical Notice

This tool is designed for:
- ✅ Security research and educational purposes
- ✅ Authorized threat intelligence operations
- ✅ Cybersecurity training and demonstration

**Unauthorized access** to computer systems is illegal. Use this tool only on systems you own or have explicit permission to test.

## 📞 Support

For issues, questions, or suggestions, please open an [issue](https://github.com/naqqibb/Aegiss/issues) on GitHub.

---

**AEGIS CyberNet v13.1** - Threat Intelligence at the Speed of Light
