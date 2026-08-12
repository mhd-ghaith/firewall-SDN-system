# SDN Firewall System

A dynamic network firewall built on Software Defined Networking (SDN) principles,
enabling real-time security policy management through a web interface.

## Overview

This project implements a centralized firewall using the Ryu SDN controller
and OpenFlow 1.3 protocol. Security rules are pushed directly to Open vSwitch
(OVS) switches, taking effect instantly across the entire network without
requiring any restarts. All rules and events are persisted in a SQLite database,
surviving controller restarts.

## System Architecture

[Web Browser] → [Flask Web UI :5000] → [Ryu REST API :8080] → [OVS Switches]
OpenFlow 1.3
[SQLite DB] ← firewall.db (rules + logs + rule_stats tables)
[Containernet + Docker] ← Network simulation topology

## Features

- Dynamic firewall rule management via web interface
- Real-time rule enforcement using OpenFlow 1.3
- Block/Allow rules based on source IP, destination IP, protocol, and ports
- Priority-based rule conflict resolution (Block=200, Allow=100)
- Persistent storage using SQLite — rules survive controller restarts
- Security event logging with timestamps
- Traffic monitoring with live SVG charts
- Network simulation using Containernet and Docker

## Project Structure

Firewall_with_SDN/
├── controller/
│   └── firewall.py          # Ryu SDN controller + REST API + SQLite
└── webUI/
├── app.py               # Flask web application
├── static/
│   ├── style.css        # UI styling
│   └── main.js          # Frontend logic
└── templates/
├── dashboard.html   # Dashboard page
├── policies.html    # Firewall policies management
├── monitoring.html  # Traffic monitoring
├── logs.html        # Security event logs
└── about.html       # About page
containernet/
└── sdn_topology.py          # Network simulation topology

## Requirements

### System
- Ubuntu 20.04 LTS
- Python 3.8+
- Docker 20.10+
- Open vSwitch 2.13

### Python Packages
**Controller:**
ryu==4.34

**Web UI:**
flask==3.0.3
requests==2.31.0

**Containernet:**
containernet
docker

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/sdn-firewall.git
cd sdn-firewall
```

### 2. Install Ryu
```bash
sudo pip3 install ryu --break-system-packages
```

### 3. Set up Flask virtual environment
```bash
cd webUI
python3 -m venv application
source application/bin/activate
pip install flask requests
deactivate
```

### 4. Install Containernet
```bash
cd ~/containernet
python3 -m venv cont_env
source cont_env/bin/activate
pip install wheel setuptools --upgrade
pip install . --no-build-isolation
pip install docker
deactivate
```
### 5. Pull Docker image
```bash
sudo docker pull iwaseyusuke/mininet
```

## Running the System

Open three separate terminals:

### Terminal 1 | Ryu Controller:
```bash
cd Firewall_with_SDN/controller
ryu-manager --wsapi-port 8080 firewall.py
```

### Terminal 2 | Flask Web UI:
```bash
cd Firewall_with_SDN/Web_UI
source application/bin/activate
python3 app.py
```

### Terminal 3 | Containernet Topology:
```bash
cd containernet
source cont_env/bin/activate
sudo $(which python3) sdn_topology.py
```

Then open your browser at: http://127.0.0.1:5000

## Network Topology

h_attacker (10.0.0.100)
      |
      s1 (External Firewall)
      |
      s2 (DMZ Switch) ──── h_web1 (10.0.1.1)
      |                └── h_web2 (10.0.1.2)
      |
      s3 (Internal Firewall 1)
      |
      s4 (Internal Switch) ──── h_app1  (10.0.2.1)
      |                    ├── h_app2  (10.0.2.2)
      |                    ├── h_work1 (10.0.2.3)
      |                    ├── h_work2 (10.0.2.4)
      |                    └── h_db    (10.0.2.5)
      |
      s5 (Internal Firewall 2)

**Note:** The topology provided above is an example configuration used to demonstrate and test the system. Containernet allows you to modify the topology according to your requirements by changing the switches, hosts, links, IP addresses, and their connections in the topology file. You can add or remove hosts and switches, change the network structure, or assign different IP addresses, as long as the resulting topology is compatible with the firewall rules and controller configuration. This allows the system to be tested in different network scenarios without modifying the core firewall implementation.

## Database Schema

The system uses SQLite with three tables:

| Table | Description |
|-------|-------------|
| rules | Stores firewall rules (src, dst, proto, sport, dport, action, priority) |
| logs | Stores security events (rule_id, src_ip, dst_ip, protocol, action, timestamp) |
| rule_stats | Tracks packet counts per rule for blocked traffic detection |


