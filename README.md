# SDN Firewall System

**A programmable network firewall powered by Software-Defined Networking (SDN).**

The SDN Firewall System is a network security project that combines centralized firewall policy management with a web-based interface and an SDN controller.

Built using Python, Flask, Ryu, OpenFlow 1.3, Open vSwitch, and SQLite, the system explores programmable traffic filtering, firewall rule management, and security event monitoring.

The project uses Containernet to create a simulated network environment for experimenting with and evaluating firewall policies.

<p align="center">
  <img src="https://img.shields.io/badge/Python-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-black?logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/OpenFlow-1.3-orange" alt="OpenFlow 1.3">
  <img src="https://img.shields.io/badge/SQLite-blue?logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
</p>

<p align="center">
  <a href="https://github.com/mhd-ghaith/firewall-SDN-system">View Repository</a>
  ·
  <a href="https://github.com/mhd-ghaith/firewall-SDN-system/issues">Report a Bug</a>
</p>

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Screenshots](#screenshots)
- [System Architecture](#system-architecture)
- [Network Topology](#network-topology)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Example](#usage-example)
- [Testing and Validation](#testing-and-validation)
- [Database Schema](#database-schema)
- [Security Considerations](#security-considerations)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Overview

Traditional network security configurations may require administrators to configure individual devices when traffic-filtering policies change. Software-Defined Networking (SDN) provides a programmable approach to network management by separating control logic from packet forwarding.

The SDN Firewall System explores this approach by integrating a web-based management interface with a Ryu SDN controller and OpenFlow-compatible switches.

The application provides a centralized interface for managing supported firewall policies and viewing available monitoring information. The controller processes firewall policies and communicates with the network infrastructure to enforce the configured behavior.

Containernet provides a controlled environment for creating network topologies and experimenting with traffic-filtering scenarios.

### Project Objectives

- Implement centralized firewall policy management.
- Configure traffic-filtering rules through a web interface.
- Enforce supported firewall policies using an SDN controller.
- Store firewall rules and security events in SQLite.
- Display available firewall and network monitoring information.
- Evaluate firewall behavior through controlled network experiments.

This project is intended for educational use and experimentation with programmable network security.

## Key Features

### Firewall Policy Management

- Manage firewall rules through a web interface.
- Configure supported source and destination addresses.
- Define protocol and port matching criteria where implemented.
- Configure allow and block actions.
- Use the rule-priority behavior implemented by the system.

### SDN-Based Enforcement

- Integrate with the Ryu SDN controller.
- Use OpenFlow 1.3 for communication with compatible switches.
- Apply firewall policies through the controller's enforcement logic.

### Monitoring and Logging

- View available traffic and firewall statistics.
- Inspect recorded security events.
- Review rule-related statistics supported by the implementation.

### Persistent Storage

- Store firewall rules in SQLite.
- Persist supported security event records.
- Maintain rule-related statistics where implemented.

### Network Simulation

- Use Containernet to create a configurable network environment.
- Experiment with simulated hosts and switches.
- Evaluate firewall behavior using controlled network tests.

### Machine Learning Algorithms

- Train the dataset [CSE-CIC-IDS2018](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv) on 5 different algorithms for binary classification (malicious vs benign traffic).
- Compare the results to conclude the best model.
