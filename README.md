# packet-sniffer
Here is a draft for your README file based on the provided code:

---

# Network Packet Sniffer

This project implements a **Network Packet Sniffer** to capture, process, and display network traffic in real-time. The tool includes both command-line and graphical user interface (GUI) options, making it versatile for different use cases.

## Features

- **Real-time Packet Capturing**: Monitors network traffic on specified interfaces.
- **Protocol Analysis**: Decodes Ethernet, IP, TCP, UDP, and raw data layers.
- **Command-Line Interface (CLI)**:
  - Filters packets based on protocols, IPs, and ports.
  - Supports logging packet data to a file.
  - Provides live statistics on packet captures.
- **Graphical User Interface (GUI)**:
  - Simple interface for selecting network interfaces and filters.
  - Displays captured packets in a user-friendly list.
  - Options to log packet data and clear captured packets.

---

## File Descriptions

### 1. `core.py`
Core functionality for decoding packets and monitoring a network interface.  
- **`Decoder`**: Captures packets using Scapy and processes each one for detailed analysis.  
- **`PacketSniffer`**: Orchestrates the packet capturing process and notifies observers about incoming packets.

### 2. `output.py`
Defines the abstract interface and specific implementations for processing and displaying packet data.  
- **`Output`**: Abstract base class for output processing.  
- **`OutputToScreen`**: Displays packet details on the console and optionally provides live statistics.

### 3. `sniffer.py`
CLI tool to run the packet sniffer.  
- Features:
  - Argument parsing for interface selection, packet filtering, logging, and statistics.
  - Ensures the program runs with administrative privileges for capturing packets.  

### 4. `sniffer_gui.py`
GUI tool for user-friendly packet sniffing.  
- **Features**:
  - Select network interfaces from a dropdown menu.
  - Input custom packet filters.
  - Display captured packets in a list.
  - Start/Stop capturing with buttons.

### 5. `wifi.py`
Utility script for listing available network interfaces using Scapy.

---

## Requirements

- **Python** 3.8 or higher
- **Libraries**:
  - `scapy`
  - `tkinter`
- **Permissions**: Requires administrative privileges to access network interfaces.

---

## Usage

### CLI
1. Run the sniffer script:
   ```bash
   python sniffer.py -i <interface> [-d] [-f <filter>] [-l <log_file>] [-s <stats_interval>]
   ```
   Example:
   ```bash
   python sniffer.py -i eth0 -d -f "tcp" -l packets.log -s 10
   ```

2. Press `Ctrl+C` to stop the packet capture.

### GUI
1. Launch the GUI:
   ```bash
   python sniffer_gui.py
   ```
2. Select the network interface from the dropdown.
3. Enter optional filters and click "Start Capture."

---

## License

This project is licensed under the MIT License. Feel free to modify and distribute as per the terms of the license.

---

## Acknowledgments

Built using [Scapy](https://scapy.net/), a powerful Python library for network packet manipulation and analysis.
