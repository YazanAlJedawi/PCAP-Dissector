#  PCAP Dissector

```
               ready to digest pcap!
 ____  ____  ____  ____  ____  ____  ____  ____  ____ 
||D ||||I ||||S ||||S ||||E ||||C ||||T ||||O ||||R ||
||__||||__||||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\|


```

## Overview

**PCAP Dissector** is a command-line tool designed for basic network traffic analysis from Packet Capture (PCAP) files. It provides functionalities to analyze HTTP and SSH traffic, and to gather general network statistics, helping users quickly identify patterns and potential anomalies within their network captures.

## Features

* **HTTP Analysis**: Parses HTTP requests and responses, identifying suspicious user agents, interesting paths (e.g., `/admin`, `/login`), and potential malware downloads based on MIME types. Generates a `http_report.csv` file.
* **SSH Analysis**: Detects SSH sessions and performs a basic brute-force attempt analysis by estimating session length. Short sessions might indicate failed login attempts.
* **Network Statistics**: Gathers general statistics such as protocol usage, top talkers (by packets and bytes), and TCP flag summaries. It also attempts to guess the operating system based on TTL values.

## Dependencies

PCAP Dissector relies on the following Python libraries and external tools:

* Python 3.x
* `pyshark`: A Python wrapper for TShark, allowing packet dissection.
* `scapy`: A powerful interactive packet manipulation program.
* `tshark`: The command-line network protocol analyzer, which pyshark depends on.

> You will need to install Wireshark (which includes TShark) on your system or install `tshark` separately.

## Installing Python Dependencies

```bash
pip install pyshark scapy
```

## Installing TShark

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install tshark
```

### Linux (CentOS/RHEL/Fedora)

```bash
sudo yum install wireshark
# or
sudo dnf install wireshark
```

### macOS (using Homebrew)

```bash
brew install wireshark
# Add Wireshark to your PATH if not automatically done:
# export PATH="/usr/local/opt/wireshark/bin:$PATH"
```

### Windows

Download and install Wireshark from the [official Wireshark website](https://www.wireshark.org/). Ensure that **TShark** is selected during the installation process and that its directory is added to your system's PATH environment variable.

## Installation

```bash
git clone https://github.com/YazanAlJedawi/PCAP-Dissector.git
cd PCAP-Dissector
```

Ensure dependencies are met (as described above).

## Usage

The `Dissector.py` script is the main entry point for the tool.

### General Syntax

```bash
python Dissector.py [MODE] <pcap_file>
```

### Available Modes

* `http-analysis <pcap_file>`: Analyzes HTTP traffic.
* `ssh-analysis <pcap_file>`: Analyzes SSH traffic.
* `stats <pcap_file>`: Gathers general network statistics.
* `help`: Displays the help message.
* `logo`: Prints the tool's logo.
* `exit`: Exits the tool.

### Examples

#### HTTP Traffic Analysis

```bash
python Dissector.py http-analysis capture.pcap
```

#### SSH Traffic Analysis

```bash
python Dissector.py ssh-analysis network_log.pcapng
```

#### Network Statistics Collection

```bash
python Dissector.py stats traffic.pcap
```

#### Display Help

```bash
python Dissector.py help
```


## Project Structure

```
.
├── Dissector.py          # Main entry point for the tool
├── commands_handler.py   # Handles command-line arguments and displays help/logo
├── http_Dissector.py     # Module for HTTP traffic analysis
├── ssh_Dissector.py      # Module for SSH traffic analysis
└── stats_collector.py    # Module for general network statistics collection
```

## Contributing

more functionality can and will be added, but you are more that welcome to do so !


Y.