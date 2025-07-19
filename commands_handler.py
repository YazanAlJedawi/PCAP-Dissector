
import os


LOGO_STR = r"""
               ready to digest pcap!
 ____  ____  ____  ____  ____  ____  ____  ____  ____ 
||D ||||I ||||S ||||S ||||E ||||C ||||T ||||O ||||R ||
||__||||__||||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\|


"""

def print_logo():
    print(LOGO_STR)

def help_msg_func():
    help_msg = f"""\n
{LOGO_STR}

Usage: python Dissector.py [MODE] <pcap_file>

Available modes:
  http-analysis <pcap_file>  : Analyzes HTTP traffic in the specified PCAP file.
  ssh-analysis <pcap_file>   : Analyzes SSH traffic in the specified PCAP file.
  stats <pcap_file>          : Gathers general network statistics from the specified PCAP file.

Examples:
  python Dissector.py http-analysis capture.pcap
  python Dissector.py ssh-analysis network_log.pcapng
  python Dissector.py stats traffic.pcap

  help        : Show this guide.
  logo        : Prints the tool's logo.

Note:
  This tool primarily analyzes PCAP (Packet Capture) files.
"""
    return help_msg

def interface():
    Interface=f"""\n
{LOGO_STR}

This tool allows:
- Analyzing HTTP traffic from PCAP files.
- Analyzing SSH traffic from PCAP files.
- Collecting general network statistics from PCAP files.

- "help" to ask for help

Made By:
  - YazanAlJedawi: https://github.com/YazanAlJedawi
"""
    return Interface


