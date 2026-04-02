Pynet
=====
A collection of lightweight Python network tools for scanning, discovery,
and intrusion detection.


TOOLS
-----

pyport.py — Port Scanner
  Scans a target host for open TCP ports. Works on both local and public
  IP addresses. Useful for auditing exposed services on any reachable host.

  Usage:
    python pyport.py <target> [start_port] [end_port]

  Examples:
    python pyport.py 192.168.1.1 1 1024
    python pyport.py 93.184.216.34 1 1024


pyip.py — Ping Sweeper
  Sweeps a subnet to discover live hosts by sending ICMP ping requests
  across a range of IPs.

  Usage:
    python pyip.py <subnet>

  Example:
    python pyip.py 192.168.1.0/24


antiscan.py — Port Scan Detector (IDS)
  Monitors network traffic and detects port scanning activity against
  your machine. Raises an alert when a host probes an unusual number
  of ports in a short time window.

  Usage:
    python antiscan.py

  Note: Requires root/administrator privileges to capture raw packets.


INSTALLATION
------------
  git clone https://github.com/Gasfornuis/Pynet.git
  cd Pynet
  pip install -r requirements.txt

  Requirements: Python 3.8+


LICENSE
-------
  MIT — see LICENSE file
