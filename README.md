# C/U-Plane Attacker

## !!

Due to size limit, please download the following [PCAP](https://drive.google.com/file/d/1YhxIEkcpbp0TWK8rxDPyLF1LRB1yAcXQ/view?usp=sharing) and place it into Traffic folder.

## 1. Packet Editor
There are two parts of contribution for the packet editor:
1. Dissector for O-RAN-FH-C packet Type-1 with extType-1 support and O-RAN-FH-U packet
2. PCAP Generator to mix packets from several PCAP files into a single PCAP with support to set up destination MAC Adddress, set up source MAC Address, randomize source MAC Address, and set up VLAN

### How to play with it

#### Install dependencies

* Scapy

#### Adding dissector to Scapy

> cp /python_code/oran_fh.py [Scapy directory]/layers/

After opening Scapy:
> load_layer("oran_fh")

#### Generate PCAP Generator binary 

> pyinstaller /python_code/pcap_gen.py --onefile --hiddenimport scapy
> sudo cp dist/pcap_gen /usr/bin

#### Launching it

> pcap_gen --help
> pcap_gen [-h] --pcap PCAP --out OUT --mbps MBPS [--vlan VLAN] [--src SRC] [--dst DST] [--r]

Example: 
> pcap_gen --pcap foobar1.pcap:3,foobar2.pcap:4 --out test.pcap --vlan 4 --dst 00:11:22:33:44:55 --src 00:11:22:33:44:66 --mbps 10

## 2. Packet Generator 

The tool is designed based on DPDK-burst-replay to conduct O-RAN.TIFG.E2E-Test.0-v03.00 Secton 7.2.2 C-Plane eCPRI DoS Attack (Network layer).

### How to play with it

#### Install dependencies

* dpdk-dev (obsly)
* libnuma-dev
* That's all.

NB: libpcap is not required, as dpdk-replay process pcap files manually.

#### Compiling and installing it

> RTE_SDK= <DPDK_PATH>
> export PCAP_DIR=<CUFH_ATTACKER_PATH>/Traffic
> make -f DPDK_Makefile && sudo cp build/cufh-attacker /usr/bin

#### Launching it

> cufh-attacker [TRAFFIC-TYPE] [OPTIONS] PORT1[,PORTX...]

Example:
> cufh-attacker (for usage)
> cufh-attacker --cp-dl-big 1000 --c --src 11:22:33:44:77:22 --dst 11:22:33:44:77:11 --vlan 1 --numacore 0 03:00.0
> cufh-attacker --up-ul-r 1,10,1 --dst 11:22:33:44:77:11 --numacore 0 03:00.1

Refer to [this guide](https://hackmd.io/@ferlinda/ryFZcikK3) to use the application.

### BSD LICENCE [DPDK-burst-replay]

Copyright 2018 Jonathan Ribas, FraudBuster. All rights reserved.

Modified 2023 by Ferlinda Feliana.
