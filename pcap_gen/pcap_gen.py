import random
import math
import argparse
from scapy.all import *

def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )

def count_mbps(packets,mbps):
    p_length = 0
    for packet in packets:
        p_length+=(len(packet)*8)
    nbruns = (mbps*1000000)/p_length
    nbruns = math.ceil(nbruns)
    return nbruns

def modify_packet(packets, args):
    for packet in packets:
        packet.time = 0000000000.000000
    if args.vlan != None:
        for packet in packets:
            packet.vlan = args.vlan
    
    if args.src != None:
        for packet in packets:
            packet.src = args.src
    
    if args.dst != None:
        for packet in packets:
            packet.dst = args.dst   
    return packets

def generate_out_pcap(packets,args,nbruns):
    for packet in packets:
        if args.r:
            packet.src=rand_mac()
        if packets.index(packet) == 0:
            wrpcap(args.out,packet)
        else:
            wrpcap(args.out,packet,append=True)

    ## Generation loop
    for i in range (1,nbruns):
        for packet in packets:
            if args.r:
                packet.src=rand_mac()
            wrpcap(args.out,packet,append=True)
    
    return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', type=str, required=True, 
                        help='List of input pcap files and frame numbers to merge (e.g. file1.pcap:10,file2.pcap:20).')
    parser.add_argument('--out', type=str, required=True, 
                        help='Name of the output file. Example: merged.pcap')
    parser.add_argument('--mbps', type=int, required=True, 
                        help='Traffic volume of the output file in Mbps. Example: 100')
    parser.add_argument('--vlan', type=int, required=False,
                        help='Change VLAN of the frames. Example: 10')
    parser.add_argument('--src', type=str, required=False,
                        help='Change source MAC address of the frames.')
    parser.add_argument('--dst', type=str, required=False,
                        help='Change destination MAC address of the frames.')
    parser.add_argument('--r', action='store_true', required=False,
                        help='Randomize source MAC address of the frames')

    args = parser.parse_args()

    pcap_list, frame_no_list = zip(*[(s.split(":")[0], int(s.split(":")[1])) for s in args.pcap.split(",")])
    pcap_list, frame_no_list = list(pcap_list), list(frame_no_list)

    packet_list = []

    for pcap in pcap_list:
        packet_list.append(rdpcap(pcap)[frame_no_list[pcap_list.index(pcap)]])

    packet_list = modify_packet(packet_list, args)

    nbruns = count_mbps(packet_list,args.mbps)
    
    res = generate_out_pcap(packet_list,args,nbruns)

    if res:
        print("Success.")
    else:
        print("Failed")
