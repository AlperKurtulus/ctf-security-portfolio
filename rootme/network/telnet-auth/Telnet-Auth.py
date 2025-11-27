#!/usr/bin/python3

from scapy.all import *
import sys

print("  Starting the analysis tool. ")

def analyze_pcap(pcap_file):
    #Read the PCAP file into a list of packets.

    try: 
        packets = rdpcap(pcap_file)
        print(f"  Succesfully loaded {pcap_file}")

    except FileNotFoundError:
        print (f"  Error: file {pcap_file} not found")
        return

    #Initialize an empty byte string to hold the reassembled data    
    assembled_stream = b""

    #Iterate through each packet in the capture
    for packet in packets:
        # We are only interested in TCP packets that contain actual Data (Raw layer).
        # We skip SYN, ACK, FIN packets that have no payload.

        if packet.haslayer(TCP) and packet.haslayer(Raw):
         # Extract the payload (load) from the Raw layer
          payload = packet[Raw].load

         #Append the payload to our data stream
          assembled_stream += payload
        # Decode and print the final result
        # We use 'errors=ignore' to prevent crashing on non-printable characters.
    print("\n  Reassembled Data Stream:")
    print("-" * 50)
    print(assembled_stream.decode('utf-8', errors='ignore'))
    print("-" * 50)

if __name__ == "__main__":
    target_file = "/home/joker/Desktop/RM-Folders/ch2.pcap"
    analyze_pcap(target_file)
