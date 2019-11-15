#!/usr/env/bin python
from scapy.all import *
from datetime import datetime
import argparse


def get_arg():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="interface", help="Specify the interface you want to sniff.")
    parse.add_argument("-f", "--filter", dest="filters", help="Specify a filter if needed.", default=None)
    parse.add_argument("-s", "--store", dest="store_true", help="True to store the packets, default False",
                       default=False)
    arguments = parse.parse_args()
    return arguments


class Sniffer:

    def __init__(self, interface, filters, store):
        self.interface = interface
        self.filters = filters
        self.store = store
        self.pcap = None

    def start(self):
        print("[*] Start Sniffing ...")
        self.pcap = sniff(iface=self.interface, filter=self.filters, store=self.store, prn=Sniffer.extract_information)
        if self.store:
            wrpcap("temp.cap", self.pcap)

    @staticmethod
    def extract_information(pkt):
        try:
            # Extract Ethernet frame information.
            print("\n")
            print("[+] Received at", datetime.now().strftime("%d/%m/%Y %H:%M:%s"))
            print("[+] Source MAC:", pkt.src)
            print("[+] Destination MAC:", pkt.dst)
            print("[+] Type:", pkt.type)
            pkt_ip = pkt.payload
            # Check if it is IPv4 IEEE 802 Ethertype 2048
            if str(pkt.type) == "2048":
                # Now extract the IP packet information.
                print("\t[+] Packet Type: IPv4")
                print("\t[+] Packet ID:", pkt_ip.id)
                print("\t[+] Source IP:", pkt_ip.src)
                print("\t[+] Destination IP:", pkt_ip.dst)
                print("\t[+] Ttl:", pkt_ip.ttl)
                pkt_segment = pkt_ip.payload
                # Check the type of the Layer 3 protocol.
                if pkt_ip.proto == 1:
                    print("\t\t[+] Protocol ICMP")
                    print(hexdump(pkt_segment))
                elif pkt_ip.proto == 6:
                    print("\t\t[+] Protocol TCP")
                    print("\t\t[+] Source Port:", pkt_segment.sport)
                    print("\t\t[+] Destination Port:", pkt_segment.dport)
                    print("\t\t[+] Data:")
                    print(hexdump(pkt_segment))
                    print()
                elif pkt_ip.proto == 17:
                    print("\t\t[+] Protocol UDP")
                    print("\t\t[+] Source Port:", pkt_segment.sport)
                    print("\t\t[+] Destination Port:", pkt_segment.dport)
                    print("\t\t[+] Data:")
                    print(hexdump(pkt_segment))
                else:
                    print("\t\t[+] IP Protocol ID:", pkt_segment.proto)

            # Check if it is ARP IEEE 802 Ethertype 2054
            elif str(pkt.type) == "2054":
                # Check if it is 1 (Request) or 2 (Response) so it can display all the information correctly
                if pkt_ip.op == 1:
                    print("\t[+] Packet Type: ARP REQUEST")
                    print(f"\t[+] Who has {pkt_ip.pdst}? Tell {pkt_ip.psrc}")
                elif pkt_ip.op == 2:
                    print("\t[+] Packet Type: ARP RESPONSE")
                    print(f"\t[+] {pkt_ip.psrc} at {pkt_ip.hwsrc}")

            # Check if it is IPv6 IEEE 802 Ethertype 34525
            elif str(pkt.type) == "34525":
                print("IPv6 Not implemented yet.")

        except Exception as msg:
            print("[-]###", str(msg), "not found ###")


def main():
    options = get_arg()
    interface = options.interface
    filters = options.filters
    store = options.store_true
    sniffer = Sniffer(interface, filters, store)
    sniffer.start()


if __name__ == '__main__':
    main()
