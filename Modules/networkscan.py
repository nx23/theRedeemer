#!/usr/env/bin python
from scapy.all import *
import argparse


def get_arg():
    parse = argparse.ArgumentParser()
    parse.add_argument("-t", "--target", dest="target", help="Specify ip or ip range to scan.")
    options = parse.parse_args()
    return options


class NetworkScan:

    def __init__(self, target):
        self.target = target
        self.host_list = []

    def start(self):
        print("[*] Start scanning", self.target)
        host_list = NetworkScan.arp_scan(self)
        NetworkScan.show_results(host_list)

    def arp_scan(self):
        # Create a packet with the net ip destination.
        arp_segment = ARP(pdst=self.target)
        # Create a broadcast frame.
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Assembly our frame.
        arp_probe = ether_frame/arp_segment
        # Send our probe and receive the answer.
        # Note: srp return 2 lists (answered and unanswered), only the answered is needed.
        probe_answered = srp(arp_probe, verbose=False, timeout=1)[0]
        # For a organized answer, a list of dict is made.
        for element in probe_answered:
            # Enter the results into the list
            host_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
            self.host_list.append(host_dict)
        return self.host_list

    @staticmethod
    def show_results(host_list):
        for host in host_list:
            host_ip = host["IP"]
            host_mac = host["MAC"]
            print(f"[+] IP: {host_ip}\t\tMAC: {host_mac}")


def main():
    options = get_arg()
    network_scan = NetworkScan(options.target)
    network_scan.start()


if __name__ == '__main__':
    main()

