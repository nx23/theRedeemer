#!/usr/env/bin python
from scapy.all import *
import argparse
import sys

# WiFi_Scan parameters
def get_arg():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="interface", help="Specify the interface to be used.")
    parse.add_argument("-f", "--filters", dest="filters", help="Specify the filter to be used", default=None)
    arguments = parse.parse_args()
    return arguments


class WiFiScan:
    # This variable is declared so that we can use the set of devices found only internally
    devices_found = []

    def __init__(self, interface, filters):
        self.interface = interface
        self.filters = filters

    @staticmethod
    def information_extractor(pkt):
        try:
            # Check for a Dot11 Beacon layer
            if pkt.haslayer(Dot11Beacon):
                # Check for a management frame
                if pkt.type == 0 and pkt.subtype == 8:
                    # Create a string from pkt.info so that it can remove de 'b' letter from de start
                    # This is done to a better display on the screen
                    bssid = str(pkt.info)
                    # create a new device if all of the above match
                    new_device = {"essid": pkt.addr2, "bssid": bssid[1:]}
                    # If it wasn't listed before append to the devices list and show it on screen
                    if new_device not in WiFiScan.devices_found:
                        WiFiScan.devices_found.append(new_device)
                        print(f"\t{new_device['essid']}\t\t{new_device['bssid']}")
                        time.sleep(1)

        except (KeyboardInterrupt, SystemExit):
            WiFiScan.stop()

    def start(self):
        print("[*] Scanning for WiFi Networks around ...")
        print("\tESSID\t\t\t\tBSSID")
        sniff(iface=self.interface, filter=self.filters, store=False, prn=WiFiScan.information_extractor)

    @staticmethod
    def stop():
        print("[!] Scan stopped ...")
        sys.exit()


def main():
    options = get_arg()
    interface = options.interface
    filters = options.filters
    wifiscan = WiFiScan(interface, filters)
    wifiscan.start()


if __name__ == '__main__':
    main()

