#!/usr/env/bin python
from scapy.all import *
import argparse
import sys

# WiFi_Scan parameters
def get_arg():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="interface", help="Specify the interface to be used.")
    parse.add_argument("-b", "--bssid", dest="bssid", help="Specify the bssid to look for.")
    arguments = parse.parse_args()
    return arguments


class HandshakeGrabber:
    # this class variable is needed to search for a specific bssid, it will be initialized on de init method
    bssid = None

    def __init__(self, interface, bssid):
        self.interface = interface
        HandshakeGrabber.bssid = bssid

    @staticmethod
    def information_extractor(pkt):
        # Check for a Dot11 EAPOL layer
        if pkt.haslayer(EAPOL):
            layer_fcs = pkt.getlayer(Dot11FCS)
            # If the addr2 on the frame match the one specified by de user, show msg
            if layer_fcs.addr2 == HandshakeGrabber.bssid:
                print(f"Handshake for {HandshakeGrabber.bssid} grabbed.")
                HandshakeGrabber.write_cap(pkt)

    def start(self):
        print("[*] Scanning for handshakes ...")
        # The filter ether proto 0x0888e will make the sniffer only scan for handshakes
        HandshakeGrabber.pkts = sniff(iface=self.interface, filter='ether proto 0x0888e',
                                      prn=HandshakeGrabber.information_extractor)

    @staticmethod
    def stop():
        print("[!] Scan stopped ...")
        sys.exit()

    @staticmethod
    # Append the handshake grabbed to the cap file, if it does not exist, create it
    def write_cap(pkt):
        file_name = "The_Redeemer_Handshake_" + HandshakeGrabber.bssid + ".cap"
        wrpcap(file_name, pkt, append=True)
        print("[+] Pcap file created.")

def main():
    options = get_arg()
    interface = options.interface
    bssid = options.bssid
    handshakegrabber = HandshakeGrabber(interface, bssid)
    handshakegrabber.start()


if __name__ == '__main__':
    main()

