#!/usr/env/bin python
from Modules.networkscan import *
from Modules.sniffer import *
from Modules.arppoisoning import *
from Modules.wifiscan import *
from Modules.deauth import *
from Modules.handshakegrabber import *

import argparse


def arp_poisoning(interface, gateway_ip, target_ip):
    arp_attack = ArpPoisoning(interface, gateway_ip, target_ip)
    arp_attack.start()


def network_scan(target):
    scan = NetworkScan(target)
    scan.start()


def sniffer(interface, filters, store):
    sniffer_attack = Sniffer(interface, filters, store)
    sniffer_attack.start()


def wifi_scan(interface, filters):
    wifiscan = WiFiScan(interface, filters)
    wifiscan.start()


def handshake_grabber(interface, bssid):
    handshakegrabber = HandshakeGrabber(interface, bssid)
    handshakegrabber.start()


def deauth(interface, target_mac, access_point):
    deauth_attack = DeauthAttack(interface, target_mac, access_point)
    deauth_attack.start()


def main():
    help_msg = """
            Welcome to The Redeemer v1.4
    
    Choose a module and then the arguments needed.
    
    Network_Scan        -t, --target <target ip>
    
    ARP_Poisoning       -i, --interface <interface> -g, --gateway <gateway ip> -t, --target <target ip>
                            
    Sniffer             -t, --target <target ip> -f, --filters <filters>, -s, --store
    
    WiFi_Scan           -i, --interface <interface> -f, --filters <filters>
    
    Handshake_Grabber   -i, --interface <interface> -b, --bssid <bssid>
    
    Deauth_Attack       -i, --interface <interface> -t, --target <target mac> -a, --access_point <access point mac>
    """

    # Instantiate the parse object
    parser = argparse.ArgumentParser("The Redeemer CLI", add_help=False, description="The Redeemer",
                                     usage=help_msg)
    # This is used to personalize our version control
    parser.add_argument('-v', '--version', action='version',
                        version='The Redeemer 1.4', help="Show program's version")
    # This is used to personalize our help message
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Show this help message and exit.')

    # Tell the parse that it will be subparsers.
    subparser = parser.add_subparsers(help='Module args', dest='command')

    # NETWORK_SCAN ARGUMENTS SEGMENT #
    # Specify the arguments to networkscan module
    parser_network_scan = subparser.add_parser('Network_Scan')
    parser_network_scan.add_argument("-t", "--target", dest="target_ip", help="Specify ip or ip range to be scanned.")
    # Set the default function call so it is more organized.
    parser_network_scan.set_defaults(func=network_scan)

    # ARP_POISONING ARGUMENTS SEGMENT #
    # Specify the arguments to arppoisoning module
    parser_arp = subparser.add_parser('ARP_Poisoning')
    parser_arp.add_argument("-i", "--interface", dest="interface", help="Specify the interface to be used.")
    parser_arp.add_argument("-g", "--gateway", dest="gateway_ip", help="Specify the ip of the gateway to scan.")
    parser_arp.add_argument("-t", "--target", dest="target_ip", help="Specify the target ip to scan.")
    # Set the default function call so it is more organized.
    parser_arp.set_defaults(func=arp_poisoning)

    # SNIFFER ARGUMENTS SEGMENT #
    # Specify the arguments to sniffer module
    parser_sniffer = subparser.add_parser('Sniffer')
    parser_sniffer.add_argument("-i", "--interface", dest="interface", help="Specify the interface you want to sniff.")
    parser_sniffer.add_argument("-f", "--filter", dest="filters", help="Specify a filter if needed.", default=None)
    parser_sniffer.add_argument("-s", "--store", dest="store_true", help="True to store the packets, default False",
                       default=False)
    # Set the default function call so it is more organized.
    parser_sniffer.set_defaults(func=sniffer)

    # WIFI_SCAN ARGUMENTS SEGMENT #
    # Specify the arguments to wifiscan module
    parser_wifi_scan = subparser.add_parser('WiFi_Scan')
    parser_wifi_scan.add_argument("-i", "--interface", dest="interface", help="Specify the interface to be used.")
    parser_wifi_scan.add_argument("-f", "--filters", dest="filters", help="Specify the filter to be used", default=None)
    # Set the default function call so it is more organized.
    parser_wifi_scan.set_defaults(func=wifi_scan)

    # HANDSHAKE_GRABBER ARGUMENTS SEGMENT #
    # Specify the arguments to handshakegrabber module
    parser_handshake = subparser.add_parser('Handshake_Grabber')
    parser_handshake.add_argument("-i", "--interface", dest="interface", help="Specify the interface to be used.")
    parser_handshake.add_argument("-b", "--bssid", dest="bssid", help="Specify the bssid to look for.")
    # Set the default function call so it is more organized.
    parser_handshake.set_defaults(func=handshake_grabber)

    # DEAUTH ARGUMENTS SEGMENT #
    # Specify the arguments to deauth module
    parser_deauth = subparser.add_parser('Deauth_Attack')
    parser_deauth.add_argument("-i", "--interface", dest="interface", help="Specify the interface to be used.")
    parser_deauth.add_argument("-a", "--access_point", dest="access_point", help="Specify the MAC of the access point.")
    parser_deauth.add_argument("-t", "--target", dest="target_mac", help="Specify the MAC of the target.",
                       default="FF:FF:FF:FF:FF:FF")
    # Set the default function call so it is more organized.
    parser_deauth.set_defaults(func=deauth)

    # Parse the arguments
    module_arg = parser.parse_args()

    if module_arg.command == 'Network_Scan':
        module_arg.func(module_arg.target_ip)

    elif module_arg.command == 'ARP_Poisoning':
        module_arg.func(module_arg.interface, module_arg.gateway_ip, module_arg.target_ip)

    elif module_arg.command == 'Sniffer':
        module_arg.func(module_arg.interface, module_arg.filters, module_arg.store_true)

    elif module_arg.command == 'WiFi_Scan':
        module_arg.func(module_arg.interface, module_arg.filters)

    elif module_arg.command == 'Handshake_Grabber':
        module_arg.func(module_arg.interface, module_arg.bssid)

    elif module_arg.command == 'Deauth_Attack':
        module_arg.func(module_arg.interface, module_arg.target_mac, module_arg.access_point)

    else:
        print(f'Module {module_arg.command} not found.')


if __name__ == '__main__':
    main()

