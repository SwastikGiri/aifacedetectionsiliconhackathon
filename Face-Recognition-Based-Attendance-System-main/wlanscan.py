from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11


def scan_wifi_devices():
    print("Scanning for Wi-Fi devices...")
    wifi_devices = {}

    def handle_packet(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore')
            bssid = packet[Dot11].addr2
            if ssid not in wifi_devices:
                wifi_devices[ssid] = bssid

    sniff(iface="Wi-Fi", prn=handle_packet, count=100)

    print("Found {} Wi-Fi devices.".format(len(wifi_devices)))
    for ssid, bssid in wifi_devices.items():
        print("  SSID: {}, BSSID: {}".format(ssid, bssid))

if __name__ == "__main__":
    scan_wifi_devices()
