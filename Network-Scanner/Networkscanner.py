
from scapy.layers.l2 import ARP, Ether
from scapy.all import arping
import scapy.all as scapy
import optparse


#1)arp_request
#2)broadcast
#3)response

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i","--ipaddress", dest="ip_address",help="Enter IP Address")

    (user_input,arguments) = parse_object.parse_args()

    if not user_input.ip_address:
        print("Enter IP Address")

    return user_input

def scan_my_network(ip):
    arp_request_packet = ARP(pdst=ip)
    #scapy.ls(scapy.ARP())
    broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())
    combined_packet = broadcast_packet/arp_request_packet
    (answered_list,unanswered_list) = scapy.srp1(combined_packet,timeout=3)
    answered_list.summary()


user_ip_address = get_user_input()
scan_my_network(user_ip_address.ip_address)