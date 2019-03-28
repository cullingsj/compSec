#################################
# author@ Daniel Laden          #
# email@ dthomasladen@gmail.com #
#################################

import dpkt
import socket
from dpkt.compat import compat_ord


def mac_addr(address): ### Code Source 1
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet): ### Code Source 1
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)



f = dpkt.pcap.Reader(open("lbl-internal.20041004-1305.port002.dump.pcap", 'rb'))

for ts, pkt in f:
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
    except: #not an ethernet packet
        continue
    # print(eth)
    # print(mac_addr(eth.src))
    # print(mac_addr(eth.dst))

    # fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
    # syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
    # rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
    # psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
    # ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
    # urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
    # ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
    # cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
    try:
        ip = eth.data

        if ip.p != dpkt.ip.IP_PROTO_TCP: ### Code Source 2
            # We are only interested in TCP
            continue


        ### Code Source 1
        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
        ###

        ###Code Source 2
        tcp = ip.data
        if((tcp.flags & dpkt.tcp.TH_ACK)): #ACKS
            print('Found TCP ACK in Packet #%d'%ts)
        if ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
            # TCP SYN and ACK
            print('Found TCP SYN & ACK in Packet #%d'%ts)
        print('Packet #{1:d} : {0:b} = 0x{0:x}'.format(tcp.flags, num))
        ###Code Source 2
    except: #not an ip packet
        continue

#########################################################
#Coding resources
#
#(1) https://github.com/kbandla/dpkt/blob/master/examples/print_packets.py
#https://dpkt.readthedocs.io/en/latest/print_packets.html
#https://stackoverflow.com/questions/33054527/typeerror-a-bytes-like-object-is-required-not-str-when-writing-to-a-file-in
#(2) https://stackoverflow.com/a/49041285
#########################################################
