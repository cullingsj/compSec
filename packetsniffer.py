#################################
# author@ Daniel Laden          #
# email@ dthomasladen@gmail.com #
#################################

import dpkt

f = dpkt.pcap.Reader(open("lbl-internal.20041004-1305.port002.dump.pcap", 'rb'))

for ts, pkt in f:
    try:
        eth = dpkt.ethernet.Ethernet(pkt)
    except: #not an ethernet packet
        continue
    print(eth)
    print(eth.src)
    print(eth.dst)


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
        tcp = ip.data
        print(ip)
        print(tcp)
    except: #not an ip or tcp packet
        continue
