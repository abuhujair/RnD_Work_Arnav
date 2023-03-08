#!/usr/bin/python

from bcc import BPF
import time
import sys
from ctypes import *
import ipaddress


def help():
    print("execute: {0} <net_interface>".format(sys.argv[0]))
    print("e.g.: {0} eno1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    help()
elif len(sys.argv) == 2:
    interface = sys.argv[1]

OUTPUT_INTERVAL = 1

# bpf = BPF(text=bpf_text)
bpf = BPF(src_file = "icmp_filter.c",debug = 0)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, interface)

try:
    while True :
        time.sleep(OUTPUT_INTERVAL)
        # retrieeve packet_cnt map
        packet_cnt = bpf.get_table('packet_cnt')    # retrieeve packet_cnt map
        packet_cnt_output = packet_cnt.items()
        output_len = len(packet_cnt_output)
        for i in range(0,output_len):
            # print(packet_cnt_output[i])

            # print(str(packet_cnt_output[i][0]))
            temp = int(str(packet_cnt_output[i][0])[8:-1]) # c_ulong(13882346294099160331)[8:-1] => 13882346294099160331
            # print(temp)

            # print(str(bin(temp)))
            temp = int(str(bin(temp))[2:]) # 0b11....01....11 => 11....01....11
            # print(temp)

            src = int(str(temp)[:32],2) # part1 
            dst = int(str(temp)[32:],2)
            print(ipaddress.ip_address(src))
            print(ipaddress.ip_address(dst))
            pkt_num = str(packet_cnt_output[i][1])[7:-1] # c_long(2) => 2

        packet_cnt.clear() # delete map entires after printing output. confiremd it deletes values and keys too 
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass
