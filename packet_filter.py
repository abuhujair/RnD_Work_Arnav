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
bpf = BPF(src_file = "packet_filter.c",debug = 0)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, interface)
data_map = bpf.get_table('data_map')    # retrieve metric map
data_map.clear() # delete map entires after printing output. confiremd it deletes values and keys too 

try:
    print("Ready To Receive\n")
    while True :
        packet_cnt_output = data_map.items()
        output_len = len(packet_cnt_output)
        for i in range(0,output_len):
            print(packet_cnt_output[i][0].dst_port)
            # print(packet_cnt_output[i][0].src_port)
            print(packet_cnt_output[i][1].data)
            # print(packet_cnt_output[i][1].seq_num)
            # print(packet_cnt_output[i][1].ack_num)
            # print(packet_cnt_output[i][1].count)
            print(packet_cnt_output[i][1].data_len)
        time.sleep(1)
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass
