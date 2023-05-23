#!/usr/bin/python3

from bcc import BPF
import time
import sys
from ctypes import *
import ipaddress
import os

bpf = BPF(src_file = "extended_metric_grabber.c",debug = 0)
function_call = bpf.load_func("packet_monitor_id", BPF.SOCKET_FILTER)
last_piece = bpf.load_func("last_piece", BPF.SOCKET_FILTER)
tail_call = bpf.load_func("extend_monitor", BPF.SOCKET_FILTER)

prog_array = bpf.get_table("prog_array")
prog_array[c_int(2)] = c_int(tail_call.fd)
prog_array[c_int(3)] = c_int(last_piece.fd)


BPF.attach_raw_socket(function_call, "lo")
bpf_map = bpf.get_table('ps_map')    # retrieve metric bpf_map
bpf_map.clear() # delete old bpf_map entires  
# os.system('clear')

try:
    print("Ready To Receive\n")
    while True :
        packet_cnt_output = bpf_map.items()
        output_len = len(packet_cnt_output)
        total_count = 0 
        time.sleep(1)
        os.system('clear')
        for i in range(0,output_len):
            print("\033[1;37m %s" %(str(packet_cnt_output[i][0].data)[1:]),end = " ")
            bar = '#'*int((packet_cnt_output[i][1].count)/2)
            total_count = total_count + (packet_cnt_output[i][1].count)/2
            print("\033[1;32m %s" %(bar))
        print("\033[1;37m-------total %d------------------------" %(total_count))
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass