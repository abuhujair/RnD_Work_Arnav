#!/usr/bin/python

from bcc import BPF
import time
import sys
from ctypes import *
import ipaddress

bpf = BPF(src_file = "payload_metric_grabber.c",debug = 0)

function_call = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_call, "lo")

bpf_map = bpf.get_table('ps_map')    # retrieve metric bpf_map

bpf_map.clear() # delete old bpf_map entires  

try:
    print("Ready To Receive\n")
    while True :
        packet_cnt_output = bpf_map.items()
        output_len = len(packet_cnt_output)
        for i in range(0,output_len):
            print(packet_cnt_output[i][0].src_port)
            print(ipaddress.ip_address(packet_cnt_output[i][0].src_ip))
            print(str(bytearray(packet_cnt_output[i][1].data)))
            print("-------------------------------")
        time.sleep(1)
        # bpf_map.clear() # delete bpf_map entires after printing output. confiremd it deletes values and keys too 
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass
