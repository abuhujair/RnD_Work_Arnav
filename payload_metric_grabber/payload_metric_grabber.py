#!/usr/bin/python

from bcc import BPF
import time
import sys
from ctypes import *
import ipaddress
import os

def help():
    print("Execute: {0} <attribute to Monitor>".format(sys.argv[0]))
    print("Avaibale Attribute List:  name , id \n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    help()
elif len(sys.argv) == 2:
    attribute = sys.argv[1]

bpf = BPF(src_file = "payload_metric_grabber.c",debug = 0)
if(attribute == "name"):
    function_call = bpf.load_func("packet_monitor_name", BPF.SOCKET_FILTER)
elif(attribute == "id"):
    function_call = bpf.load_func("packet_monitor_id", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_call, "lo")
bpf_map = bpf.get_table('ps_map')    # retrieve metric bpf_map
bpf_map.clear() # delete old bpf_map entires  
os.system('clear')

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