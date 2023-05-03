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
bpf = BPF(src_file = "status_metric.c",debug = 0)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function_skb_matching, interface)


metric_map = bpf.get_table('metric_map')    # retrieve metric map

metric_map.clear() # delete map entires after printing output. confiremd it deletes values and keys too 
ok_count=0
nf_count=0

try:
    print("Ready To Receive\n")
    while True :
        packet_cnt_output = metric_map.items()
        output_len = len(packet_cnt_output)
        for i in range(0,output_len):
            temp_ok = packet_cnt_output[i][1].ok_count
            temp_nf = packet_cnt_output[i][1].not_found_count
            if(temp_nf != nf_count or temp_ok!=ok_count):
                if(temp_nf == nf_count):
                    print("\033[1;31m Not Found : %d" %(nf_count))
                else:
                    nf_count = temp_nf
                    print("\033[1;31m Not Found : %d" %(nf_count))
                if(temp_ok == ok_count):
                    print("\033[1;32m OK : %d" %(ok_count))
                else:
                    ok_count = temp_ok
                    print("\033[1;32m OK : %d" %(ok_count))
                print("\033[1;37m--------------------------\n")
        time.sleep(1)
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass

# Foreground 	Background
# Black 	30 	Black 	40
# Red 	    31 	Red 	41
# Green     32 	Green 	42
# Yellow    33 	Yellow 	43
# Blue 	    34 	Blue 	44
# Purple    35 	Purple 	45
# Cyan 	    36 	Cyan 	46
# White     37 	White 	47
