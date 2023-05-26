#!/usr/bin/python3

from bcc import BPF
import time
import sys
import ctypes as ct
import os

# Loading Functions from eBPF code
bpf = BPF(src_file = "extended_metric_grabber.c",debug = 0)
packet_monitor = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)
packet_parser = bpf.load_func("packet_header_parser", BPF.SOCKET_FILTER)

# Program Array for Tail-Call
prog_array = bpf.get_table("prog_array")
prog_array[ct.c_int(2)] = ct.c_int(packet_parser.fd)

# User Metric Map
# Struct Definition
TAG_LENGTH = 10
class MetricKey(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("src_port", ct.c_uint16)
    ]
class MetricData(ct.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("tag", ct.c_char*TAG_LENGTH),
        ("tag_length",ct.c_uint8),
        ("tag_lps", ct.c_uint8*TAG_LENGTH),
    ]

    def __init__(self, tag, tag_lps) -> None:
        self.tag = tag.encode('utf-8')
        self.tag_length = ct.c_uint8(len(tag))
        self.tag_lps = (ct.c_uint8*TAG_LENGTH)(*tag_lps)
        super().__init__()

def calculateLPS(tag):
    tag_lps = [0]*TAG_LENGTH
    for i in range(1,len(tag)):
        if tag[tag_lps[i-1]] == tag[i]:
            tag_lps[i] = tag_lps[i-1]+1
    return tag_lps

mKey = MetricKey()
mKey.src_port = ct.c_uint16(80)

tag = '\"id\":'
mData = MetricData(tag,calculateLPS(tag))

user_metric = bpf["user_metric"]
user_metric[mKey] = mData

BPF.attach_raw_socket(packet_monitor, "lo")













# bpf_map = bpf.get_table('ps_map')    # retrieve metric bpf_map
# bpf_map.clear() # delete old bpf_map entires  
# os.system('clear')

# try:
#     print("Ready To Receive\n")
#     while True :
#         packet_cnt_output = bpf_map.items()
#         output_len = len(packet_cnt_output)
#         total_count = 0 
#         time.sleep(1)
#         os.system('clear')
#         for i in range(0,output_len):
#             print("\033[1;37m %s" %(str(packet_cnt_output[i][0].data)[1:]),end = " ")
#             bar = '#'*int((packet_cnt_output[i][1].count)/2)
#             total_count = total_count + (packet_cnt_output[i][1].count)/2
#             print("\033[1;32m %s" %(bar))
#         print("\033[1;37m-------total %d------------------------" %(total_count))      
# except KeyboardInterrupt:
#     sys.stdout.close()
#     pass