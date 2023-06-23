#!/usr/bin/python3

from __future__ import print_function
from typing import Any
import ctypes as ct

from bcc import BPF
from bcc.utils import printb

# Load eBPF code
bpf = BPF(src_file = "extended_metric_grabber.c",debug = 0)

# User Metric Map
# Struct Definition
TAG_LENGTH = 10
class MetricKey(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("src_port", ct.c_uint16)
    ]
class MetricData(ct.Structure):
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

# Load Functions
tcp_header_parser = bpf.load_func("tcp_header_parser", BPF.SOCKET_FILTER)
http_payload_parser = bpf.load_func("http_payload_parser", BPF.SOCKET_FILTER)

# Program Array for Tail-Call
prog_array = bpf.get_table("prog_array")
prog_array[ct.c_int(2)] = ct.c_int(http_payload_parser.fd)

BPF.attach_raw_socket(tcp_header_parser, "lo")

print("Message:")
# format output
st = ""

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        if len(msg)!=2:
            # print((bytes.fromhex(st)).decode('utf-8'))
            printb(b"%s" % (msg))
            # st = ""
        else:
            pass
            # st += msg.decode('utf-8')
    except KeyboardInterrupt:
        exit()











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