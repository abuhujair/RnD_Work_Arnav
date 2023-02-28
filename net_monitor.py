#!/usr/bin/python
#
# net_monitor.py Aggregates incoming network traffic
# outputs source ip, destination ip, the number of their network traffic, and current time
# how to use : net_monitor.py <net_interface> 
# 
# Copyright (c) 2020 YoungEun Choe

from bcc import BPF
import time
from ast import literal_eval
import sys

def help():
    print("execute: {0} <net_interface>".format(sys.argv[0]))
    print("e.g.: {0} eno1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    help()
elif len(sys.argv) == 2:
    INTERFACE = sys.argv[1]

bpf_text = """

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14

BPF_PERF_OUTPUT(skb_events);
BPF_HASH(packet_cnt, u64, long, 256); 

int packet_monitor(struct __sk_buff *skb) {
    u8 *cursor = 0;
    u32 saddr, daddr;
    long* count = 0;
    long one = 1;
    u64 pass_value = 0;
    
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if (ip->nextp != IP_ICMP) 
    {
      /*  if (ip -> nextp != IP_UDP) 
        {
            if (ip -> nextp != IP_ICMP) 
                return 0; 
        }
        */
        return 0;
    }
    
    saddr = ip -> src;
    daddr = ip -> dst;
    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;

    count = packet_cnt.lookup(&pass_value); 
    if (count)  // check if this map exists
        *count += 1;
    else        // if the map for the key doesn't exist, create one
        {
            packet_cnt.update(&pass_value, &one);
        }
    return -1;
}

"""

from ctypes import *
import ctypes as ct
import sys
import ipaddress

OUTPUT_INTERVAL = 1

bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

try:
    while True :
        time.sleep(OUTPUT_INTERVAL)
        # retrieeve packet_cnt map
        packet_cnt = bpf.get_table('packet_cnt')    # retrieeve packet_cnt map
        packet_cnt_output = packet_cnt.items()
        output_len = len(packet_cnt_output)
        for i in range(0,output_len):
            print(packet_cnt_output[i])

            print(str(packet_cnt_output[i][0]))
            temp = int(str(packet_cnt_output[i][0])[8:-1]) # c_ulong(13882346294099160331)[8:-1] => 13882346294099160331
            print(temp)

            print(str(bin(temp)))
            temp = int(str(bin(temp))[2:]) # 0b11....01....11 => 11....01....11
            print(temp)

            src = int(str(temp)[:32],2) # part1 
            dst = int(str(temp)[32:],2)
            print(ipaddress.ip_address(src))
            print(ipaddress.ip_address(dst))
            pkt_num = str(packet_cnt_output[i][1])[7:-1] # c_long(2) => 2

        packet_cnt.clear() # delete map entires after printing output. confiremd it deletes values and keys too 
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass