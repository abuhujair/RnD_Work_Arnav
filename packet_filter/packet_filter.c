#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14
#define MAX 100
#define MIN_HTTP_TLEN 16
#define OK_STATUS 200
#define NOT_FOUND_STATUS 404

struct Key
{
    u32 src_ip;              // source ip
    u32 dst_ip;              // destination ip
    unsigned short src_port; // source port
    unsigned short dst_port; // destination port
    u32 seq_num;
    u32 ack_num;
};

struct Value
{
    u16 data_len;
    char data[MAX];
    int count;
};


BPF_PERF_OUTPUT(skb_events);

BPF_HASH(data_map, struct Key, struct Value, 5);

int packet_monitor(struct __sk_buff *skb)
{
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    struct ip_t *ip = cursor_advance(cursor, sizeof(struct ip_t));

    // calculate ip header length
    // value to multiply * 4
    // e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte

    u32 ip_header_length = ip->hlen << 2; // Shift left 2 -> *4 multiply

    if (ip_header_length < sizeof(struct ip_t)){
        return 0;
    }
    if (ip->nextp != IP_TCP){
        return 0;
    }

    // shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length - sizeof(struct ip_t)));

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(struct tcp_t));
    if (tcp->dst_port != 15100)
        return 0;

    u32 tcp_header_length = tcp->offset << 2;
    u32 payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    u32 payload_length = ip->tlen - ip_header_length - tcp_header_length;
    u32 total_len = payload_length+payload_offset;

    if (payload_length <= 10)
        return 0;
    
    bpf_trace_printk("CheckPoint :payload_len\n");

    struct Key k = {
        .src_ip = 0,
        .dst_ip = 0,
        .src_port = 0,
        .dst_port = 0,
        .seq_num =0,
        .ack_num =0
    };
    k.dst_ip = ip->dst;
    k.src_ip = ip->src;
    k.dst_port = tcp->dst_port;
    k.src_port = tcp->src_port;
    k.seq_num = tcp->seq_num;
    k.ack_num = tcp->ack_num;

    struct Value *v = data_map.lookup(&k);
    u16 data_itr=0;
    int i=0;
    if (v)
    {   
        // if((v->seq_num != tcp->seq_num) && (v->ack_num != tcp->ack_num) ){
            data_itr = v->data_len;
            for(i=payload_offset;i<total_len && ((data_itr + (i-payload_offset)) < MAX);i++){
                v->data[data_itr+(i-payload_offset)] = (char)load_byte(skb,i);
            }
            v->count++;
            v->data_len = data_itr+(i-payload_offset);        

        // }
        return 0;
    }
    
    struct Value v_new = {
        .data_len=0,
        .data={0},
        .count=0
    };

    data_itr=0;
    v_new.count = 1;
    for(i=payload_offset;i<total_len;i++){
        v_new.data[data_itr] = (char)load_byte(skb,i);
        data_itr++;
        v_new.data_len++;
        if(data_itr>=MAX)
            break;
    }
    data_map.lookup_or_try_init(&k, &v_new);
    return 0;
}

