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

struct Key_user{
    u32 port;
};

struct Metric{
    u16 ok_count;
    u16 not_found_count;
    u16 other;
    u32 seq_num;
    u32 ack_num;
};

BPF_PERF_OUTPUT(skb_events);

// BPF_HASH(data_map, struct Key, struct Value, 5);
BPF_HASH(metric_map, struct Key_user, struct Metric, 5);

int packet_monitor(struct __sk_buff *skb)
{
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    struct ip_t *ip = cursor_advance(cursor, sizeof(struct ip_t));

    // calculate ip header length
    // value to multiply * 4
    // e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte

    u32 ip_header_length = ip->hlen << 2; // Shift left 2 -> *4 multiply

    if (ip_header_length < sizeof(struct ip_t))
    {
        return 0;
    }
    if (ip->nextp != IP_TCP)
    {
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

    if (payload_length <= MIN_HTTP_TLEN)
        return 0;

    struct Key_user ku = {
        .port=0
    };

    ku.port = tcp->dst_port;

    char init_payload[MIN_HTTP_TLEN]={0};
    int init_payload_itr=0;
    int i = 0;
    for(i=payload_offset;i<total_len;i++){
        init_payload[init_payload_itr] = (char)load_byte(skb,i);
        init_payload_itr++;
        if(init_payload_itr==MIN_HTTP_TLEN)
            break;
    }    

    // HTTP /2   XXX
    // 1234 56 7 ---
    init_payload_itr=0;
    if(init_payload[0]=='H' && init_payload[1]=='T' && init_payload[2]=='T' && init_payload[3]=='P'){
        init_payload_itr=4;

        // get to first ' '
        while(init_payload[init_payload_itr]!=' ' && init_payload_itr < MIN_HTTP_TLEN){
            init_payload_itr++;
        }

        //for the ' '
        init_payload_itr++;

        int status=0;
        // get the next 3 characters
        while(init_payload[init_payload_itr]!=' ' && init_payload_itr < MIN_HTTP_TLEN){
            status = status*10+(init_payload[init_payload_itr]-'0');
            init_payload_itr++;
        }

        struct Metric *m = metric_map.lookup(&ku);

        if(m){
            if((m->seq_num != tcp->seq_num) && (m->ack_num != tcp->ack_num) ){
                m->seq_num = tcp->seq_num;
                m->ack_num = tcp->ack_num;
                switch (status)
                {
                    case OK_STATUS:
                        m->ok_count++;
                        break;
                    
                    case NOT_FOUND_STATUS:
                        m->not_found_count++;
                        break;

                    default:
                        m->other++;
                        break;
                }
            }
        }
        else{
            struct Metric m_new={
                .ok_count=0,
                .not_found_count=0,
                .other=0,
                .seq_num=0,
                .ack_num=0
            };
            m_new.seq_num = tcp->seq_num;
            m_new.ack_num = tcp->ack_num;
            switch (status)
            {
                case OK_STATUS:
                    m_new.ok_count++;
                    break;
                
                case NOT_FOUND_STATUS:
                    m_new.not_found_count++;
                    break;

                default:
                    m_new.other++;
                    break;
            }
            metric_map.lookup_or_try_init(&ku, &m_new);
        }
    }
    return 0;
}

