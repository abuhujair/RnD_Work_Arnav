#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

// Layer2 Constants
#define ETH_HLEN 14

// Layer3 Constants
#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1

// Layer4 Constants

// Layer7 Constants
// HTTP
#define MIN_HTTP_TLEN 50
#define OK_STATUS 200
#define NOT_FOUND_STATUS 404

// Application Requirement
#define PORT_TO_MONITOR 80

// MAP to store the index of all programs
BPF_PROG_ARRAY(prog_array, 10);

// MAP to store metric by user
#define TAG_LENGTH 10
struct metric_key{
    __u16 src_port;
};
struct metric_data{
    char tag[TAG_LENGTH];
    __u8 tag_length;
    __u8 tag_lps[TAG_LENGTH];
};
BPF_HASH(user_metric,struct metric_key, struct metric_data);

// Map to store state in between tail_call
struct tail_call_state{
    __u32 payload_offset;
    __u32 payload_length;
};
BPF_HASH(tail_state, struct __sk_buff *, struct tail_call_state);

int http_header_parser(struct __sk_buff *skb){
    struct __sk_buff *sKey = skb;
    struct tail_call_state * statep;
    if(statep==NULL){
        goto HTTP_PARSER_EXIT;
    }

HTTP_PARSER_EXIT:
    return 0;
}

int tcp_header_parser(struct __sk_buff *skb){
    struct __sk_buff *sKey = skb;

    struct metric_key mKey = {
        .src_port = 0
    };
    struct metric_data *mData;

    __u8 *cursor = 0;
    struct ethernet_t * ethernet = cursor_advance(cursor, sizeof(struct ethernet_t));
    
    struct ip_t * ip = cursor_advance(cursor, sizeof(struct ip_t));
    __u8 ip_header_length = ip->hlen << 2; // Shift Left 2 -> *4 multiply
    if(ip_header_length < sizeof(struct ip_t)){
        goto TCP_PARSER_EXIT;
    }
    if(ip->nextp != IP_TCP){
        goto TCP_PARSER_EXIT;
    }
    // Shift cursor forward for dynamic header size
    void *_ = cursor_advance(cursor,(ip_header_length - sizeof(struct ip_t)));

    struct tcp_t *tcp = cursor_advance(cursor,sizeof(struct tcp_t));

    mKey.src_port = tcp->src_port;
    mData = user_metric.lookup(&mKey);
    if(mData == NULL){
        goto TCP_PARSER_EXIT;
    }
    __u32 tcp_header_length = tcp->offset << 2;
    
    // Create and save state in tail_state map
    struct tail_call_state state = {
        .payload_offset = 0;
        .payload_length = 0;
    };
    state.payload_length = ETH_HLEN + ip_header_length + tcp_header_length;
    state.payload_offset = ip->tlen - ip_header_length - tcp_header_length;
    tail_state.update(&sKey,&state);

    // Tail Call to HTTP header parser
    prog_array.call(skb,2);

    // Delete the state if it already exist
    struct tail_call_state * statep;
    statep = tail_state.lookup(&sKey)
    if(statep != NULL){
        tail_state.delete(&sKey);
    }

TCP_PARSER_EXIT:
    return 0;
}