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
    struct ethernet_t * ethernet;
    struct ip_t * ip;
    struct tcp_t * tcp;
};
BPF_HASH(tail_state, struct __sk_buff *, struct tail_call_state);

// Data-Structure to create pointer to skb->data
#define PAYLOAD_LENGTH 2500
struct payload_t{
    __u8 data;
} BPF_PACKET_HEADER;


int http_payload_parser(struct __sk_buff *skb){
    struct __sk_buff *sKey = skb;

    // Retrieving state
    struct tail_call_state * statep;
    statep = tail_state.lookup(&sKey);
    if(statep == NULL){
        goto HTTP_PARSER_EXIT;
    }
    struct tcp_t * tcp = statep->tcp;
    __u8 *cursor = 0;
    cursor_advance(cursor,statep->payload_offset);

    // Retrieving metric
    struct metric_key mKey = {
        .src_port = 0,
    };
    mKey.src_port = tcp->src_port;
    struct metric_data *mData;
    mData = user_metric.lookup(&mKey);
    if(mData == NULL){
        goto HTTP_PARSER_EXIT;
    }

    bpf_trace_printk("HTTP payload parser %x %d %s\n", sKey, mData->tag_length, mData->tag);

    // Creating struct to point to Payload_offset
    struct payload_t * payload;
    // int8_t j = 0;
    __u8 j = 0;
    // int8_t k = -1;
    __u16 i = 0;
    for(;i<PAYLOAD_LENGTH && i<statep->payload_length && j < TAG_LENGTH; ){
        payload = (void*)(cursor+i);
        if(payload->data == mData->tag_lps[j]){
            if(j == mData->tag_length-1){
                bpf_trace_printk("%d",cursor+i);
                break;
            }
            j++;
            // k++;
            i++;
        }
        else if(j>0){
            __u8 k = j-1;
            if( k >=0 && k < TAG_LENGTH)
                j = mData->tag_lps[k];
            // k = j-1;
        }
        else{
            i++;
        }
    }

    // for(int i = 0; i<TAG_LENGTH ; i++){
    //     bpf_trace_printk("%x",mData->tag[i], mData->tag_lps[i]);
    // }
    // bpf_trace_printk("Checkpoint2\n");
    // prog_array.call(skb,2);
    
HTTP_PARSER_EXIT:
    tail_state.delete(&sKey);
    return 0;
}

int tcp_header_parser(struct __sk_buff *skb){
    struct __sk_buff *sKey = skb;

    struct metric_key mKey = {
        .src_port = 0
    };
    struct metric_data *mData;

    __u8 *cursor = 0;
    // Ethernet Header Parsing
    struct ethernet_t * ethernet = cursor_advance(cursor, sizeof(struct ethernet_t));
    
    // IP Header Parsing
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

    // TCP Header Parsing
    struct tcp_t *tcp = cursor_advance(cursor,sizeof(struct tcp_t));
    mKey.src_port = tcp->src_port;
    mData = user_metric.lookup(&mKey);
    if(mData == NULL || tcp->flag_syn || tcp->flag_fin){
        goto TCP_PARSER_EXIT;
    }
    __u8 tcp_header_length = tcp->offset << 2;
    

    // Create and save state in tail_state map
    struct tail_call_state state = {
        .payload_offset = 0,
        .payload_length = 0,
        .ethernet = NULL,
        .ip = NULL,
        .tcp = NULL,
    };
    state.payload_length = ip->tlen - ip_header_length - tcp_header_length;
    state.payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    state.ethernet = ethernet;
    state.ip = ip;
    state.tcp = tcp;

    if(state.payload_length == 0){
        goto TCP_PARSER_EXIT;
    }

    tail_state.update(&sKey,&state);

    // Tail Call to HTTP header parser
    bpf_trace_printk("TCP header parser %x %d %d\n", sKey, state.payload_offset, state.payload_length);
    prog_array.call(skb,2);
    bpf_trace_printk("Tail Call Failed %x %d %d\n", sKey, state.payload_offset, state.payload_length);


    // Delete the state if it already exist
    struct tail_call_state * statep;
    statep = tail_state.lookup(&sKey);
    if(statep != NULL){
        tail_state.delete(&sKey);
    }

TCP_PARSER_EXIT:
    return 0;
}