#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14
#define MAX 20
#define MIN_HTTP_TLEN 50
#define OK_STATUS 200
#define NOT_FOUND_STATUS 404
#define MAX_LEN 50
// #define Attribute_Len 14
#define Attribute_Len 5
// #define delimeter_character '\r'
#define delimeter_character ','

enum state
{
    GRAB_HLEN,
    GRAB_ID,
    GRAB_DATA
};

struct program_state_key
{
    __u32 src_ip;            // source ip
    unsigned short src_port; // destination port
};

struct data_key
{
    char data[MAX_LEN];
};

struct data_metric
{
    __u32 count;
    __u32 max_value;
    __u32 min_value;
};

BPF_PERF_OUTPUT(skb_events);

BPF_HASH(ps_map, struct program_state_key, struct data_key, 5);

int packet_monitor(struct __sk_buff *skb)
{
    bpf_trace_printk("\n\n--------------Func Start-----------");
    __u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(struct ethernet_t));

    struct ip_t *ip = cursor_advance(cursor, sizeof(struct ip_t));

    // calculate ip header length
    // value to multiply * 4
    // e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte

    __u32 ip_header_length = ip->hlen << 2; // Shift left 2 -> *4 multiply

    if (ip_header_length < sizeof(struct ip_t)){
        goto EXIT;
    }

    if (ip->nextp != IP_TCP){
        goto EXIT;
    }
    bpf_trace_printk("CheckPoint :TCP");

    // shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length - sizeof(struct ip_t)));

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(struct tcp_t));
    if (tcp->src_port != 15100)
        goto EXIT;

    bpf_trace_printk("CheckPoint :PORT");
    __u32 tcp_header_length = tcp->offset << 2;
    __u32 payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
    __u32 payload_length = ip->tlen - ip_header_length - tcp_header_length;
    __u32 total_len = payload_length + payload_offset;

    if (payload_length <= MIN_HTTP_TLEN)
        goto EXIT;

    bpf_trace_printk("CheckPoint :payload_len");

 
    // limit of 512 bytes for total stack 
    // read uptill the payload length as mtu can be 1500 bytes 
    long status;
    char local_data[305] = {0};
    const unsigned int local_data_limit = 300;
    // int data_itr =0 ;
    int i =0;
    char flag = '0';
    int j_val =0;
    // char arr [] = {'C','o','n','t','e','n','t','-','L','e','n','g','t','h'};
    char arr [] = {'\'','i','d','\'',':'};
    for(i=0;i<5;i++){

        if(payload_length < local_data_limit)
            break;

        status = bpf_skb_load_bytes(skb,payload_offset,local_data,local_data_limit);
        if(status !=0 )
            goto EXIT;    

        for(int j=0;j<(local_data_limit-Attribute_Len);j++){
            flag='0';
            for(int k=0;k<Attribute_Len ;k++){
                if(arr[k]==local_data[j+k])
                    flag='1';
                else{
                    flag='0';                    
                    break;
                }
            }
            if(flag=='1'){
                j_val=payload_offset+j+Attribute_Len;
                break;
            }
        }
        if(flag=='1'){
            break;
        }
        payload_length -= local_data_limit;
        payload_offset += local_data_limit;
    }

    int k=0;

    if(flag=='0'){
        for(i=payload_offset;i<(total_len-Attribute_Len)&&i<local_data_limit;i++){
            for(int k=0;k<Attribute_Len ;k++){
                char c = load_byte(skb,i+k);
                if(arr[k]==c)
                    flag='1';
                else{
                    flag='0';                    
                    break;
                }
            }
            if(flag=='1'){
                j_val = payload_offset+i+Attribute_Len;
                break;
            }
        }
    }

    bpf_trace_printk("CheckPoint :SKB data"); 

    if(flag=='0'){
        bpf_trace_printk("CheckPoint :Attribute Not Found");
        goto EXIT;
    }

    bpf_trace_printk("CheckPoint :Attribute Found");
    struct program_state_key ps_k = {
        .src_port = 0,
        .src_ip = 0};

    ps_k.src_port = tcp->src_port;
    ps_k.src_ip = ip->src;

    struct data_key *d = ps_map.lookup(&ps_k);
    if (d)
    {
        bpf_trace_printk("CheckPoint :data");
        // max len of the attribute
        for(int i=0;i<10;i++){
            char c=(char)load_byte(skb,(j_val+i));
            if(c==delimeter_character)
                break;
            d->data[i] = c;
        }

        goto EXIT;
    }

    struct data_key d_new = {
        .data = {0}};
    
    bpf_trace_printk("CheckPoint :New Data");

    for(int i=0;i<10;i++){
        char c=(char)load_byte(skb,(j_val+i));
        if(c==delimeter_character)
            break;        
        d_new.data[i] = c;
    }

    ps_map.lookup_or_try_init(&ps_k, &d_new);

EXIT:
    bpf_trace_printk("--------------Func End-----------\n\n");
    return 0;
}
