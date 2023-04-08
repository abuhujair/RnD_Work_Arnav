

/*Todo :

1. Set the HTTP CHECK  -- DONE
2. multi-packet json data traversal
3. replace string repacement with optimized one .
4. Include request based save  -- 
5. optimal hopping in payload to reach the required attribute fast using some statistics of the payload.

*/ 

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

// For content-length
// #define Attribute_Len 16
// #define delimeter_character '\r'

// For ID
// #define Attribute_Len 5
// #define delimeter_character ','

// For name
#define Attribute_Len 7
#define delimeter_character ','

#define PORT_TO_MONITOR 80

struct program_state_key
{
    __u32 src_ip;            // source ip
    unsigned short src_port; // destination port
};

struct data_key{
    char data[MAX_LEN];
};

struct data_metric{
    __u32 count;
};

BPF_PERF_OUTPUT(skb_events);
BPF_HASH(ps_map, struct data_key, struct data_metric, 200);

int packet_monitor_name(struct __sk_buff *skb)
{   
    // char arr [] = {'C','o','n','t','e','n','t','-','L','e','n','g','t','h',':',' '};
    // char arr [] = {'"','i','d','"',':'};
    char arr [] = {'"','n','a','m','e','"',':'};
    const int arr_size = sizeof(arr);
    bpf_trace_printk("\n\n--------------Func Start-----------");
    __u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(struct ethernet_t));

    struct ip_t *ip = cursor_advance(cursor, sizeof(struct ip_t));

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
    if (tcp->src_port != PORT_TO_MONITOR)
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
    int i =0;
    char flag = '0';
    int j_val =0;

    for(i=0;i<5;i++){

        if(payload_length < local_data_limit)
            break;

        status = bpf_skb_load_bytes(skb,payload_offset,local_data,local_data_limit);
        if(status !=0 )
            goto EXIT;    

        for(int j=0;j<(local_data_limit-arr_size);j++){
            flag='0';
            for(int k=0;k<arr_size ;k++){
                if(arr[k]==local_data[j+k])
                    flag='1';
                else{
                    flag='0';                    
                    break;
                }
            }
            if(flag=='1'){
                j_val=payload_offset+j+arr_size;
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
    
        for(int itr=0, i=payload_offset;i<(total_len-arr_size)&&itr<local_data_limit;i++,itr++){
            for(int k=0;k<arr_size ;k++){
                char c = load_byte(skb,i+k);
                if(arr[k]==c)
                    flag='1';
                else{
                    flag='0';                    
                    break;
                }
            }
            if(flag=='1'){
                j_val = i+arr_size;
                break;
            }
        }
        bpf_trace_printk("CheckPoint :SKB data last read"); 
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

    struct data_key key ={
        .data={0}
    };

    for(int i=0;i<MAX_LEN;i++){
        char c=(char)load_byte(skb,(j_val+i));
        if(c==delimeter_character)
            break;        
        key.data[i] = c;
    }

    struct data_metric *d = ps_map.lookup(&key);
    if (d)
    {
        bpf_trace_printk("CheckPoint :data");
        // max len of the attribute
        d->count=d->count+1;
        goto EXIT;
    }

    struct data_metric d_new = {
        .count = 1};
    
    bpf_trace_printk("CheckPoint :New Data");

    
    ps_map.lookup_or_try_init(&key, &d_new);

EXIT:
    bpf_trace_printk("--------------Func End-----------\n\n");
    return 0;
}

int packet_monitor_id(struct __sk_buff *skb)
{   
    // char arr [] = {'C','o','n','t','e','n','t','-','L','e','n','g','t','h',':',' '};
    char arr [] = {'"','i','d','"',':'};
    // char arr [] = {'"','n','a','m','e','"',':'};
    const int arr_size = sizeof(arr);
    bpf_trace_printk("\n\n--------------Func Start-----------");
    __u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(struct ethernet_t));

    struct ip_t *ip = cursor_advance(cursor, sizeof(struct ip_t));

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
    if (tcp->src_port != PORT_TO_MONITOR)
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
    int i =0;
    char flag = '0';
    int j_val =0;
    
    status = bpf_skb_load_bytes(skb,payload_offset,local_data,15);
    if(status !=0 )
        goto EXIT;    


    char http_check_string []  =  {'H','T','T','P','/','1','.','1',' ','2','0','0',};
    for(i=0;i<12;i++){
        if(local_data[i]!=http_check_string[i])
            break;
    }    

    //http Fail    
    if(i!=12){
        goto EXIT;
    }

    bpf_trace_printk("CheckPoint :HTTP ok");

    for(i=0;i<5;i++){

        if(payload_length < local_data_limit)
            break;

        status = bpf_skb_load_bytes(skb,payload_offset,local_data,local_data_limit);
        if(status !=0 )
            goto EXIT;    

        for(int j=0;j<(local_data_limit-arr_size);j++){
            flag='0';
            for(int k=0;k<arr_size ;k++){
                if(arr[k]==local_data[j+k])
                    flag='1';
                else{
                    flag='0';                    
                    break;
                }
            }
            if(flag=='1'){
                j_val=payload_offset+j+arr_size;
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
    
        for(int itr=0, i=payload_offset;i<(total_len-arr_size)&&itr<local_data_limit;i++,itr++){
            for(int k=0;k<arr_size ;k++){
                char c = load_byte(skb,i+k);
                if(arr[k]==c)
                    flag='1';
                else{
                    flag='0';                    
                    break;
                }
            }
            if(flag=='1'){
                j_val = i+arr_size;
                break;
            }
        }
        bpf_trace_printk("CheckPoint :SKB data last read"); 
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

    struct data_key key ={
        .data={0}
    };

    for(int i=0;i<10;i++){
        char c=(char)load_byte(skb,(j_val+i));
        if(c==delimeter_character)
            break;        
        key.data[i] = c;
    }

    struct data_metric *d = ps_map.lookup(&key);
    if (d)
    {
        bpf_trace_printk("CheckPoint :data");
        // max len of the attribute
        d->count=d->count+1;
        goto EXIT;
    }

    struct data_metric d_new = {
        .count = 1};
    
    bpf_trace_printk("CheckPoint :New Data");

    
    ps_map.lookup_or_try_init(&key, &d_new);

EXIT:
    bpf_trace_printk("--------------Func End-----------\n\n");
    return 0;
}

