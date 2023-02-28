from bcc import BPF
'''
Code  : 

    // kprobe__<kernel function to be hooked>   
    // bcc takes the part after kprobe to be a kernel function that needs to  be hooked
    
    int kprobe__sys_clone(void *ctx) { 
        bpf_trace_printk("Hello, World!\\n"); // input to debug trace of (/sys/kernel/debug/tracing/trace_pipe)
        return 0; 
    }

BCC Function :
        trace_print () 
        // bcc inplementation : gets the output of tracepipe and forwards it to std out
         
'''
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()


