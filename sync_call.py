from bcc import BPF
'''
Code  : 

    // kprobe__<kernel function to be hooked>   
    // bcc takes the part after kprobe to be a kernel function that needs to  be hooked
    
    int kprobe__sys_sync(void *ctx) { 
        bpf_trace_printk("Tracing sys_sync()... Ctrl-C to end\\n"); // input to debug trace of (/sys/kernel/debug/tracing/trace_pipe)
        return 0; 
    }

BCC Function :
        trace_print () 
        // bcc inplementation : gets the output of tracepipe and forwards it to std out
         
'''

prog = """
    int kprobe__sys_sync(void *ctx) { 
        bpf_trace_printk("Tracing sys_sync()... Ctrl-C to end\\n"); // input to debug trace of (/sys/kernel/debug/tracing/trace_pipe)
        return 0; 
    }
"""
sys_sync_bpf = BPF(text=prog)
sys_sync_bpf.trace_print()

