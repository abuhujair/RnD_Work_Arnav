from bcc import BPF


'''
NOTE :
Global variables not allowed 

'''

# your c code 
prog = """
    int hook(void *ctx) { 
        bpf_trace_printk("Tracing call()..Ctrl-C to end\\n"); // input to debug trace of (/sys/kernel/debug/tracing/trace_pipe)
        return 0; 
    }
"""

# system call name
system_call_to_hook = "clone"    

#initialize BPF object wiht the c program
bpf_obj = BPF(text=prog)

# attach custom hook using attach_kprobe on syscall "sync" with function "add_bpf_sync"
bpf_obj.attach_kprobe(event=bpf_obj.get_syscall_fnname(system_call_to_hook), fn_name="hook")

# print the trace output to std out
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = bpf_obj.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))


