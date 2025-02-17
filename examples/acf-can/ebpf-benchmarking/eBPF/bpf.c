#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include <math.h>
#include "utils.h"


#define MAX_SPLIT_HISTOGRAM 20

struct config
{
    __u32 pid_sender;
    __u32 pid_receiver;
    __be32 src_ip;
    __be32 dest_ip;
    __u32 src_port;
    __u32 dest_port;
} __attribute__((packed));
// HINT: Dont declare config as a static variable
volatile const struct config CONFIG;
#define cfg (&CONFIG)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SPLIT_HISTOGRAM);
    __type(key, u32);
    __type(value, u64);
} hist SEC(".maps");

__u64 last_recv_ts = 0;
//float jitter=0;


SEC("tracepoint/raw_syscalls/sys_enter_sendto")
int tp_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{   
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_time, &pid, &ts, BPF_ANY);

    //bpf_printk("sendto syscall called\n");
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit_sendto")
int tp_exit_sendto(struct trace_event_raw_sys_enter *ctx)
{
    if (cfg->pid_sender != 0 && bpf_get_current_pid_tgid() >> 32 != cfg->pid_sender)
        return 0;

    //bpf_printk("sendto syscall exited\n");
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter_recvfrom")
int tp_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{   
    if (cfg->pid_receiver != 0 && bpf_get_current_pid_tgid() >> 32 != cfg->pid_receiver)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *tsp, delta;
    
    if (last_recv_ts != 0)
    {

        __u64 diff = bpf_ktime_get_ns() - last_recv_ts;
        __u32 key = floor(log2l_(diff));
        if (key > MAX_SPLIT_HISTOGRAM)
            key = MAX_SPLIT_HISTOGRAM;
        __u64 *value = bpf_map_lookup_elem(&hist, &key);

        if (value)
            __sync_fetch_and_add((int*)value, 1);
        else{
            __u64 value = 1;
            if (bpf_map_update_elem(&hist, &key, &value, BPF_NOEXIST) != 0) {
                // Handle error (e.g., map is full)
                return -1;
            }
        }
        // TODO: Float operations not permitted in the eBPF program. Move jitter calulation to user space
        //jitter += (diff - jitter) / 16.0;
        //bpf_printk("recvfrom syscall called\n");
    }

    last_recv_ts = bpf_ktime_get_ns();
    tsp = bpf_map_lookup_elem(&start_time, &pid);
    if (tsp) {
        delta = bpf_ktime_get_ns() - *tsp;
        //bpf_printk("PID: %d, Time: %lld\n", pid, delta);
        bpf_map_delete_elem(&start_time, &pid);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit_recvfrom")
int tp_exit_recvfrom(struct trace_event_raw_sys_enter *ctx)
{ 
    if (cfg->pid_receiver!= 0 && bpf_get_current_pid_tgid() >> 32 != cfg->pid_receiver)
        return 0;

    //bpf_printk("recvfrom syscall exited\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
