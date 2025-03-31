#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include <math.h>
#include "utils.h"

#define MAX_SPLIT_HISTOGRAM 34

struct config
{
    __u32 pid_sender;
    __u32 pid_receiver;
    __u32 pid_can_gen;
    __be32 src_ip;
    __be32 dest_ip;
    __u32 src_port;
    __u32 dest_port;
    bool is_kernel_space;
} __attribute__((packed));
// HINT: Dont declare config as a static variable
volatile const struct config CONFIG;
#define cfg (&CONFIG)

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} start_time SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SPLIT_HISTOGRAM);
    __type(key, u32);
    __type(value, u64);
} hist_send SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SPLIT_HISTOGRAM);
    __type(key, u32);
    __type(value, u64);
} hist_read SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SPLIT_HISTOGRAM);
    __type(key, u32);
    __type(value, u64);
} hist_etoe SEC(".maps");

__u64 last_sendto_ts = 0;
__u64 last_read_ts = 0;
__u64 last_acf_can_tx_ts = 0;
__u64 last_forward_can_frame_ts = 0;

// float jitter=0;

static __always_inline int printStatsSK(struct sk_buff *skb)
{
    struct sk_buff skb_local = {};
    char devname[32];
    char h_src[6];
    char h_dest[6];

    bpf_probe_read(&skb_local, sizeof(skb_local), skb);

    struct ethhdr *eth = (struct ethhdr *)(skb_local.head + skb_local.mac_header);
    // struct iphdr *iph = (struct iphdr *)(skb_local.head + skb_local.network_header);
    // struct udphdr *udp = (struct udphdr *)(skb_local.head + skb_local.transport_header);

    bpf_probe_read_kernel_str(devname, sizeof(devname), skb_local.dev->name);
    bpf_printk("devname: %s", devname);

    // bpf_printk("h_dest: %p", eth->dest);
    // bpf_printk("h_source: %p", eth->src);
    // bpf_printk(" %pI4 -> %pI4 ", &iph->saddr, &iph->daddr);
    return 0;
}

static __always_inline int getDevName(char *devname, struct sk_buff *skb)
{
    struct sk_buff skb_local = {};
    bpf_probe_read(&skb_local, sizeof(skb_local), skb);
    bpf_probe_read_kernel_str(devname, sizeof(devname), skb_local.dev->name);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter_sendto")
int tp_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_sender != 0 && pid != cfg->pid_sender)
        return 0;
    
    bpf_printk("sys_enter_sendmsg called\n");

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_time, &pid, &ts, BPF_ANY);

    __u64 ts_diff_read_send = ts - last_read_ts;
    last_sendto_ts = ts;

    if (last_read_ts != 0)
    {
        __u32 key = floor(log2l_(ts_diff_read_send));
        if (key > MAX_SPLIT_HISTOGRAM)
            key = MAX_SPLIT_HISTOGRAM;
        __u64 *value = bpf_map_lookup_elem(&hist_read, &key);
        // bpf_printk("tp_enter_sendto called %llu - diff %llu \n", ts, ts_diff_read_send/1000);
        if (value)
            __sync_fetch_and_add((int *)value, 1);
        else
        {
            __u64 value = 1;
            if (bpf_map_update_elem(&hist_read, &key, &value, BPF_NOEXIST) != 0)
            {
                // Handle error (e.g., map is full)
                return -1;
            }
        }
    }
    return 0;
}


SEC("tracepoint/raw_syscalls/sys_enter_recvfrom")
int tp_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_receiver != 0 && pid != cfg->pid_receiver)
        return 0;

    u64 *tsp, delta;
    if (last_sendto_ts != 0)
    {
        __u64 diff = bpf_ktime_get_ns() - last_sendto_ts;
        __u32 key = floor(log2l_(diff));
        if (key > MAX_SPLIT_HISTOGRAM)
            key = MAX_SPLIT_HISTOGRAM;
        __u64 *value = bpf_map_lookup_elem(&hist_etoe, &key);
         bpf_printk("sys_enter_recvfrom called %llu - diff %llu \n", bpf_ktime_get_ns(), diff/1000);

        if (value)
            __sync_fetch_and_add((int *)value, 1);
        else
        {
            __u64 value = 1;
            if (bpf_map_update_elem(&hist_etoe, &key, &value, BPF_NOEXIST) != 0)
            {
                // Handle error (e.g., map is full)
                return -1;
            }
        }
    }
    return 0;
}





SEC("tracepoint/raw_syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_sender != 0 && pid != cfg->pid_sender)
        return 0;

    /*__u64 ts = bpf_ktime_get_ns();
    if (last_read_ts != 0)
    {
        __u64 diff = bpf_ktime_get_ns() - last_read_ts;
        __u32 key = floor(log2l_(diff));
        if (key > MAX_SPLIT_HISTOGRAM)
            key = MAX_SPLIT_HISTOGRAM;
        __u64 *value = bpf_map_lookup_elem(&hist_read, &key);
        // bpf_printk("read syscall exited %llu -- diff %llu\n", ts , diff/1000);
        if (value)
            __sync_fetch_and_add((int *)value, 1);
        else
        {
            __u64 value = 1;
            if (bpf_map_update_elem(&hist_read, &key, &value, BPF_NOEXIST) != 0)
            {
                // Handle error (e.g., map is full)
                return -1;
            }
        }
    }*/
    last_read_ts = bpf_ktime_get_ns();
    return 0;
}

/**
 * The kprobe to monitor the kernel version of acf-can function
 */

SEC("kprobe/acfcan_tx")
int kprobe_acfcan_tx(struct pt_regs *ctx)
{
    printStatsSK((struct sk_buff *)PT_REGS_PARM1(ctx));
    char devname[32];
    getDevName(devname, (struct sk_buff *)PT_REGS_PARM1(ctx));
    if (strcmp(devname, "ecu1") == 0)
    {
        last_acf_can_tx_ts = bpf_ktime_get_ns();
        bpf_printk("ecu1");
    }
    return 0;
}

SEC("kprobe/forward_can_frame")
int kprobe_forward_can_frame(struct pt_regs *ctx)
{
    printStatsSK((struct sk_buff *)PT_REGS_PARM2(ctx));
    char devname[32];
    getDevName(devname, (struct sk_buff *)PT_REGS_PARM2(ctx));
    if (strcmp(devname, "ecu1") == 0)
    {
        bpf_printk("ecu1");
        if (last_acf_can_tx_ts != 0)
        {
            last_forward_can_frame_ts = bpf_ktime_get_ns();
            __u64 diff = last_forward_can_frame_ts - last_acf_can_tx_ts;
            __u32 key = floor(log2l_(diff));
            if (key > MAX_SPLIT_HISTOGRAM)
                key = MAX_SPLIT_HISTOGRAM;
            __u64 *value = bpf_map_lookup_elem(&hist_read, &key);
            bpf_printk("forward_can_frame %llu -- diff %llu\n", last_forward_can_frame_ts, diff / 1000);
            if (value)
                __sync_fetch_and_add((int *)value, 1);
            else
            {
                __u64 value = 1;
                if (bpf_map_update_elem(&hist_read, &key, &value, BPF_NOEXIST) != 0)
                {
                    // Handle error (e.g., map is full)
                    return -1;
                }
            }
        }
    }
    return 0;
}

SEC("kprobe/ieee1722_packet_handdler")
int kprobe_ieee1722_packet_handdler(struct pt_regs *ctx)
{
    printStatsSK((struct sk_buff *)PT_REGS_PARM1(ctx));
    if (last_forward_can_frame_ts != 0)
    {
        __u64 e2e = bpf_ktime_get_ns() - last_forward_can_frame_ts;
        __u32 key = floor(log2l_(e2e));
        if (key > MAX_SPLIT_HISTOGRAM)
            key = MAX_SPLIT_HISTOGRAM;

        __u64 *value = bpf_map_lookup_elem(&hist_etoe, &key);
        bpf_printk("ieee1722_packet_handdler %llu -- diff %llu\n", bpf_ktime_get_ns(), e2e / 1000);
        if (value)
            __sync_fetch_and_add((int *)value, 1);
        else
        {
            __u64 value = 1;
            if (bpf_map_update_elem(&hist_etoe, &key, &value, BPF_NOEXIST) != 0)
            {
                // Handle error (e.g., map is full)
                return -1;
            }
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
