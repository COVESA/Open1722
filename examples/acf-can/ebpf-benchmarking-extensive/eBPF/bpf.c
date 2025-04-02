#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include <math.h>
#include "utils.h"

struct config
{
    __u32 pid_talker;
    __u32 pid_listener;
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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_can_avtp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_recv_ts SEC(".maps");

struct event
{
    __u64 timestamp;
    __u32 pid;
    __u64 uid; // Unique identifier for the event
    char function[32];
    char devname[32];
};

struct event_recv
{
    __u64 timestamp;
    char devname[32];
};

__u64 last_read_start_from_can_ts = 0;
__u64 last_read_end_from_can_ts = 0;
__u64 last_send_start_talker_ts = 0;
__u64 last_send_end_talker_ts = 0;
__u64 uid = 1;
__u64 uid2 = 1;
bool is_ecu1_forwarding = false;
bool is_ecu2_forwarding = false;
bool ecu1_acf_can_tx_called = false;
bool ecu2_acf_can_tx_called = false;


/*/
static __always_inline void submit_event(__u32 pid, const char *msg)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events_can_avtp, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = pid;
    __builtin_memcpy(e->function, msg, sizeof(e->function) - 1);
    e->function[sizeof(e->function) - 1] = '\0';

    bpf_ringbuf_submit(e, 0);
}
*/

#define SUBMIT_EVENT(func_name, _pid, _uid, ts, devname)                      \
    do                                                                  \
    {                                                                   \
        struct event *e = bpf_ringbuf_reserve(&events_can_avtp,         \
                                              sizeof(struct event), 0); \
        if (!e)                                                         \
        {                                                               \
            bpf_printk("Failed to reserve ringbuf space\n");            \
            return 0;                                                   \
        }                                                               \
        memset(e, 0, sizeof(*e));                                       \
        e->timestamp = (ts);                                            \
        e->pid = _pid;                                                  \
        e->uid = _uid;                                                   \
        __builtin_memcpy(e->function, (func_name),                      \
                         sizeof(e->function) - 1);                      \
        e->function[sizeof(e->function) - 1] = '\0';                    \
        memset(e->devname, 0, sizeof(e->devname));                      \
        bpf_probe_read_str(e->devname, sizeof(e->devname), devname);    \
        bpf_ringbuf_submit(e, 0);                                       \
    } while (0)

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

SEC("tracepoint/raw_syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_talker != 0 && pid != cfg->pid_talker)
        return 0;

    uid++;
    last_read_start_from_can_ts = bpf_ktime_get_ns();
    char devname[32];

    /*struct event *e;
    e = bpf_ringbuf_reserve(&events_can_avtp, sizeof(struct event), 0);
    if (!e)
    {
        bpf_printk("Failed to reserve ringbuf space\n");
        return 0;
    }
    memset(e, 0, sizeof(*e));
    e->timestamp = last_read_start_from_can_ts;
    e->pid = pid;
    e->uid = uid;
    __builtin_memcpy(e->function, "sys_enter_read", sizeof(e->function) - 1);
    e->function[sizeof(e->function) - 1] = '\0';
    bpf_ringbuf_submit(e, 0);*/
    SUBMIT_EVENT("sys_enter_read", pid, uid, last_read_start_from_can_ts, devname);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_talker != 0 && pid != cfg->pid_talker)
        return 0;

    last_read_end_from_can_ts = bpf_ktime_get_ns();

    struct event *e;
    e = bpf_ringbuf_reserve(&events_can_avtp, sizeof(*e), 0);
    if (!e)
        return 0;
    memset(e, 0, sizeof(*e));
    e->timestamp = last_read_end_from_can_ts;
    e->pid = pid;
    e->uid = uid;
    __builtin_memcpy(e->function, "sys_exit_read", sizeof(e->function) - 1);
    e->function[sizeof(e->function) - 1] = '\0';
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter_sendto")
int tp_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_talker != 0 && pid != cfg->pid_talker)
        return 0;

    last_send_start_talker_ts = bpf_ktime_get_ns();

    struct event *e;
    e = bpf_ringbuf_reserve(&events_can_avtp, sizeof(*e), 0);
    if (!e)
        return 0;
    memset(e, 0, sizeof(*e));
    e->timestamp = last_send_start_talker_ts;
    e->pid = pid;
    e->uid = uid;
    __builtin_memcpy(e->function, "sys_enter_sendto", sizeof(e->function) - 1);
    e->function[sizeof(e->function) - 1] = '\0';
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit_sendto")
int tp_exit_sendto(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_talker != 0 && pid != cfg->pid_talker)
        return 0;

    last_send_end_talker_ts = bpf_ktime_get_ns();

    struct event *e;
    e = bpf_ringbuf_reserve(&events_can_avtp, sizeof(*e), 0);
    if (!e)
        return 0;
    memset(e, 0, sizeof(*e));
    e->timestamp = last_send_end_talker_ts;
    e->pid = pid;
    e->uid = uid;
    __builtin_memcpy(e->function, "sys_exit_sendto", sizeof(e->function) - 1);
    e->function[sizeof(e->function) - 1] = '\0';
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter_recvfrom")
int tp_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_listener != 0 && pid != cfg->pid_listener)
        return 0;

    bpf_printk("sys_enter_recvfrom called\n");

    __u64 rx_time = bpf_ktime_get_ns();

    __u64 *e;
    e = bpf_ringbuf_reserve(&events_recv_ts, sizeof(struct event), 0);
    if (!e)
    {
        bpf_printk("Failed to reserve ringbuf space\n");
        return 0;
    }
    memset(e, 0, sizeof(*e));
    *e = rx_time;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/**
 * The kprobe to monitor the kernel version of acf-can function
 */

SEC("kprobe/acfcan_tx")
int kprobe_acfcan_tx(struct pt_regs *ctx)
{
    // printStatsSK((struct sk_buff *)PT_REGS_PARM1(ctx));

    char devname[32];
    getDevName(devname, (struct sk_buff *)PT_REGS_PARM1(ctx));
    last_read_start_from_can_ts = bpf_ktime_get_ns();

    if (strcmp(devname, "ecu1") == 0 && !(ecu1_acf_can_tx_called && is_ecu1_forwarding))
    {
        uid++;
        strncpy(devname, "ecu1", sizeof(devname));
        SUBMIT_EVENT("acfcan_tx", 0, uid, last_read_start_from_can_ts, devname);
        ecu1_acf_can_tx_called = true;
        bpf_printk("ecu1 acfcan_tx called\n");

    }
    else if (strcmp(devname, "ecu2") == 0)
    {
        uid2++;
        strncpy(devname, "ecu2", sizeof(devname));
        SUBMIT_EVENT("acfcan_tx", 0, uid2, last_read_start_from_can_ts, devname);
        ecu2_acf_can_tx_called = true;
    }
    return 0;
}

SEC("kretprobe/acfcan_tx")
int kretprobe_acfcan_tx(struct pt_regs *ctx)
{
    bpf_printk("acfcan_tx exited\n");

    ecu1_acf_can_tx_called = false;
    ecu2_acf_can_tx_called = false;
    return 0;
}

SEC("kprobe/forward_can_frame")
int kprobe_entry_forward_can_frame(struct pt_regs *ctx)
{
    // printStatsSK((struct sk_buff *)PT_REGS_PARM2(ctx));
    char devname[32];

    getDevName(devname, (struct sk_buff *)PT_REGS_PARM2(ctx));
    // bpf_printk("devname (entry_tx_side): %s", devname);
    if (strcmp(devname, "ecu1") == 0)
    {
        last_send_start_talker_ts = bpf_ktime_get_ns();
        // bpf_printk("ecu1 start time: %llu", last_send_start_talker_ts);
        is_ecu1_forwarding = true;
        SUBMIT_EVENT("enter_forward_can_frame", 0, uid, last_send_start_talker_ts, devname);
        bpf_printk("ecu1 enter_forward_can_frame called\n");
    }
    else if (strcmp(devname, "ecu2") == 0)
    {
        last_send_start_talker_ts = bpf_ktime_get_ns();
        // bpf_printk("ecu2 start time: %llu", last_send_start_talker_ts);
        is_ecu2_forwarding = true;
        SUBMIT_EVENT("enter_forward_can_frame", 0, uid2, last_send_start_talker_ts, devname);
    }
    else
    {
        is_ecu1_forwarding = false;
        is_ecu2_forwarding = false;
    }
    return 0;
}

SEC("kretprobe/forward_can_frame")
int kretprobe_exit_forward_can_frame(struct pt_regs *ctx)
{
    // printStatsSK((struct sk_buff *)PT_REGS_PARM2(ctx));
    char devname[32];
    getDevName(devname, (struct sk_buff *)PT_REGS_PARM2(ctx));
    last_send_end_talker_ts = bpf_ktime_get_ns();
    // bpf_printk("devname (exit_tx_side): %s", devname);
    if(is_ecu1_forwarding){
        strncpy(devname, "ecu1", sizeof(devname));
        SUBMIT_EVENT("exit_forward_can_frame", 0, uid, last_send_end_talker_ts, devname);
        is_ecu1_forwarding = false;
        bpf_printk("ecu1 enter_forward_can_frame exited\n");

    }
    else if(is_ecu2_forwarding){
        strncpy(devname, "ecu2", sizeof(devname));
        SUBMIT_EVENT("exit_forward_can_frame", 0, uid2, last_send_end_talker_ts, devname);
        is_ecu2_forwarding = false;

    }
    else if (is_ecu1_forwarding && is_ecu2_forwarding){
        //TODO: HANDLE THIS CASE
        bpf_printk("ecu1 and ecu2 are forwarding at the same time: TRICKY CASE");
        return 0;
    }

    // bpf_printk("ecu1 end time : %llu", last_send_end_talker_ts);
    
    return 0;
}

SEC("kprobe/ieee1722_packet_handdler")
int kprobe_ieee1722_packet_handdler(struct pt_regs *ctx)
{
    // printStatsSK((struct sk_buff *)PT_REGS_PARM1(ctx));
    char devname[32];
    getDevName(devname, (struct sk_buff *)PT_REGS_PARM1(ctx));

    __u64 rx_time = bpf_ktime_get_ns();
    //bpf_printk("devname (rx_side): %s", devname);

    struct event_recv *e;
    e = bpf_ringbuf_reserve(&events_recv_ts, sizeof(struct event), 0);
    if (!e)
    {
        bpf_printk("Failed to reserve ringbuf space\n");
        return 0;
    }
    memset(e, 0, sizeof(*e));
    e->timestamp = rx_time;
    memset(e->devname, 0, sizeof(e->devname));
    bpf_probe_read_str(e->devname, sizeof(e->devname), devname);
    //__builtin_memcpy(e->devname, devname,sizeof(e->devname) - 1);
    // e->devname[sizeof(e->devname) - 1] = '\0';
    bpf_ringbuf_submit(e, 0);
    //bpf_printk("devname (rx_side): %s", devname);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
