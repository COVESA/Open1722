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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 ); 
} events_can_avtp SEC(".maps");

struct event
{
    __u64 timestamp;
    __u32 pid;
    __u64 uid; // Unique identifier for the event
    char function[32];
};

__u64 last_read_start_from_can_ts = 0;
__u64 last_read_end_from_can_ts = 0;
__u64 last_send_start_talker_ts = 0;
__u64 last_send_end_talker_ts = 0;
__u64 uid = 1;

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

SEC("tracepoint/raw_syscalls/sys_enter_read")
int tp_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_sender != 0 && pid != cfg->pid_sender)
        return 0;
    bpf_printk("sys_enter_read called\n");

    uid++;
    last_read_start_from_can_ts = bpf_ktime_get_ns();

    struct event *e;
    e = bpf_ringbuf_reserve(&events_can_avtp, sizeof(struct event), 0);
    if (!e) {
        bpf_printk("Failed to reserve ringbuf space\n");
        return 0;
    }
    memset(e, 0, sizeof(*e));
    e->timestamp = last_read_start_from_can_ts;
    e->pid = pid;
    e->uid = uid;
    __builtin_memcpy(e->function, "sys_enter_read", sizeof(e->function) - 1);
    e->function[sizeof(e->function) - 1] = '\0';
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit_read")
int tp_exit_read(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (cfg->pid_sender != 0 && pid != cfg->pid_sender)
        return 0;
    
    bpf_printk("sys_exit_read called\n");

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
    if (cfg->pid_sender != 0 && pid != cfg->pid_sender)
        return 0;

    bpf_printk("sys_enter_sendto called\n");
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
    if (cfg->pid_sender != 0 && pid != cfg->pid_sender)
        return 0;

    bpf_printk("sys_exit_sendto called\n");
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

char LICENSE[] SEC("license") = "GPL";
