#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 声明BSD/GPL许可证
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* key: pid.  value: start time */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 102400);
    __type(key, u32);
    __type(value, u64);
} starts SEC(".maps");

// 添加到kprobe类型ebpf程序入口，即开始编写ebpf程序前
static void entry(void) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 nsec;

    nsec = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
}

// 添加到kprobe类型ebpf程序出口，即handle_exit()返回前
static void exit(void) {
    u64 *start;
    u64 nsec = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 delta;

    start = bpf_map_lookup_elem(&starts, &pid);
    if (!start)
        return;

    delta = nsec - *start;
    delta /= 1000;
    bpf_printk("delta: %llu\n", delta);
}

// 声明监控内核函数tcp_v4_send_reset的入口
SEC("kprobe/tcp_v4_send_reset")
int BPF_KPROBE(tcp_v4_send_reset, int dfd,
               struct filename *name) { // 自动获取内核参数
    entry();
    // 在内核日志中打印信息
    bpf_printk("tcp_v4_send_reset() is here.\n");
}

// 声明监控内核函数tcp_v4_send_reset的退出
SEC("kretprobe/tcp_v4_send_reset")
int BPF_KRETPROBE(tcp_v4_send_reset_exit, long ret) {
    exit();
    return 0;
}
