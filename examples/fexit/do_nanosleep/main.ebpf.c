#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 在 map 的值里放一个自旋锁
struct lock_data {
    struct bpf_spin_lock lock;
};

// 定义一个只有 1 个元素的 ARRAY map，用于持有锁
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct lock_data);
} lock_map SEC(".maps");

// 声明BSD/GPL许可证
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 声明监控内核函数do_nanosleep的返回
SEC("fexit/do_nanosleep")
int BPF_PROG(fexit_sleep)
{
    // 强制制造一点执行时间
    bpf_printk("in fexit\n");

    // 模拟耗时（增加并发窗口）
    u32 key = 0;
    struct lock_data *v = bpf_map_lookup_elem(&lock_map, &key);
    if (v) {
        bpf_spin_lock(&v->lock);
        bpf_spin_unlock(&v->lock);
    }

    return 0;
}