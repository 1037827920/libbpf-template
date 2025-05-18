#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 声明BSD/GPL许可证
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 声明监控内核函数do_unlinkat的入口
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat,
               int dfd,
               struct filename* name) {  // 自动获取内核参数
    pid_t pid;
    const char* filename;

    // 当前进程pid
    pid = bpf_get_current_pid_tgid() >> 32;
    // 通过bpf_core_read宏安全读取内核结构体中的文件名
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

// 声明监控内核函数do_unlinkat的退出
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret) {
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
