#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* 
 * 最简单的 sleepable BPF 程序
 * 只要有 .s 后缀，内核就会检查是否支持 sleepable
 */
SEC("fentry.s/do_nanosleep")
int BPF_PROG(test_sleepable, struct hrtimer_sleeper *t, enum hrtimer_mode mode)
{
    struct task_struct *task;
    char comm[16] = {};
    void *user_addr;
    int ret;

    /* 获取当前任务 */
    task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    /* 读取用户空间地址（进程参数起始地址） */
    user_addr = (void *)BPF_CORE_READ(task, mm, arg_start);
    if (!user_addr)
        return 0;

    /* 
     * 关键：bpf_copy_from_user 是 sleepable helper
     * 如果内核不支持 sleepable，加载阶段就会失败
     */
    ret = bpf_copy_from_user(comm, sizeof(comm) - 1, user_addr);
    if (ret == 0) {
        bpf_printk("sleepable test: read from user success: %s\n", comm);
    }

    return 0;
}