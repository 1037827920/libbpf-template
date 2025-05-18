#include <linux/bpf.h>  // 要在bpf_helpers.h之前包含
#include <bpf/bpf_helpers.h>

// 声明BSD/GPL许可证
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 存储当前进程PID的全局变量
// 用户程序会在加载ebpf程序前修改这个值
int my_pid = 0;

// SEC宏定义eBPF程序的挂载点，这里挂载到进入write系统调用的跟踪点(tracepoint)
SEC("tp/syscalls/sys_enter_write")
int monitor_write_enter(void* ctx) {
    // 获取当前触发事件的进程ID
    // bpf_get_current_pid_tgid()返回64位值，高32位是PID，低32位是TGID
    int pid = bpf_get_current_pid_tgid() >> 32;

    // 只处理我们关注的进程ID
    if (pid != my_pid)
        return 0;

    // 在内核日志中打印信息
    bpf_printk("Hello ebpf from PID %d.\n", pid);

    return 0;
}

SEC("tp/syscalls/sys_exit_write")
int monitor_write_exit(void* ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid)
        return 0;

    bpf_printk("Goodbye ebpf from PID %d.\n", pid);

    return 0;
}