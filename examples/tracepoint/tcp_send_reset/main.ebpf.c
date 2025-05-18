#include <linux/bpf.h>  // 要在bpf_helpers.h之前包含
#include <bpf/bpf_helpers.h>

// 声明BSD/GPL许可证
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// SEC宏定义eBPF程序的挂载点，这里挂载到进入write系统调用的跟踪点(tracepoint)
SEC("tp/tcp/tcp_send_reset")
int trace_tcp_send_reset(void* ctx) {
    // 在内核日志中打印信息
    bpf_printk("trace_tcp_send_reset() is here.\n");

    return 0;
}