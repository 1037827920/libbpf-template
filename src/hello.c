#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>
#include "hello.skel.h"

// libbpf日志回调函数
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    return vfprintf(stderr, format, args);  // 将日志输出到标准错误
}

int main(int argc, char** argv) {
    struct hello_ebpf* skel;
    int err;

    // 设置libbpf的错误和调试信息回调函数
    libbpf_set_print(libbpf_print_fn);

    // 打开并解析BPF应用程序
    skel = hello_ebpf__open();
    if (!skel) {
        fprintf(stderr, "无法打开BPF骨架\n");
        return 1;
    }

    // 设置只监控当前进程的write系统调用
    skel->bss->my_pid = getpid();  // 获取当前进程PID

    // 加载并验证BPF程序
    err = hello_ebpf__load(skel);
    if (err) {
        fprintf(stderr, "加载和验证BPF骨架失败\n");
        goto cleanup;  // 跳转到清理流程
    }

    // 附加tracepoint处理程序
    err = hello_ebpf__attach(skel);
    if (err) {
        fprintf(stderr, "附加BPF骨架失败\n");
        goto cleanup;
    }

    printf(
        "成功启动! 请运行 `sudo cat "
        "/sys/kernel/debug/tracing/trace_pipe` "
        "查看BPF程序的输出.\n");

    // 主循环 - 保持程序运行
    for (;;) {
        // 触发BPF程序执行
        fprintf(stderr, ".");
        sleep(1);  // 每秒输出一个点
    }

cleanup:
    // 清理资源
    hello_ebpf__destroy(skel);  // 销毁BPF骨架
    return -err;                // 返回错误码
}
