#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>
#include "main.skel.h"

// libbpf日志回调函数
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    return vfprintf(stderr, format, args);  // 将日志输出到标准错误
}

int main(int argc, char** argv) {
    struct main_ebpf* skel;
    int err;

    // 设置libbpf的错误和调试信息回调函数
    libbpf_set_print(libbpf_print_fn);

    // 打开并解析eBPF应用程序
    skel = main_ebpf__open();
    if (!skel) {
        fprintf(stderr, "无法打开eBPF程序\n");
        return 1;
    }

    skel->bss->my_pid = getpid();  // 获取当前进程PID

    // 加载并验证eBPF程序
    err = main_ebpf__load(skel);
    if (err) {
        fprintf(stderr, "加载和验证eBPF程序失败\n");
        goto cleanup;  // 跳转到清理流程
    }

    // 挂载到tracepoint
    err = main_ebpf__attach(skel);
    if (err) {
        fprintf(stderr, "挂载eBPF程序失败\n");
        goto cleanup;
    }

    printf(
        "成功启动! 请运行 `sudo cat "
        "/sys/kernel/debug/tracing/trace_pipe` "
        "查看BPF程序的输出.\n");

    // 主循环 - 保持程序运行
    for (;;) {
        // 触发BPF程序执行
        fprintf(stderr, ".");  // 会调用write系统调用
        sleep(1);              // 每秒输出一个点
    }

cleanup:
    // 清理资源
    main_ebpf__destroy(skel);
    return -err;
}
