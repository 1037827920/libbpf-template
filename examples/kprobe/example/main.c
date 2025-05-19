#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "main.skel.h"

// libbpf日志回调函数
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char** argv) {
    struct main_ebpf* skel;
    int err;

    // 设置libbpf的错误和调试信息回调函数
    libbpf_set_print(libbpf_print_fn);

    // 打开并加载验证eBPF应用程序
    skel = main_ebpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "打开和加载eBPF程序失败\n");
        return 1;
    }

    // 挂载到main
    err = main_ebpf__attach(skel);
    if (err) {
        fprintf(stderr, "附加eBPF程序失败\n");
        goto cleanup;
    }

    printf(
        "成功启动! 请运行 `sudo cat "
        "/sys/kernel/debug/tracing/trace_pipe` "
        "查看BPF程序的输出.\n");

    // 主循环 - 保持程序运行
    for (;;) {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    main_ebpf__destroy(skel);
    return -err;
}
