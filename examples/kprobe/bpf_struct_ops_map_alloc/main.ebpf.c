#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 声明BSD/GPL许可证
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define BPF_OBJ_NAME_LEN 16

// 声明监控内核函数do_unlinkat的入口
SEC("kprobe/bpf_struct_ops_map_alloc")
int BPF_KPROBE(bpf_struct_ops_map_alloc, union bpf_attr *attr)
{
    __u32 map_type = 0, btf_vmlinux_value_type_id = 0;

    // 通过bpf_core_read宏安全读取内核结构体中的文件名
    bpf_core_read(&map_type, sizeof(map_type), &attr->map_type);
    bpf_core_read(&btf_vmlinux_value_type_id, sizeof(btf_vmlinux_value_type_id), &attr->btf_vmlinux_value_type_id);

    bpf_printk("ENTER map_type=%u btf_vmlinux_value_type_id=%u\n",
               map_type, btf_vmlinux_value_type_id);

    return 0;
}

// 声明监控内核函数do_unlinkat的退出
SEC("kretprobe/bpf_struct_ops_map_alloc")
int BPF_KRETPROBE(bpf_struct_ops_map_alloc_exit, struct bpf_map *ret)
{
    bpf_printk("EXIT ret=%d\n", (long)ret);
    return 0;
}
