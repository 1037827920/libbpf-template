#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int monitor_write_enter(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("Hello ebpf from PID %d.\n", pid);

	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int monitor_write_exit(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("Goodbye ebpf from PID %d.\n", pid);

    return 0;
}