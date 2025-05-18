# libbpf-template
一个使用libbpf作为工具链开发ebpf程序的模板

# 使用指南

**1. clone仓库：**

```bash
git clone --recurse-submodules https://github.com/1037827920/libbpf-template.git
```

**2. 生成`vmlinux.h`：**

```bash
cd tools
bash generate_vmlinux.sh
```

**3. 编写ebpf程序以及用户空间程序：**

- ebpf程序：xxx.bpf.c，即在内核空间中运行的逻辑代码
- 用户空间程序：用来加载、附加并卸载ebpf程序的程序

**4. 编译：**

```bash
cd src
make
```

**5. 运行：**

```bash
./program
```

**6. 验证：**

```bash
cat /sys/kernel/debug/tracing/trace_pipe
```