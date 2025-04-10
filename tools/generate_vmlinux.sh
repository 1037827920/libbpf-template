#!bin/bash

# 检查 bpftool 是否已安装
if ! command -v bpftool &>/dev/null; then
    echo "正在安装 bpftool..."
    
    # 检测包管理器并安装
    if command -v apt &>/dev/null; then
        sudo apt update && sudo apt install -y bpftool
    elif command -v yum &>/dev/null; then
        sudo yum install -y bpftool
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y bpftool
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm bpftool
    else
        echo "无法自动安装 bpftool, 请手动安装后重试"
        exit 1
    fi
fi

# 生成 vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../vmlinux.h
