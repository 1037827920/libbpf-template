# 输出目录
OUTPUT := .output
# 编译器
CLANG := clang
# libbpf源码路径
LIBBPF_SRC := $(abspath ../libbpf/src)
# bpftool源码路径
BPFTOOL_SRC := $(abspath ../bpftool/src)
# 静态库路径
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
# libbpf输出目录
LIBBPF_OUTPUT := $(abspath $(OUTPUT)/libbpf)
# bpftool输出目录
BPFTOOL_OUTPUT := $(abspath $(OUTPUT)/bpftool)
# bpftool二进制文件
BPFTOOL := $(BPFTOOL_OUTPUT)/bootstrap/bpftool
# 内核头文件路径
VMLINUX := ../vmlinux.h
# 头文件包含路径
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(dir $(VMLINUX))
# 编译选项：-g 生成调试信息 -Wall 启用所有编译警告
CFLAGS := -g -Wall
# 链接选项：加上系统中环境变量要求的链接选项
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
# 程序名
APPS = hello

# 自定义的makefile宏，用于安全地设置变量值
# 只有当变量未被环境变量或命令行参数设置时，才赋予默认值
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	rm -rf $(OUTPUT) $(APPS)

# 目录创建
$(OUTPUT) $(LIBBPF_OUTPUT) $(BPFTOOL_OUTPUT):
	mkdir -p $@

# 构建libbpf静态库
# 使用wildcard匹配所有.c.h文件和Makefile文件，并通过｜确保LIBBPF_OUTPUT存在
# 1. $(MAKE) -C $(LIBBPF_SRC)：进入libbpf源码目录，执行make命令，构建libbpf静态库
# 2. BUILD_STATIC_ONLY=1：只构建静态库
# 3. OBJDIR=$(dir $@)/libbpf：指定libbpf静态库的输出目录，$(dir $@)表示目标文件的目录(.output/)
# 4. DESTDIR=$(dir $@)：指定libbpf静态库的安装目录，$(dir $@)表示目标文件的目录(.output/)
# 5. install：执行libbpf源码目录的Makefile中的install目标，将libbpf静态库安装到指定目录
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OUTPUT)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# 构建bpftool工具
# 1. 进入bpftool源码目录，执行make命令，构建bpftool工具
# 2. ARCH=：指定构建目标架构，这里为空，表示构建当前主机架构
# 3. CROSS_COMPILE=：指定交叉编译工具链前缀，这里为空，表示使用当前主机工具链
# 4. OUTPUT=$(BPFTOOL_OUTPUT)/：指定bpftool工具的输出目录
# 5. bootstrap：执行bpftool源码目录的Makefile中的bootstrap目标，构建bpftool工具
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# 构建ebpf程序
# 1. .ebpf.c -> .ebpf.o
# 第一条命令：编译ebpf程序
# 第二条命令：利用bpftool生成最终的bpf对象文件
# filter只过滤出.c文件进行编译
# patsubst将.ebpf.c替换为.tmp.ebpf.o，返回为$@，即目标文件
$(OUTPUT)/%.ebpf.o: %.ebpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86		      \
		     $(INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.ebpf.o,%.tmp.ebpf.o,$@)
	$(BPFTOOL) gen object $@ $(patsubst %.ebpf.o,%.tmp.ebpf.o,$@)

# 2. 生成骨架头文件，该文件包含bpf程序的所有元信息
# 使用bpftool自动创建了用户态与内核态之间的交互接口，封装了bpf对象加载、映射管理、事件处理等底层操作
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.ebpf.o | $(OUTPUT) $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

# 3. 编译用户空间程序
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# 4. 最终链接
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# 出错时删除不完整目标
.DELETE_ON_ERROR:

# 保留中间文件
.SECONDARY: