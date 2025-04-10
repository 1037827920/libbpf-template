OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
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

# 控制构建过程中的输出行为
ifeq ($(V),1)
	Q =
	msg =
else # 默认情况
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

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
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

# 目录创建
$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# 构建libbpf静态库
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# 构建bpftool工具
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# 构建ebpf程序
# 1. .ebpf.c -> .ebpf.o
$(OUTPUT)/%.ebpf.o: %.ebpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86		      \
		     $(INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.ebpf.o,%.tmp.ebpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.ebpf.o,%.tmp.ebpf.o,$@)

# 2. 生成骨架头文件，该文件包含bpf程序的所有元信息
# 使用bpftool自动创建了用户态与内核态之间的交互接口，封装了bpf对象加载、映射管理、事件处理等底层操作
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.ebpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# 3. 编译用户空间程序
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h
$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# 4. 最终链接
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# 出错时删除不完整目标
.DELETE_ON_ERROR:

# 保留中间文件
.SECONDARY:
