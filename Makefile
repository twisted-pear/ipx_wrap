LLC ?= llc-17
CLANG ?= clang-17
CC ?= gcc
BPFT ?= bpftool
PAHOLE ?= pahole

LIBBPF_PREFIX ?= /usr
VMLINUX_H_PREREQ = $(shell test -f /sys/kernel/btf/vmlinux && echo "/sys/kernel/btf/vmlinux" || echo "vmlinux.btf")

USER_TARGETS = ipx_wrap_set_prefix
TC_OBJ = ipx_wrap_kern.o

LIBS = -lbpf

all: $(USER_TARGETS) $(TC_OBJ)

vmlinux.h: $(VMLINUX_H_PREREQ)
	$(BPFT) btf dump file $< format c > $@

vmlinux.btf:
	$(PAHOLE) --btf_encode_detached=$@

$(TC_OBJ): %.o: %.c vmlinux.h
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -D __KERNEL_VERSION_MAJOR__=$(KERNEL_VERSION_MAJOR) \
	    -D __KERNEL_VERSION_MINOR__=$(KERNEL_VERSION_MINOR) \
	    -I $(LIBBPF_PREFIX)/include/ \
	    -Wall \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-address-of-packed-member \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(USER_TARGETS): %: %.c
	$(CC) -Wall -I $(LIBBPF_PREFIX)/include/ -L $(LIBBPF_PREFIX)/lib64/ -o $@ $< $(LIBS)

clean:
	rm -f *.o *.ll $(USER_TARGETS) vmlinux.h vmlinux.btf

.PHONY: all clean
