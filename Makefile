LLC ?= llc-17
CLANG ?= clang-17
CC ?= gcc
BPFT ?= bpftool
PAHOLE ?= pahole

LIBBPF_PREFIX ?= /usr
VMLINUX_H_PREREQ = $(shell test -f /sys/kernel/btf/vmlinux && echo "/sys/kernel/btf/vmlinux" || echo "vmlinux.btf")

USER_TARGETS = ipx_wrap_if_config
MUX_TARGETS = ipx_wrap_ripd ipx_wrap_tx_client ipx_wrap_rx_client
MUXER_TARGETS = ipx_wrap_mux
TC_OBJ = ipx_wrap_kern.o

CFLAGS = -Wall -I $(LIBBPF_PREFIX)/include/
USER_LIBS = -lbpf
MUXER_LIBS = -lcap

all: $(MUX_TARGETS) $(USER_TARGETS) $(TC_OBJ) $(MUXER_TARGETS)

vmlinux.h: $(VMLINUX_H_PREREQ)
	$(BPFT) btf dump file $< format c > $@

vmlinux.btf:
	$(PAHOLE) --btf_encode_detached=$@

$(TC_OBJ): %.o: %.c vmlinux.h common.h
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

$(USER_TARGETS): %: %.c common.h
	$(CC) $(CFLAGS) -L $(LIBBPF_PREFIX)/lib64/ -o $@ $< $(USER_LIBS)

ipx_wrap_mux_proto.o: ipx_wrap_mux_proto.c ipx_wrap_mux_proto.h uthash.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(MUXER_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h uthash.h
	$(CC) $(CFLAGS) -o $@ $< ipx_wrap_mux_proto.o $(MUXER_LIBS)

$(MUX_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h
	$(CC) $(CFLAGS) -o $@ $< ipx_wrap_mux_proto.o

clean:
	rm -f *.o *.ll $(USER_TARGETS) $(MUX_TARGETS) $(MUXER_TARGETS) vmlinux.h vmlinux.btf

.PHONY: all clean
