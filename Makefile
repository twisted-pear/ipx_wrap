LLC ?= llc-17
CLANG ?= clang-17
CC ?= gcc
BPFT ?= bpftool
PAHOLE ?= pahole

LIBBPF_PREFIX ?= /usr
VMLINUX_H_PREREQ = $(shell test -f /sys/kernel/btf/vmlinux && echo "/sys/kernel/btf/vmlinux" || echo "vmlinux.btf")

USER_TARGETS = ipx_wrap_if_config
IFD_TARGETS = ipx_wrap_ifd
MUX_TARGETS = ipxcat
SERVICE_TARGETS = ipx_wrap_ripd ipx_wrap_sapd
MUXER_TARGETS = ipx_wrap_mux
BPF_OBJ = ipx_wrap_kern.o ipx_wrap_mux_kern.o

CFLAGS = -Wall -I $(LIBBPF_PREFIX)/include/
USER_LIBS = -lbpf
MUXER_LIBS = -lcap -lbpf

all: $(MUX_TARGETS) $(USER_TARGETS) $(IFD_TARGETS) $(BPF_OBJ) $(MUXER_TARGETS) $(SERVICE_TARGETS)

vmlinux.h: $(VMLINUX_H_PREREQ)
	$(BPFT) btf dump file $< format c > $@

vmlinux.btf:
	$(PAHOLE) --btf_encode_detached=$@

%.skel.h: %.o vmlinux.h common.h
	$(BPFT) gen skeleton $< > $@

$(BPF_OBJ): %.o: %.c vmlinux.h common.h ipx_wrap_common_kern.h ipx_wrap_common_proto.h
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
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

ipx_wrap_kern_nopin.o: ipx_wrap_kern.c vmlinux.h common.h ipx_wrap_common_kern.h
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -D __IPX_WRAP_NOPIN__ \
	    -I $(LIBBPF_PREFIX)/include/ \
	    -Wall \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-address-of-packed-member \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(IFD_TARGETS): %: %.c common.h ipx_wrap_kern_nopin.skel.h
	$(CC) $(CFLAGS) -L $(LIBBPF_PREFIX)/lib64/ -o $@ $< $(USER_LIBS)

ipx_wrap_mux_proto.o: ipx_wrap_mux_proto.c ipx_wrap_mux_proto.h ipx_wrap_common_proto.h uthash.h
	$(CC) $(CFLAGS) -c -o $@ $<

ipx_wrap_service_lib.o: ipx_wrap_service_lib.c ipx_wrap_service_lib.h ipx_wrap_mux_proto.h ipx_wrap_common_proto.h uthash.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(MUXER_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h ipx_wrap_common_proto.h uthash.h ipx_wrap_mux_kern.skel.h
	$(CC) $(CFLAGS) -o $@ $< ipx_wrap_mux_proto.o $(MUXER_LIBS)

$(MUX_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h ipx_wrap_common_proto.h
	$(CC) $(CFLAGS) -o $@ $< ipx_wrap_mux_proto.o

$(SERVICE_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h ipx_wrap_common_proto.h ipx_wrap_service_lib.o ipx_wrap_service_lib.h
	$(CC) $(CFLAGS) -o $@ $< ipx_wrap_mux_proto.o ipx_wrap_service_lib.o

clean:
	rm -f *.o *.ll *.skel.h $(USER_TARGETS) $(IFD_TARGETS) $(MUX_TARGETS) $(MUXER_TARGETS) $(SERVICE_TARGETS) vmlinux.h vmlinux.btf

.PHONY: all clean
