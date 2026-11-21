LLC ?= llc-19
CLANG ?= clang-19
CC ?= gcc
BPFT ?= bpftool
PAHOLE ?= pahole

LIBBPF_PREFIX ?= /usr
VMLINUX_H_PREREQ = $(shell test -f /sys/kernel/btf/vmlinux && echo "/sys/kernel/btf/vmlinux" || echo "vmlinux.btf")

USER_TARGETS = ipx_wrap_if_config
IFD_TARGETS = ipx_wrap_ifd
MUX_TARGETS = ipxcat ipxdiag spxinetd ipxping spxtcp ipxtap ipxsend ipxrecv spxclient spxserver
RCON_TARGETS = rconcl
SERVICE_TARGETS = ipx_wrap_ripd ipx_wrap_sapd ipx_wrap_pongd
MUXER_TARGETS = ipx_wrap_mux
BPF_OBJ = ipx_wrap_kern.o ipx_wrap_mux_kern.o ipx_wrap_mux_spx_kern.o

INTEGRATION_TEST_GROUPS = basic1 basic2

CFLAGS = -Wall -Wextra -I $(LIBBPF_PREFIX)/include/ -O2
BPF_CFLAGS = -D __BPF_TRACING__ -I $(LIBBPF_PREFIX)/include/ -Wall -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-address-of-packed-member -Wno-missing-declarations -Werror -O2
ifeq ($(NDEBUG),1)
CFLAGS += -DNDEBUG
BPF_CFLAGS += -DNDEBUG
else
CFLAGS += -fsanitize=address -fsanitize=leak -fsanitize=undefined -g
endif
USER_LIBS = -lbpf
MUXER_LIBS = -lcap -lbpf
MUX_LIBS = -lm
RCON_LIBS = -lcrypto -lmenuw $(shell pkg-config --libs ncursesw)
RCON_CFLAGS = $(shell pkg-config --cflags ncursesw)

all: $(MUX_TARGETS) $(RCON_TARGETS) $(USER_TARGETS) $(IFD_TARGETS) $(BPF_OBJ) $(MUXER_TARGETS) $(SERVICE_TARGETS)

vmlinux.h: $(VMLINUX_H_PREREQ)
	$(BPFT) btf dump file $< format c > $@~
	mv --force $@~ $@

vmlinux.btf:
	$(PAHOLE) --btf_encode_detached=$@

%.skel.h: %.o vmlinux.h common.h
	$(BPFT) gen skeleton $< > $@~
	mv --force $@~ $@

$(BPF_OBJ): %.o: %.c vmlinux.h common.h ipx_wrap_common_kern.h ipx_wrap_common_proto.h
	$(CLANG) -S \
	    -target bpf \
	    $(BPF_CFLAGS) \
	    -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(USER_TARGETS): %: %.c common.h
	$(CC) $(CFLAGS) -L $(LIBBPF_PREFIX)/lib64/ -o $@ $< $(USER_LIBS)

ipx_wrap_kern_nopin.o: ipx_wrap_kern.c vmlinux.h common.h ipx_wrap_common_kern.h
	$(CLANG) -S \
	    -target bpf \
	    $(BPF_CFLAGS) \
	    -D __IPX_WRAP_NOPIN__ \
	    -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(IFD_TARGETS): %: %.c common.h ipx_wrap_kern_nopin.skel.h
	$(CC) $(CFLAGS) -L $(LIBBPF_PREFIX)/lib64/ -o $@ $< $(USER_LIBS)

ipx_wrap_mux_proto.o: ipx_wrap_mux_proto.c ipx_wrap_mux_proto.h ipx_wrap_common_proto.h uthash.h
	$(CC) $(CFLAGS) -c -o $@ $<

ipx_wrap_service_lib.o: ipx_wrap_service_lib.c ipx_wrap_service_lib.h ipx_wrap_mux_proto.h ipx_wrap_common_proto.h uthash.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(MUXER_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h ipx_wrap_common_proto.h uthash.h ipx_wrap_mux_kern.skel.h ipx_wrap_mux_spx_kern.skel.h
	$(CC) $(CFLAGS) -o $@ $< ipx_wrap_mux_proto.o $(MUXER_LIBS)

$(MUX_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h ipx_wrap_common_proto.h ipx_wrap_helpers.o ipx_wrap_helpers.h
	$(CC) $(CFLAGS) -o $@ $< ipx_wrap_mux_proto.o ipx_wrap_helpers.o $(MUX_LIBS)

$(RCON_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h ipx_wrap_common_proto.h ipx_wrap_helpers.o ipx_wrap_helpers.h cp850.h
	$(CC) $(CFLAGS) $(RCON_CFLAGS) -o $@ $< ipx_wrap_mux_proto.o ipx_wrap_helpers.o $(RCON_LIBS)

$(SERVICE_TARGETS): %: %.c common.h ipx_wrap_mux_proto.o ipx_wrap_mux_proto.h ipx_wrap_common_proto.h ipx_wrap_service_lib.o ipx_wrap_service_lib.h
	$(CC) $(CFLAGS) -o $@ $< ipx_wrap_mux_proto.o ipx_wrap_service_lib.o

INTEGRATION_TEST_NETWORKS = $(foreach dir,$(INTEGRATION_TEST_GROUPS),tests/$(dir)/network.yaml)
INTEGRATION_TESTS_FILES = $(foreach dir,$(INTEGRATION_TEST_GROUPS),$(wildcard tests/$(dir)/*.test.yaml))
INTEGRATION_TESTS_COMPOSE = $(INTEGRATION_TESTS_FILES:.test.yaml=.compose.yaml)
INTEGRATION_TESTS = $(INTEGRATION_TESTS_FILES:.test.yaml=)

$(INTEGRATION_TEST_NETWORKS): %/network.yaml: %/topo.yaml tests/templates.yaml
	@cat tests/templates.yaml $< > $@

$(INTEGRATION_TESTS): %: %.compose.yaml %.bats tests/defaults.env
	@echo "Running test suite $@..."
	@docker compose --progress quiet \
		--env-file tests/defaults.env \
		--project-directory `dirname $<` \
		-f $< up --quiet-build --quiet-pull \
		--attach test_runner --exit-code-from test_runner; \
		RET=$$?; docker compose --progress quiet \
		--env-file tests/defaults.env \
		--project-directory `dirname $<` \
		-f $< down --volumes; exit $$RET

integration-tests: $(INTEGRATION_TESTS)

clean:
	rm -f *.o *.ll *.skel.h *.h~ $(USER_TARGETS) $(IFD_TARGETS) $(MUX_TARGETS) $(RCON_TARGETS) $(MUXER_TARGETS) $(SERVICE_TARGETS) vmlinux.h vmlinux.btf $(INTEGRATION_TESTS_COMPOSE) $(INTEGRATION_TEST_NETWORKS)

.PHONY: all integration-tests clean $(INTEGRATION_TESTS)

.INTERMEDIATE: $(INTEGRATION_TESTS_COMPOSE) $(INTEGRATION_TEST_NETWORKS)

.SECONDEXPANSION:
%.compose.yaml: %.test.yaml tests/templates.yaml $$(dir $$@)network.yaml
	@cat tests/templates.yaml $< > $@
