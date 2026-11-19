FROM debian:trixie
RUN apt update && apt upgrade -y
RUN apt install -y build-essential libcap-dev bpftool libbpf-dev clang llvm libc6-dev-i386 libssl-dev pkgconf iproute2 ethtool
RUN apt install -y iputils-ping tcpdump procps netcat-openbsd ndisc6
RUN apt install -y openssh-server openssh-client
RUN apt install -y iperf3
RUN useradd -u 1000 -m -s /bin/bash ipxuser
COPY --exclude=tests . /home/ipxuser/ipx_wrap
RUN chown -R ipxuser:ipxuser /home/ipxuser/ipx_wrap
USER ipxuser
WORKDIR /home/ipxuser/ipx_wrap
RUN LLC=llc-19 CLANG=clang-19 BPFT=/usr/sbin/bpftool make
