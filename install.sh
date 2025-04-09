#!/bin/sh

set -eu

usage()
{
	echo "Usage: install.sh <if> <if ipv6 addr>"
	exit 1
}

[ "${#}" -ne 2 ] && usage

IF="${1}"
ADDR="${2}"

IPX_WRAP_DIR="`dirname ${0}`"

ethtool -K "${IF}" tx off >/dev/null
ethtool -K "${IF}" rx off >/dev/null
ethtool -K "${IF}" generic-segmentation-offload off >/dev/null
ethtool -K "${IF}" scatter-gather off >/dev/null
ethtool -K "${IF}" tx-gso-list off >/dev/null
ethtool -K "${IF}" tx-ipxip4-segmentation off >/dev/null
ethtool -K "${IF}" tx-ipxip6-segmentation off >/dev/null
ethtool -K "${IF}" tx-udp_tnl-segmentation off >/dev/null
ethtool -K "${IF}" tx-udp_tnl-csum-segmentation off >/dev/null

tc qdisc add dev "${IF}" clsact
tc filter add dev "${IF}" ingress bpf object-file "${IPX_WRAP_DIR}/ipx_wrap_kern.o" section tc/ingress direct-action
tc filter add dev "${IF}" egress bpf object-file "${IPX_WRAP_DIR}/ipx_wrap_kern.o" section tc/egress direct-action

"${IPX_WRAP_DIR}/ipx_wrap_if_config" "${IF}" "${ADDR}"
