#!/bin/sh

set -eu

cleanup_subprocesses()
{
	trap - EXIT
	pkill -P $$ || true
}

usage()
{
	echo "Usage: start_interfaces.sh <prefix>"
	exit 1
}

[ "${#}" -ne 1 ] && usage

IPX_PREFIX="${1}"

SCRIPTS_DIR="`dirname ${0}`"
IPX_WRAP_DIR="`dirname ${SCRIPTS_DIR}`"

trap 'cleanup_subprocesses' EXIT INT QUIT TERM

ip -6 -o addr | grep "inet6 ${IPX_PREFIX}:" | while read IFLINE; do
	IFACE=`echo "${IFLINE}" | cut -d ' ' -f 2`
	IPV6_ADDR=`echo "${IFLINE}" | awk '{print $4}' | cut -d '/' -f 1`

	ethtool -K "${IFACE}" rx off tx off generic-segmentation-offload off scatter-gather off tx-gso-list off tx-ipxip4-segmentation off tx-ipxip6-segmentation off tx-udp_tnl-segmentation off tx-udp_tnl-csum-segmentation off tcp-segmentation-offload off generic-receive-offload off tx-vlan-offload off tx-gre-segmentation off tx-gre-csum-segmentation off tx-gso-partial off tx-tunnel-remcsum-segmentation off tx-sctp-segmentation off tx-esp-segmentation off tx-vlan-stag-hw-insert off rx-vlan-offload off rx-vlan-stag-hw-parse off >/dev/null
	"${IPX_WRAP_DIR}/ipx_wrap_ifd" "${IFACE}" "${IPV6_ADDR}" &
done

sleep infinity &
wait "$!"
