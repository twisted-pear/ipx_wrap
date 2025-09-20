#!/bin/sh

set -eu

usage()
{
	echo "Usage: setup_for_prefix.sh <32-bit hex prefix> <sapd cfg>"
	exit 1
}

[ "${#}" -ne 2 ] && usage
[ ! -f "${2}" ] && usage

IPV6_PREFIX=`echo "${1}" | sed 's/\([0-9a-fA-F]\{4\}\)\([0-9a-fA-F]\{4\}\)/\1:\2/'`
IPX_PREFIX="${1}"

[ "${IPV6_PREFIX}" = "${IPX_PREFIX}" ] && usage

SAPD_CFG="${2}"

IPX_WRAP_DIR="`dirname ${0}`"

"${IPX_WRAP_DIR}/ipx_wrap_mux" "0x${IPX_PREFIX}" &
sleep 2

ip -6 -o addr | grep "inet6 ${IPV6_PREFIX}:" | while read IFLINE; do
	IFACE=`echo "${IFLINE}" | cut -d ' ' -f 2`
	IPV6_ADDR=`echo "${IFLINE}" | awk '{print $4}' | cut -d '/' -f 1`

	"${IPX_WRAP_DIR}/ipx_wrap_ifd" "${IFACE}" "${IPV6_ADDR}" &
done

"${IPX_WRAP_DIR}/ipx_wrap_ripd" "0x${IPX_PREFIX}" &
"${IPX_WRAP_DIR}/ipx_wrap_pongd" "0x${IPX_PREFIX}" &
"${IPX_WRAP_DIR}/ipx_wrap_sapd" "0x${IPX_PREFIX}" "${SAPD_CFG}" &
