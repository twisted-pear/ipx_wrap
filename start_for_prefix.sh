#!/bin/sh

set -eu

cleanup_subprocesses()
{
	trap - EXIT

	[ -n "${SAPD_PID+set}" ] && kill "${SAPD_PID}" || true
	[ -n "${PONGD_PID+set}" ] && kill "${PONGD_PID}" || true
	[ -n "${RIPD_PID+set}" ] && kill "${RIPD_PID}" || true

	[ -n "${MUX_PID+set}" ] && kill "${MUX_PID}" || true

	pkill -P $$ || true
}

usage()
{
	echo "Usage: start_for_prefix.sh <32-bit hex prefix> <sapd cfg>"
	exit 1
}

[ "${#}" -ne 2 ] && usage
[ ! -f "${2}" ] && usage

IPV6_PREFIX=`echo "${1}" | sed 's/\([0-9a-fA-F]\{4\}\)\([0-9a-fA-F]\{4\}\)/\1:\2/'`
IPX_PREFIX="${1}"

[ "${IPV6_PREFIX}" = "${IPX_PREFIX}" ] && usage

SAPD_CFG="${2}"

IPX_WRAP_DIR="`dirname ${0}`"

trap 'cleanup_subprocesses' EXIT INT QUIT TERM

"${IPX_WRAP_DIR}/ipx_wrap_mux" "0x${IPX_PREFIX}" &
MUX_PID="$!"
sleep 5

ip -6 -o addr | grep "inet6 ${IPV6_PREFIX}:" | while read IFLINE; do
	IFACE=`echo "${IFLINE}" | cut -d ' ' -f 2`
	IPV6_ADDR=`echo "${IFLINE}" | awk '{print $4}' | cut -d '/' -f 1`

	"${IPX_WRAP_DIR}/ipx_wrap_ifd" "${IFACE}" "${IPV6_ADDR}" &
done

"${IPX_WRAP_DIR}/ipx_wrap_ripd" "0x${IPX_PREFIX}" &
RIPD_PID="$!"

"${IPX_WRAP_DIR}/ipx_wrap_pongd" "0x${IPX_PREFIX}" &
PONGD_PID="$!"

"${IPX_WRAP_DIR}/ipx_wrap_sapd" "0x${IPX_PREFIX}" "${SAPD_CFG}" &
SAPD_PID="$!"

sleep infinity &
wait "$!"
