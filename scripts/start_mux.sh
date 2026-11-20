#!/bin/sh

set -eu

cleanup_subprocesses()
{
	trap - EXIT
	pkill -P $$ || true
}

usage()
{
	echo "Usage: start_mux.sh <prefix>"
	exit 1
}

[ "${#}" -ne 1 ] && usage

IPX_PREFIX="${1}"

SCRIPTS_DIR="`dirname ${0}`"
IPX_WRAP_DIR="`dirname ${SCRIPTS_DIR}`"

trap 'cleanup_subprocesses' EXIT INT QUIT TERM

"${SCRIPTS_DIR}/start_interfaces.sh" "${IPX_PREFIX}" &

IPX_PREFIX_MUX=`echo "${IPX_PREFIX}" | tr -d ':'`
"${IPX_WRAP_DIR}/ipx_wrap_mux" "0x${IPX_PREFIX_MUX}"
