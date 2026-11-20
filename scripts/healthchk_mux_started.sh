#!/bin/sh

set -eu

usage()
{
	echo "Usage: healthchk_mux_started.sh <prefix>"
	exit 1
}

[ "${#}" -ne 1 ] && usage

IPX_PREFIX="${1}"

SCRIPTS_DIR="`dirname ${0}`"
IPX_WRAP_DIR="`dirname ${SCRIPTS_DIR}`"

"${SCRIPTS_DIR}/healthchk_interfaces_started.sh" "${IPX_PREFIX}" || exit 1

socat -d0 -T1 ABSTRACT-CONNECT:ipxw_mux_ctrl,socktype=2 stdin
