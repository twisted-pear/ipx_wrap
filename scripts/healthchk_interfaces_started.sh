#!/bin/sh

set -eu

usage()
{
	echo "Usage: healthchk_interfaces_started.sh <prefix>"
	exit 1
}

[ "${#}" -ne 1 ] && usage

SCRIPTS_DIR="`dirname ${0}`"
IPX_WRAP_DIR="`dirname ${SCRIPTS_DIR}`"


ip -6 -o addr | grep "inet6 ${IPX_PREFIX}:" | while read IFLINE; do
	IFACE=`echo "${IFLINE}" | cut -d ' ' -f 2`
	tc filter show dev "${IFACE}" ingress | grep -q 'ipx_wrap_in'
	tc filter show dev "${IFACE}" egress | grep -q 'ipx_wrap_out'
done
