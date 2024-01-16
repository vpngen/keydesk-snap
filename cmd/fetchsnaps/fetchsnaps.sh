#!/bin/sh

set -e

SNAP_APP_PATH="/opt/vgkeydesk-snap"

if [ -x "${SNAP_APP_PATH}/snapshot" ]; then
        SNAP_APP_BIN="${SNAP_APP_PATH}/snapshot"
elif go version >/dev/null 2>&1; then
        SNAP_APP_BIN="go run ../snap"
else
        echo "No snap tool found"
        exit 1
fi


if [ "root" != "$(whoami)" ]; then
        echo "DEBUG EXECUTION" >&2
        DEBUG="yes"
fi

chunked=""

fatal() {
        cat << EOF | awk -v chunked="${chunked}" '{if (chunked != "") print length($0) "\r\n" $0 "\r\n0\r\n\r\n"; else if (chunked == "") print $0}'
{
        "code": $1,
        "desc": "$2"
        "status": "error",
        "message": "$3"
}
EOF
        exit 1
}

printdef () {
        msg="$1"

        echo "Usage: echo \"\$PSK\" | $0 -tag <tag> -stime <global_snapshot_at> -mnt <maintenance_till> -list <brigade_id, ...>" >&2
        
        fatal "400" "Bad request" "$msg"
}

PSK=$(cat <&0)
if [ -z "${PSK}" ]; then
        printdef "PSK is empty"
fi


while [ $# -gt 0 ]; do
        case "$1" in
        -tag)
                TAG=$2
                shift
                ;;
        -stime)
                SNAP_AT=$2
                shift
                ;;
        -rfp)
                REALM_FP=$2
                shift
                ;;
        -list)
                BRIGADES=$2
                shift
                ;;
        -mnt)
                MNT="$2"
                shift
                ;;
        -d)
                if [ -z "$DEBUG" ]; then
                        printdef "The '-d' option is only for debug"
                fi

                arg="$2"

                if [ -z "${arg}" ]; then
                        printdef "DB_DIR is empty"
                fi

                DB_DIR="-d $2"
                shift
                ;;
        -c)
                if [ -z "$DEBUG" ]; then
                        printdef "The '-c' option is only for debug"
                fi

                arg="$2"

                if [ -z "${arg}" ]; then
                        printdef "CONF_DIR is empty"
                fi

                CONF_DIR="$2"
                shift
                ;;
        *)
                printdef "Unknown option: $1"
                ;;
        esac
        shift
done

if [ -z "${TAG}" ]; then
        printdef "TAG is empty"
fi

if [ -z "${SNAP_AT}" ]; then
        printdef "SNAP_AT is empty"
fi

if [ -z "${REALM_FP}" ]; then
        printdef "REALM_FP is empty"
fi

MNT_ARG=""
if [ -n "${MNT}" ]; then
        if ! printf "%s" "$MNT" | grep -qE '^[0-9]+$' ; then
                printdef "MNT is not a number"
        fi

        MNT_ARG="-mnt ${MNT}"
fi

if [ -z "${BRIGADES}" ]; then
        printdef "BRIGADES is empty"
fi

DB_DIR=${DB_DIR:-"../../../vpngen-keydesk/cmd/keydesk"}
DB_DIR="$(realpath "${DB_DIR}")"
DB_DIR="-d ${DB_DIR}"

CONF_DIR=${CONF_DIR:-"../../core/crypto/testdata"}
CONF_DIR="$(realpath "${CONF_DIR}")"
CONF_DIR="-c ${CONF_DIR}"

for id in $(printf "%s" "${BRIGADES}" | tr ',' ' '); do
        n="$(echo "${id}=======" | base32 -d 2>/dev/null | wc -c 2>/dev/null)"
        if [ -z "${n}" ] || [ "${n}" -ne 16 ]; then
                printdef "invalid brigade id: ${id}"
        fi
done

SNAPSHOT_ARRAY="{ \"snaps\" : ["
NOT_FIRST_SNAP=""

for brigade_id in $(printf "%s" "${BRIGADES}" | tr ',' ' '); do
        if [ -n "${NOT_FIRST_SNAP}" ]; then
                NOT_FIRST_SNAP="x"
                SNAPSHOT_ARRAY="${SNAPSHOT_ARRAY},"
        fi

        if [ -z "${DEBUG}" ]; then
                # shellcheck disable=SC2086
                SNAPSHOT="$(printf "%s" "$PSK" | sudo -u "${brigade_id}" -g "${brigade_id}" ${SNAP_APP_BIN} \
                        -tag "${TAG}" \
                        -stime "${SNAP_AT}" \
                        -rfp "${REALM_FP}" \
                        ${MNT_ARG} \
                )" || echo "Can't create snapshot ${brigade_id}" >&2
        else
                # shellcheck disable=SC2086
                SNAPSHOT="$(printf "%s" "$PSK" | ${SNAP_APP_BIN} \
                        -tag "${TAG}" \
                        -stime "${SNAP_AT}" \
                        -rfp "${REALM_FP}" \
                        -id "${brigade_id}" \
                        ${DB_DIR} \
                        ${CONF_DIR} \
                        ${MNT_ARG} \
                )" || echo "Can't create snapshot ${brigade_id}" >&2
        fi

        if [ -n "${SNAPSHOT}" ]; then
                SNAPSHOT_ARRAY="${SNAPSHOT_ARRAY}${SNAPSHOT}"
        fi
done

SNAPSHOT_ARRAY="${SNAPSHOT_ARRAY}]}"

echo "${SNAPSHOT_ARRAY}"