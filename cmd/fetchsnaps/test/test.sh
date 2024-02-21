#!/bin/sh

set -e

if [ -x "../fetchsnaps.sh" ]; then
        FETCHSNAPS="$(dirname "$0")/../fetchsnaps.sh"
else
        echo "No snap tool found"
        exit 1
fi

while [ $# -gt 0 ]; do
        case "$1" in
        -c)
                CONF_DIR=$2
                shift
                ;;
        -d)
                DB_DIR=$2
                shift
                ;;
        *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
done

DB_DIR=${DB_DIR:-"../../../../vpngen-keydesk/cmd/keydesk"}
DB_DIR="$(realpath "${DB_DIR}")"
CONF_DIR=${CONF_DIR:-"../../../core/crypto/testdata"}
CONF_DIR="$(realpath "${CONF_DIR}")"

if [ ! -s "${DB_DIR}/brigade.json" ]; then
        echo "No keydesk db found in ${DB_DIR}"
        exit 1
fi

BRIGADE_ID="$(jq -r .brigade_id "${DB_DIR}/brigade.json")"

if [ ! -s "${CONF_DIR}/realms_keys" ]; then
        echo "No realms keys found in ${CONF_DIR}"
        exit 1
fi

REALM_FP="SHA256:$(grep "ssh-rsa" "${CONF_DIR}/realms_keys" | head -n 1 | awk '{print $2}' | base64 -d | openssl dgst -sha256 -binary | base64 -w 0 | sed 's/=//g' | awk '{print $1}' )"

if [ ! -s "${CONF_DIR}/authorities_keys" ]; then
        echo "No authorities keys found in ${CONF_DIR}"
        exit 1
fi

TAG="snaphost-test"
SNAP_AT="$(date +%s)"

PSK="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 -w 0)"

echo "Testing snapshot fetching"
echo "CONF_DIR=${CONF_DIR}"
echo "DB_DIR=${DB_DIR}"
echo "LIST=${BRIGADE_ID}"
echo "REALM_FP=${REALM_FP}"
echo "TAG=${TAG}"
echo "SNAP_AT=${SNAP_AT}"

echo "${PSK}" | ${FETCHSNAPS} -c "${CONF_DIR}" -d "${DB_DIR}" -list "${BRIGADE_ID}" -rfp "${REALM_FP}" -tag "${TAG}" -stime "${SNAP_AT}" | tee "${DB_DIR}/brigades.snap.json"
