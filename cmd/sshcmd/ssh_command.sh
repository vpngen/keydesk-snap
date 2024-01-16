#!/bin/sh

# interpret first argument as command
# pass rest args to scripts

printdef() {
    echo "Usage: <command> <args...>" >&2
    exit 1
}

if [ $# -eq 0 ]; then 
    printdef
fi

cmd=${1}; shift
basedir=$(dirname "$0")

set -e

if [ "${cmd}" = "fetchsnaps" ]; then
        "${basedir}/fetchsnaps.sh" "$@"
else
    echo "Unknown command: ${cmd}"
    printdef
fi
