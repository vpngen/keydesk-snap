#!/bin/sh

set -e

export CGO_ENABLED=0

go build -C keydesk-snap/cmd/snapshot -o ../../../bin/snapshot

go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

nfpm package --config "keydesk-snap/debpkg/nfpm.yaml" --target "${SHARED_BASE}/pkg" --packager deb

chown "${USER_UID}:${USER_UID}" "${SHARED_BASE}/pkg/"*.deb

