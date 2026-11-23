#!/bin/sh
# .github/ci/kernel.sh: the tests of the backend that need the kernel, run from src/backend in
# golang:1.26.8-alpine as root with the right to administer the container's network
# (.github/workflows/tests.yml, job kernel; on nexus lab/v0821/nxgo.sh fw runs them so). The nft
# of Alpine (1.1.6): Debian trixie's 1.1.3 lists the fib compare of one byte that the backend
# writes as "oif missing/8", unlike the rule it makes itself, and TestBitTorrentTable fails there.
# Every skip but those of ALLOW fails: the tests must run here, not skip for lack of root, nft or ip.
set -eu
apk add -q --no-cache nftables iproute2
nft --version
ip -V
(cd ../../.github/ci && go build -o /usr/local/bin/testsum testsum.go)
rc=0
CGO_ENABLED=0 go test -json -ldflags=-checklinkname=0 -count=1 -tags "$SLIM" ./firewall/ ./netcfg/ ./diag/ ./engine/bittorrent/ > /tmp/kernel.json || rc=$?
testsum -title "go test SLIM (kernel)" -allow "$ALLOW" < /tmp/kernel.json || rc=1
exit $rc
