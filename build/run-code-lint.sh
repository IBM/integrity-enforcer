#!/bin/bash
set -e

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

# Prepare lint tools

# Install golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$(go env GOPATH)"/bin v1.32.0

# Start lint task
make lint
