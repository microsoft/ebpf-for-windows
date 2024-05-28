# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Download and copy release archive to local directory as ./ebpf-for-windows.msi before running this script.

repository=${repository:-"your repository"}
tag=${tag:-"your tag"}

docker buildx build --platform windows/amd64 --output=type=registry --pull -f Dockerfile.install -t $repository/ebpfwin-install:$tag .
