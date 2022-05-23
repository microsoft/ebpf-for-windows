# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Copy release archive to local directory as ebpf-for-windows-c-temp.zip before running this script.

repository=${repository:-"your repository"}
tag=${tag:-"your tag"}
OSVersion=${OSVersion:-"1809"}

docker buildx build --platform windows/amd64 --output=type=registry --pull -f Dockerfile.install -t $repository/ebpfwin-install:$tag --build-arg WINDOWS_VERSION=$OSVersion .
