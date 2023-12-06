# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

# Define the commands to run
$commands = @(
    "git submodule update --init --recursive",
    "cmake -G 'Visual Studio 17 2022' -S external\ebpf-verifier -B external\ebpf-verifier\build",
    "cmake -G 'Visual Studio 17 2022' -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF",
    "cmake -G 'Visual Studio 17 2022' -S external\ubpf -B external\ubpf\build",
    "nuget restore ebpf-for-windows.sln"
)

# Loop through each command and run them sequentially without opening a new window
foreach ($command in $commands) {
    Invoke-Expression -Command $command
}