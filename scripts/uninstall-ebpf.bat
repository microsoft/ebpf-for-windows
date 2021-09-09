rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT

rem Stop any eBPF binaries already loaded
sc stop ebpfsvc
sc stop NetEbpfExt
sc stop SampleEbpfExt
sc stop EbpfCore

rem Deregister the old binaries
sc delete ebpfsvc
sc delete NetEbpfExt
sc delete SampleEbpfExt
sc delete EbpfCore
