﻿# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param ($InputFile, $OutputFile, $TemplateText, $Replacement)

$lines = Get-Content $InputFile



$lines | Out-File $OutputFile