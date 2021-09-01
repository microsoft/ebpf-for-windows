# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

param($OutDir)

$commit_id = git rev-parse HEAD
'#define GIT_COMMIT_ID "' + $commit_id + '"' + "`n" | out-file -FilePath ($OutDir + "\\" + "git_commit_id.h")