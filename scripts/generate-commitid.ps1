# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param($OutDir)

$file_name = ($OutDir + "\" + "git_commit_id.h")
$commit_id = git rev-parse HEAD
$new_content = '#define GIT_COMMIT_ID "' + $commit_id + '"' + "`n"
[string]$old_commit_id = ""
if (Test-Path $file_name) {
    [string]$old_content = ""
    $old_content = Get-Content $file_name
    $old_commit_id = $old_content.Split('"')[1]
}
if ($old_commit_id -ne $commit_id) {
    Write-Output "Commit ID changed, regenerating $file_name"
    $new_content | out-file -FilePath $file_name
}
