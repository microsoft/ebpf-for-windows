# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

param ($InputFile, $OutputFile, [parameter(Mandatory=$false)]$VCToolsRedistDir, [parameter(Mandatory=$false)]$architecture, [parameter(Mandatory=$false)]$configuration)

function Get-CurrentBranch {
    $env:GIT_REDIRECT_STDERR = '2>&1'
    $CurrentBranch = git branch --show-current
    if ([string]::IsNullOrWhiteSpace($CurrentBranch)) {
        Write-Warning "Failed to get branch from git"
        return $null
    }
    return $CurrentBranch
}

# Returns the target or current git branch.
function Get-BuildBranch {
    if (![string]::IsNullOrWhiteSpace($env:SYSTEM_PULLREQUEST_TARGETBRANCH)) {
        # We are in a (AZP) pull request build.
        Write-Host "Using SYSTEM_PULLREQUEST_TARGETBRANCH=$env:SYSTEM_PULLREQUEST_TARGETBRANCH to compute branch"
        return $env:SYSTEM_PULLREQUEST_TARGETBRANCH

    } elseif (![string]::IsNullOrWhiteSpace($env:GITHUB_BASE_REF)) {
        # We are in a (GitHub Action) pull request build.
        Write-Host "Using GITHUB_BASE_REF=$env:GITHUB_BASE_REF to compute branch"
        return $env:GITHUB_BASE_REF

    } elseif (![string]::IsNullOrWhiteSpace($env:BUILD_SOURCEBRANCH)) {
        # We are in a (AZP) main build.
        Write-Host "Using BUILD_SOURCEBRANCH=$env:BUILD_SOURCEBRANCH to compute branch"
        $env:BUILD_SOURCEBRANCH -match 'refs/(?:heads/)?(.+)' | Out-Null
        return $Matches[1]

    } elseif (![string]::IsNullOrWhiteSpace($env:GITHUB_REF_NAME)) {
        # We are in a (GitHub Action) main build.
        Write-Host "Using GITHUB_REF_NAME=$env:GITHUB_REF_NAME to compute branch"
        return $env:GITHUB_REF_NAME

    } else {
        # Fallback to the current branch.
        return Get-CurrentBranch
    }
}

function Test-IsReleaseBuild {
    $buildBranch = Get-BuildBranch

    # First check if it matches release/ or tags/ pattern
    $matchesReleasePattern = $buildBranch -match '^release/|^tags/'

    # If it doesn't match the pattern, it's not a release build
    if (-not $matchesReleasePattern) {
        return $false
    }

    # If it matches the pattern but contains 'prerelease', it's not a release build
    if ($buildBranch -match 'prerelease') {
        return $false
    }

    # It matches the pattern and doesn't contain 'prerelease', so it's a release build
    return $true
}

<#
.SYNOPSIS
    Get the eBPF version string, optionally with git hash appended for non-release branches.

.DESCRIPTION
    This function constructs the version string from the Directory.Build.props file.
    For non-release branches, it appends the git commit hash to the version only for nuspec.in files.

.PARAMETER GitCommitId
    The git commit ID to append for non-release branches

.PARAMETER InputFilePath
    The path to the input file being processed to determine if prerelease versioning should be applied

.RETURNS
    The version string, potentially with git hash appended for nuspec.in files
#>
function Get-EbpfVersionString {
    param(
        [Parameter(Mandatory=$true)][string]$GitCommitId,
        [Parameter(Mandatory=$true)][string]$InputFilePath
    )

    # Read and parse the Directory.Build.props file
    $content = Get-Content -path "$PSScriptRoot\..\Directory.Build.props" -Raw -Encoding UTF8
    [xml]$xml = $content

    $VersionPropertyGroup = $xml.Project.PropertyGroup | Where-Object {$_.PSObject.Properties.Name -contains "Label" -and $_.Label -eq "Version"}

    # Build the base version number
    $baseVersion = ""
    $baseVersion += $VersionPropertyGroup.EbpfVersion_Major + "."
    $baseVersion += $VersionPropertyGroup.EbpfVersion_Minor + "."
    $baseVersion += $VersionPropertyGroup.EbpfVersion_Revision

    # Check if this is a release build
    $isReleaseBuild = Test-IsReleaseBuild
    $buildBranch = Get-BuildBranch

    # Check if we're processing a nuspec.in file
    $isNuspecFile = $InputFilePath -match '\.nuspec\.in$'

    if ($isReleaseBuild) {
        Write-Host "Release build detected (branch: $buildBranch). Using base version: $baseVersion"
        return $baseVersion
    } else {
        # For non-release builds, only append git hash for nuspec.in files
        if ($isNuspecFile) {
            $shortHash = $GitCommitId.Substring(0, [Math]::Min(8, $GitCommitId.Length))
            $versionWithHash = "$($baseVersion)-prerelease-$($shortHash)"
            Write-Host "Non-release build detected (branch: $buildBranch) for nuspec.in file. Using version with git hash: $versionWithHash"
            return $versionWithHash
        } else {
            Write-Host "Non-release build detected (branch: $buildBranch) for non-nuspec file. Using base version: $baseVersion"
            return $baseVersion
        }
    }
}

# The git commit ID is in the include directory and is in the format:
# #define GIT_COMMIT_ID "some commit id"
$git_commit_id = Get-Content -Path "$PSScriptRoot\..\include\git_commit_id.h" -Raw -Encoding UTF8
$git_commit_id = $git_commit_id.Split('"')[1]

$content = Get-Content -path "$PSScriptRoot\..\Directory.Build.props" -Raw -Encoding UTF8

# Parse the XML content
[xml]$xml = $content

$VersionPropertyGroup = $xml.Project.PropertyGroup | Where-Object {$_.PSObject.Properties.Name -contains "Label" -and $_.Label -eq "Version"}

# Get the final version string (with git hash if not a release branch and processing nuspec.in file)
$version_no_modifier = Get-EbpfVersionString -GitCommitId $git_commit_id -InputFilePath $InputFile
$version = $version_no_modifier
if ($VersionPropertyGroup.EbpfVersion_Modifier -ne "") {
    $version += "-" + $VersionPropertyGroup.EbpfVersion_Modifier
}

$content = Get-Content $InputFile
$content = $content.Replace("{version}", $version)
$content = $content.Replace("{version_no_modifier}", $version_no_modifier)
$content = $content.Replace("{VCToolsRedistDir}", $VCToolsRedistDir)
$content = $content.Replace("{git_commit_id}", $git_commit_id)
$content = $content.Replace("{architecture}", $architecture)
if ($configuration -match "Release") {
    $content = $content.Replace("{configuration}", "")
} else {
    $content = $content.Replace("{configuration}", ".$configuration")
}
set-content $OutputFile $content
