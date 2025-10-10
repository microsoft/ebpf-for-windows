# Release Process

This document outlines the steps to create, publish, and service a release of eBPF for Windows.

The eBPF project follows [Semantic Versioning 2.0](https://semver.org) for versioning releases in the format `X.Y.Z`, where "`X`" and "`Y`" are the major and
minor versions respectively. "`Z`" is the patch version for servicing releases. A release is usually made once every month. Pre-release binaries are test signed.
Official releases will be production signed using Microsoft certificates.

## Creating a new release

A GitHub issue with the title `Scheduled eBPF release is due` is automatically created on the first day of every month requesting a new release. 
When this issue is triaged, a decision must be taken by the maintainers on whether to go ahead with the new monthly release. If
the decision is to create a new release the release manager must proceed with the following process.
1. Create a release branch  in the [Microsoft ebpf-for-windows repo]([https://github.com/microsoft/ebpf-for-windows).
**Note:** Only release managers have authority to create new branches. One of the ways to create a release branch is as follows:
   1. Create a topic branch from the "`main`" branch of a forked repo, and name it "`release/X.Y`" (where "`X`" and "`Y`" are the version number
   that is being released).
   1. Add remote called "upstream" pointing to the [Microsoft ebpf-for-windows repo]([https://github.com/microsoft/ebpf-for-windows). Run:
      ```bash
      git remote add upstream https://github.com/microsoft/ebpf-for-windows.git
   1. Push the topic branch into upstream. For example:
      ```bash
      git push upstream release/0.21
1. Once the release branch is created, commits can be cherry-picked from the main branch (including feature work and bug fixes) as deemed necessary
   by the maintainers and the release managers.
1. Create a tag on the *latest commit* on the release branch. The tag name must begin with `"Release-v"` and include the release version e.g. `"Release-v0.21"`.
1. The tag creation will automatically trigger the "`CI/CD`" workflow for the `release/X.Y` branch.
1. Follow the process in the [Release Branch Validation](ReleaseProcess.md#release-branch-validation) to ensure the quality of the release branch.
1. In the triage meeting following the successful validation of the release branch, the release manager must ask if any maintainer has any reasons to hold off the release.
   If not, move on to the following steps.
1. The `sign-off` label will be added to the issue created in step 1. 
1. Publish the release as per the [Publishing a Release](ReleaseProcess.md#publishing-a-release) process.
1. Follow the process in the [Updating the Product Version](ReleaseProcess.md#updating-the-product-version) to update the version of the product in the main branch,
   for the next release. The main branch must always be ahead of the latest release branch by one minor version. For example, if the latest release is `vX.Y`, 
   then the version of the main branch should be updated to `"vX.(Y+1).0`.

## Release Branch Validation

Tagging the release branch triggers `CI/CD` workflow (`cicd.yml`) which is used to validate a release branch. When triggered by the release tag, the workflow
runs more tests than the regular CI/CD runs triggered by pull requests, including longer duration fuzz tests, fault injection tests, stress tests, performance tests etc.
These tests can be manually scheduled as well. If any of the tests fail, the release manager must investigate the failure and follow up with issues in GitHub. 
Once potential fixes are merged to the release branch repeat the release manager must run these tests manuually for validation. The process will be repeated 
until the workflow completes successfully.

## Publishing the Release to GitHub

1. Go to the repo on GitHub and click on "`<Code>`" and click on the "`Create a new release`" link.
1. Click on the "`Choose a tag`" combo box and select the tag with the version number for the release, as created earlier.
1. Fill in the release title as "`vX.Y.Z`". Note "`Z`" must be `0` for the monthly release. Otherwise, it should be the patch number. It may optionally also include
   the version modifier such as `"-beta"` or `"-rc"`.
1. Manually enter release notes or click "`Generate release notes`" and then edit as desired.
1. Microsoft maintains an *internal mirror* of the eBPF for Windows project. 
The release manager must download the relevant artifacts from the build pipeline of the internal mirror repo including the binaries, MSI installer and
SDK nuget packages for x64 and ARM64 platforms.
1. Upload these files, by dropping them in the "`Attach binaries by dropping them here or selecting them.`" area.
    For example, the file list for the release version `v0.21.1` are:
    - `Build-native-only.NativeOnlyDebug.arm64.zip`
    - `Build-native-only.NativeOnlyDebug.x64.zip`
    - `Build-native-only.NativeOnlyRelease.arm64.zip`
    - `Build-native-only.NativeOnlyRelease.x64.zip`
    - `Build.Debug.x64.zip`
    - `Build.Release.x64.zip`
    - `ebpf-for-windows.arm64.0.21.1.msi`
    - `eBPF-for-Windows.ARM64.0.21.1.nupkg`
    - `ebpf-for-windows.x64.0.21.1.msi`
    - `eBPF-for-Windows.x64.0.21.1.nupkg`

1.  Check the "`Set as a pre-release`" checkbox, unless the release is production-signed.
1.  Once the uploads are complete, click "`Publish release`". Github will automatically upload the zipped up source code file.

## Publishing the Release to NuGet.org

Upload the **SDK** `.nupkg` files for x64 and ARM64 platforms to [NuGet.org](https://www.nuget.org/). 
The metadata inside the `.nuget` package itself will automatically populate all the other form fields.

## Servicing a Release

Servicing a release has two main scenarios:

### Updating a Release branch with patches/hot-fixes from main

>NOTE: In servicing a release branch, **new features must not be added to the release branch**.  Only patches or hot-fixes will be accepted.

1. Check out a new topic branch from the `release/X.Y` branch you want to service.
1. Cherry pick the commits from `main` that you want to add to the release (patches/hot-fixes, etc.):

    ```bash
    git cherry-pick main <commit number> ... <commit number>
    ```
    If there are conflicts, resolve them. For example, via:
    ```bash
    git mergetool
    ```
1. Follow the process in the [Updating the Release Version](ReleaseProcess.md#updating-the-release-version) to update the release version to include the *patch version*.
1. Create a pull-request from the topic branch into the [original "upstream" `ebpf-for-windows` repo]([https://github.com/microsoft/ebpf-for-windows)'s "`release/X.Y`" branch, and title the PR as *"Release v`X.Y.Z`"* where "`Z`" is the patch
version.
1. Once the PR is approved and merged into the "`release/X.Y`" branch in the [original "upstream" `ebpf-for-windows` repo]([https://github.com/microsoft/ebpf-for-windows), and create a tag for the latest commit in the following format: "`vX.Y.Z`".
1. In some rare cases, the main and release branches may have deviated so much, that a bug found in the release branch may require a fix that is no longer applicable to the main branch.
   For such rare cases, a fix may be committed directly to the release branch.
1. Publish the patch release as per the [Publishing a Release](ReleaseProcess.md#publishing-a-release) process.


## Updating the Product Version

1. Run `.\scripts\update-product-version.ps1` from the root directory of the repository, from a "*Developer Powershell for VS 2022"* terminal.
   The script takes as input parameters the major, minor, patch versions and *optionally* the version modifier.
   
   Examples:
    ```ps
    # Update the product version in the main branch to 0.22.
    .\scripts\update-product-version.ps1 0 22 0
    ```
    ```ps
    # Update the product version of the v0.21 release branch for patching.
    .\scripts\update-product-version.ps1 0 21 1
    ```
    ```ps
    # Update the product version of the v1.0 release branch to include a version modifier for release candidate 1.
    .\scripts\update-product-version.ps1 1 0 0 rc1
    ```
    For example, a successful run of the script for version 0.12.0 produces the following output:

    ```ps
    PS D:\work\ebpf-for-windows> .\scripts\update-product-version.ps1 0 21 0
    Updating the version number in the 'E:\ebpf-for-windows\scripts\..\Directory.Build.props' file...
    Version number updated to '0.21.0' in E:\ebpf-for-windows\scripts\..\Directory.Build.props
    Rebuilding the solution, please wait...
    Regenerating the expected 'bpf2c' output...
    ...
    ...
    Expected 'bpf2c' output regenerated.
    Please verify all the changes then submit the pull-request into the 'release/0.12' branch.
    ```

1. Verify all the changes then commit all in the working branch.
    >NOTE: The formatting rules may complain about the formatting of the generated `.c` files from the script above. In this case,
    override them with the following (so they'll work with the `bpf2c_tests` verifying their content):
    >```bash
    >git commit --no-verify -a -m "update version to X.Y.Z".
    >```
