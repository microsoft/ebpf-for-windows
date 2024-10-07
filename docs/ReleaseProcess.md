# Release Process

This document outlines the steps to create, publish, and service a release of eBPF for Windows.

The eBPF project follows [Semantic Versioning 2.0](https://semver.org) for versioning releases in the format `X.Y.Z`, where "`X`" and "`Y`" are the major and
minor versions respectively. "`Z`" is the patch version for servicing releases. A release is usually made once every month. Pre-release binaries are test signed.
Official releases will be production signed using Microsoft certificates.

>**Note**: The *major version* for all releases is set to "`0`" (i.e., "`0.Y.Z`") until the first official release is published with version `1.0.0`.

## Creating a new release

An issue with the title `Scheduled eBPF release is due` is automatically created on the first day of every month requesting a new release with the minor
version incremented every time. When this issue is triaged, a decision must be taken by the maintainers on whether to go ahead with the new monthly release. If
the decision is to create a new release the release manager must proceed with the following process.
1. Create a release branch  in the [Microsoft ebpf-for-windows repo]([https://github.com/microsoft/ebpf-for-windows).
**Note:** Only release managers have authority to create new branches. One of the ways to create a release branch is as follows:
   1. Create a topic branch from the "`main`" branch of a forked repo, and name it "`release/X.Y`" (where "`X`" and "`Y`" are the current version number
   that is being released).
   1. Add remote called "upstream" pointing to the [Microsoft ebpf-for-windows repo]([https://github.com/microsoft/ebpf-for-windows). Run:
      ```bash
      git remote add upstream https://github.com/microsoft/ebpf-for-windows.git
   1. Push the topic branch into upstream. For example:
      ```bash
      git push upstream release/0.12
1. Once the release branch is created, commits can be cherry-picked from the main branch (including feature work and bug fixes) as deemed necessary
   by the maintainers and the release managers.
1. Follow the process in the [Release Branch Validation](ReleaseProcess.md#release-branch-validation) to ensure the quality of the release branch.
1. If the release validation process finds a bug that is present only in the release branch (but not in the main branch), a fix can be committed directly
   into the release branch instead of cherry-picking from the main branch.
1. In the triage meeting after the successful validation of the release branch, the release manager must ask if any maintainer has any reasons to hold off the release. If
   not, move on to the following steps.
1. The `sign-off` label will be added to the issue created in step 1 of the [Creating a new release](ReleaseProcess.md#creating-a-new-release) process.
1. Create a tag "`Release-vX.Y.0`" on the *latest commit on the `release/X.Y` branch*.
1. The tag creation will automatically trigger the "`CI/CD - Release validation`" workflow for the `release/X.Y` branch. In case of failure, Follow the process in
   the [Release Branch Validation](ReleaseProcess.md#release-branch-validation).
2. Publish the release as per the [Publishing a Release](ReleaseProcess.md#publishing-a-release) process.
3. Follow the process in the [Updating the Product Version](ReleaseProcess.md#updating-the-product-version) to update the version of the product in the main branch,
   for the next release.

## Release Branch Validation

The `CI/CD - Release validation` workflow(`cicd-release-validation.yml`) is used to validate a release branch. It contains more tests than the regular CI/CD
pipeline, including longer duration fuzz tests, fault injection tests, stress tests, performance tests etc. These tests can be manually scheduled. The release
manager must run these tests on the release branch. Due to the non-deterministic nature of some of the tests, it is recommended that the tests are run at least
three times on the branch. If any of the tests fail, the release manager must investigate the failure and follow up with issues in GitHub. Once potential fixes
are merged to the release branch repeat the process until the workflow completes successfully.

## Publishing the Release to GitHub

1. Go to the repo on GitHub and click on "`<Code>`" and click on the "`Create a new release`" link.
1. Click on the "`Choose a tag`" combo box and select the tag with the version number for the release, as created earlier.
1. Fill in the release title as "`vX.Y.Z`". Note "`Z`" must be `0` for the monthly release. Otherwise, it should be the patch number.
1. Manually enter release notes or click "`Generate release notes`" and then edit as desired.
1. Microsoft maintains an internal mirror of the eBPF for Windows project. For a given release branch in GitHub, the mirror repo will have a corresponding one.
The release manager must download the following artifacts from the latest build of the internal mirror repo:
   - `Build-x64 Debug.zip`
   - `Build-x64 Release.zip`.
   - `Build-x64-native-only-NativeOnlyDebug.zip`
   - `Build-x64-native-only-NativeOnlyRelease.zip`
   - `ebpf-for-windows - MSI installer (Build-x64_Release).zip` - Extract the `.msi` file and rename it to `ebpf-for-windows.X.Y.0.msi`.
   - `ebpf-for-windows - NuGet.zip` - Extract the `.nupkg` file.
      - **NOTE** : The Microsoft internal build pipeline has two flavors of nuget package. The release manager must pick the one that *does not* contain "Redist" in
      the name.
1. Upload the above files, by dropping them in the "`Attach binaries by dropping them here or selecting them.`" area.
    For example, the file list for `v0.12.0` should be:
    - `Build-x64-Debug.zip`
    - `Build-x64-Release.zip`
    - `Build-x64-native-only-NativeOnlyDebug.zip`
    - `Build-x64-native-only-NativeOnlyRelease.zip`
    - `ebpf-for-windows.0.12.0.msi`
    - `eBPF-for-Windows.0.12.0.nupkg`

2.  Check the "`Set as a pre-release`" checkbox, unless the release is production-signed.
3.  Once the uploads are complete, click "`Publish release`". Github will automatically upload the zipped up source code file.

## Publishing the Release to NuGet.org

Upload the (**non-redist**) `.nupkg` file to [NuGet.org](https://www.nuget.org/) (the metadata inside the `.nuget` package itself will automatically populate all
the other form fields).

## Servicing a Release

Servicing a release has two main scenarios:

### Updating a Release branch with patches/hot-fixes from main (*Forward Integration*)

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
1. Follow the process in the [Updating the Release Version](ReleaseProcess.md#updating-the-release-version) to update the release version.
1. Create a pull-request from the topic branch into the [original "upstream" `ebpf-for-windows` repo]([https://github.com/microsoft/ebpf-for-windows)'s "`release/X.Y`" branch, and title the PR as *"Release v`X.Y.Z`"* where "`Z`" is the patch
version.
1. Once the PR is approved and merged into the "`release/X.Y`" branch in the [original "upstream" `ebpf-for-windows` repo]([https://github.com/microsoft/ebpf-for-windows), and create a tag for the latest commit in the following format: "`Release-vX.Y.Z`".
1. Publish the patch release as per the [Publishing a Release](ReleaseProcess.md#publishing-a-release) process.


### Updating the main brach with patches/hot-fixes from a Release branch (*Reverse/Backwards Integration*)

>IMPORTANT! Normally, this should be done by the release manager **in VERY RARE scenarios** (and it's also likely an indication there's been a failure in the
releasing process), but if you are a contributor and have been asked to do this, here are the steps to be followed:

1. On your fork, create and check out a new topic branch from the "`main`" branch.
2. Cherry pick the commits from the "`release/X.Y`" branch that you want to add to the "`main`" branch (patches/hot-fixes, etc.):

    ```bash
    git cherry-pick release/X.Y <commit number> ... <commit number>
    ```
    If there are conflicts, resolve them. For example, via:
    ```bash
    git mergetool
    ```
3. Commit all the changes in the working branch.
4. Create a pull-request for your working branch into the [original "upstream" `ebpf-for-windows` repo]([https://github.com/microsoft/ebpf-for-windows)'s "`main`" branch, and title the PR as *"Backwards Integration of Release v`X.Y.Z`"* (replace "`X.Y.Z`" with the version number being released).
5. Submit the PR for review for approval, and have it merged into the [original "upstream" `ebpf-for-windows` repo]([https://github.com/microsoft/ebpf-for-windows)'s "`main`" branch.

## Updating the Product Version

1. Run the following script from the root directory of the repository, from a "*Developer Powershell for VS 2022"* terminal.

    ```ps
    # Set "X" and "Y" to the the new major and minor versions. If servicing a release, set "Z" to the revision or patch number.
    .\scripts\update-product-version.ps1 X Y Z
    ```
    For example, a successful run of the script for version 0.12.0 produces the following output:

    ```ps
    PS D:\work\ebpf-for-windows> .\scripts\update-product-version.ps1 0 12 0
    Updating the version number in the 'E:\ebpf-for-windows\scripts\..\Directory.Build.props' file...
    Version number updated to '0.12.0' in E:\ebpf-for-windows\scripts\..\Directory.Build.props
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