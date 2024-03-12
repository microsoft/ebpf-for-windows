# Release Process

This file details the steps for creating a versioned release of
eBPF for Windows, and how to service it later.

>**Note**: Currently releases are *not* production signed and therefore considered as "pre-releases". Their versioning is currently fixed to *Major Version (i.e., "X")* set to "`0`", therefore versioned as "`0.Y.Z`".

## Creating a new release

1. Create a working branch from "`main`" on your private repo fork, and check it out (e.g., `<user>/release-X-Y-Z`).
1. Run the following script from the root directory of the repository, within a "*Developer Poweshell for VS 2022"* instance. Make sure to follow [Semantic Versioning 2.0](https://semver.org) ("`X.Y.Z`"):

    ```ps
    # Replace "X.Y.Z" with the new version number being released
    .\scripts\update-release-version.ps1 X Y Z
    ```

    A successful run of the script will produce output similar to the following:

    ```ps
    PS D:\work\ebpf-for-windows> .\scripts\update-release-version.ps1 0 12 0
    Updating the version number in the 'D:\work\ebpf-for-windows\scripts\..\resource\ebpf_version.h' file...
    Version number updated to '0.12.0' in D:\work\ebpf-for-windows\scripts\..\resource\ebpf_version.h
    Updating the version number in the 'D:\work\ebpf-for-windows\scripts\..\installer\Product.wxs' file...
    Version number updated to '0.12.0' in D:\work\ebpf-for-windows\scripts\..\installer\Product.wxs
    Rebuilding the solution, please wait...
    Regenerating the expected 'bpf2c' output...
    Generating output for atomic_instruction_fetch_add.o
    ...
    ...
    Generating output for printk_unsafe.o
    Expected 'bpf2c' output regenerated.
    Please verify all the changes then submit the pull-request into the 'release/0.12' branch.
    ```

1. Verify all the changes then commit all in the working branch.
    >NOTE: The formatting rules may complain about the formatting of the generated `.c` files from the script above. In this case, override them with the following (so they'll work with the `bpf2c_tests` verifying their content):

    >```bash
    >git commit --no-verify
    >```

1. Create a **Draft** pull-request for your branch into the main repo's "`main`" branch (which you created in step 1), and title the PR as *"Release v`X.Y.Z`"* (replace "`X.Y.Z`" with the version number being released).
1. Once the CI/CD pipeline for the PR completes, download the "`ebpf-for-windows - MSI installer (Build-x64_Release)`" and "`ebpf-for-windows - NuGet package (Build-x64_Release)`" build artifacts
   (accessible via the "`Actions`" tab on GitHub).
1. Extract the `*.nupkg` file, and rename it in the following format (replace "`X.Y.Z`" with the version number being released):

    - `eBPF-for-Windows.X.Y.Z.nupkg`
1. Submit the PR for review (from its draft state), and wait for it to be approved and merged into the main repo's "`main`" branch.
1. On the main `ebpf-for-windows` repo, create a new release branch from `main` **corresponding to the previous PR's commit**, name it "`release/X.Y`" (replace "X.Y" with the version number being released).
1. Publish the release as per the "[Publishing a Release](ReleaseProcess.md#publishing-a-release)" process.

## Servicing a release

Servicing a release has two main scenarios:

### Updating a Release branch with patches/hot-fixes from main (*Forward Integration*)

>NOTE: In servicing a release branch, **new features must not be added to the release branch**.  Only patches or hot-fixes will be accepted.

1. On the main `ebpf-for-windows` repo, create and check out a new working branch from the `/release/X.Y` branch you want to service.
1. Run the following script from the root directory of the repository, within a "*Developer Poweshell for VS 2022"* instance. Make sure to follow [Semantic Versioning 2.0](https://semver.org) ("`X.Y.Z`"):

    ```ps
    # Replace "X.Y.Z" with the new version number being released
    .\scripts\update-release-version.ps1 X Y Z
    ```

1. Cherry pick the commits from `main` that you want to add to the release (patches/hot-fixes, etc.):

    ```bash
    git cherry-pick main <commit number> ... <commit number>
    ```

    If there are conflicts, resolve them. For example, via:

    ```bash
    git mergetool
    ```

1. Verify all the changes then commit all in the working branch.
    >NOTE: The formatting rules may complain about the formatting of the generated `.c` files from the script above. In this case, override them with the following (so they'll work with the `bpf2c_tests` verifying their content):

    >```bash
    >git commit --no-verify
    >```

1. Create a **Draft** pull-request for your working branch into the main repo's "`release/X.Y`" branch, and title the PR as *"Release v`X.Y.Z`"* (replace "`X.Y.Z`" with the version number being released).
1. Wait for  the CI/CD pipeline for the PR to complete successfully.
1. Submit the PR for review (from its draft state), and wait for it to be approved and merged into the main repo's "`release/X.Y`" branch.
1. Publish the release as per the "[Publishing a Release](ReleaseProcess.md#publishing-a-release)" process.

### Updating the main brach with patches/hot-fixes from a Release branch (*Reverse/Backwards Integration*)

>IMPORTANT! Normally, this should be done by the release manager **in VERY RARE scenarios** (and it's also likely an indication there's been a failure in the releasing process), but if you are a contributor and have been asked to do this, here are the steps to be followed:

1. On the main `ebpf-for-windows` repo, create and check out a new working branch from the "`main`" branch.
1. Cherry pick the commits from the "`release/X.Y`" branch branch that you want to add to the "`main`" branch (patches/hot-fixes, etc.):

    ```bash
    git cherry-pick release/X.Y <commit number> ... <commit number>
    ```

    If there are conflicts, resolve them. For example, via:

    ```bash
    git mergetool
    ```

1. Commit all the changes in the working branch.
1. Create a **Draft** pull-request for your working branch into the main repo's "`main`" branch, and title the PR as *"Backwards Integration of Release v`X.Y.Z`"* (replace "`X.Y.Z`" with the version number being released).
1. Wait for the CI/CD pipeline for the PR to complete successfully.
1. Submit the PR for review (from its draft state), and wait for it to be approved and merged into the main repo's "`main`" branch.
1. Create a tag for the PR's commit number, on the main repo's "`main`" branch, with meaningful name (i.e., "*RI-from-release-vX.Y.Z*").

## Publishing a Release

As a result of creating new release or servicing an existing one, the following steps are required to publish the release:

### Publishing the Release to GitHub

1. On the `microsoft/ebpf-for-windows` repo's `main` branch, create a tag for the release-PR's commit. The tag should reflect the version number being released and adhere to the following notation: "`vX.Y.Z`".
1. Wait for the `sign-off` label to be added from the Triage meeting, on the automated "release-issue" associated to the release to be published.
   >**IMPORTANT:** While awaiting sign-off, **only bug-fix PRs are allowed into the `release/X.Y` branch**. In case bug-fix PRs are merged into the `release/X.Y` branch, it is crucial to **designate the latest commit `release/X.Y` branch as the commit for release**.
1. Once the `sign-off` label has been added, on the `microsoft/ebpf-for-windows` repo's `release/X.Y` branch, create a tag for the *latest commit on the `release/X.Y` branch*. The tag should reflect the version number being released and adhere to the following notation: "`Release-vX.Y.Z`".
1. The tag creation will automatically trigger the "`CI/CD - Release validation`" workflow for the `release/X.Y` branch: wait for it to complete successfully.
    >**NOTE:** If the release validation fails, it is the responsibility of the release manager to trigger further investigations, including eventually the submission of necessary issues. Once the issue(s) is(are) resolved, potentially through other PRs, it is important to **delete the previous tag**. Subsequently, recreate the same tag for the *latest commit* on the `release/X.Y` branch, wait for the "`CI/CD - Release validation`" workflow to complete successfully.
1. Download the following artifacts from the `CI/CD Release Validation` workflow run:

    - *Build-x64-Debug.X.Y.Z.zip*
    - *Build-x64-Release.X.Y.Z.zip*
    - *Build-x64-native-only-Debug.X.Y.Z.zip*
    - *Build-x64-native-only-Release.X.Y.Z.zip*

1. Extract the MSI from the "*ebpf-for-windows - MSI installer (Build-x64-native-only_NativeOnlyRelease).zip*" artifact from `CI/CD Release Validation` workflow run, and rename it in the following format:

    - *eBPF-for-Windows.X.Y.Z.msi*

1. Extract the NuGet package from the "*ebpf-for-windows - NuGet package (Build-x64-native-only_NativeOnlyRelease).zip*" artifact from `CI/CD Release Validation` workflow run, and rename it in the following format:

    - *eBPF-for-Windows.X.Y.Z.nupkg*

1. Go to the repo on GitHub and click on "`<Code>`" and click on right the "`Create a new release`" link.
1. Click on the "`Choose a tag`" combo box and select the tag with new "`Release vX.Y.Z`" version number, as created earlier.
1. Fill in the release title as "`vX.Y.Z`" (replace "`X.Y.Z`" with the version number being released).
1. Manually enter release notes or click "`Generate release notes`" and then edit as desired.
1. Attach all the above artifacts (downloaded from points 5/6/7), by dropping them in the "`Attach binaries by dropping them here or selecting them.`" area. For example, the file list for `v0.13.0` should be:

    - *Build-x64-Debug.0.13.0.zip*
    - *Build-x64-Release.0.13.0.zip*
    - *Build-x64-native-only-Debug.0.13.0.zip*
    - *Build-x64-native-only-Release.0.13.0.zip*
    - *eBPF-for-Windows.0.13.0.msi*
    - *eBPF-for-Windows.0.13.0.nupkg*

1. Check the "`Set as a pre-release`" checkbox, unless the release is production-signed.
1. Once the uploads are complete, click "`Publish release`".

### Publishing the Release to NuGet.org

Upload the (**non-redist**) `.nupkg` file to [NuGet.org](https://www.nuget.org/) (the metadata inside the `.nuget` package itself will automatically populate all the other form fields).
