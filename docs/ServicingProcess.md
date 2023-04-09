# Servicing a release branch

>**Note**: Currently releases are *not* production signed and therefore considered as "pre-releases". Their versioning is currently fixed to *Major Version (i.e., "X")* set to "`0`", therefore versioned as "`0.Y.Z`".

## Updating a Release branch with patches/hot-fixes from main (*Forward Integration*)

>NOTE: in servicing a release branch, **no new features must be added to the release branch**, only patches or hot-fixes will be accepted.

1. On the main `ebpf-for-windows` repo, create and checkout a new working branch from the `/release/X.Y` branch you want to service.
1. Update the source code with the following steps:
    * Update the **minor version number "`Z`" only** in the following files, making sure to follow [Semantic Versioning 2.0](https://semver.org) ("`X.Y.Z`"):
        * `resource\ebpf_version.h`
        * `installer\Product.wxs`, within the following XML attribute:

            ```xml
            <Wix... <Product... Version="X.Y.Z" ...>...>
            ```
    * Open Visual Studio and *Rebuild* `ebpf-for-windows.sln` in "`x64/Debug`" mode.
    * Regenerate the expected `bpf2c` output (i.e. the corresponding "`.c`" files for all the solution's test/demo "`.o`" files), by running the following script:

        ```ps
        .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\
        ```
1. Cherry pick the commits from `main` that you want to add to the release (patches/hot-fixes, etc.):
    ```bash
    git cherry-pick main <commit number> ... <commit number>
    ```
    If there are conflicts, resolve them. For example, via:
    ```bash
    git mergetool
    ```
1. Commit all the changes in the working branch.
    >NOTE: the formatting rules may complain about the formatting of the generated `.c` files from the script above, in this case, format them with the following:
    >```bash
    ># In bash
    >./scripts/format-code --staged
    ># In PowerShell
    >.\\scripts\\format-code.ps1 --staged
    >```
1. Create a **Draft** pull-request for your working branch into the main repo's "`release/X.Y`" branch, and title the PR as *"Release v`X.Y.Z`"* (replace "`X.Y.Z`" with the version number being released).
1. Wait for  the CI/CD pipeline for the PR to complete successfully.
1. Submit the PR for review (from its draft state), and wait for it to be approved and merged into the main repo's "`release/X.Y`" branch.
1. Create a tag for the PR's commit number, on the main repo's "`release/X.Y`" branch, with the version number being released (i.e., "vX.Y.Z").

## Updating the Main brach with patches/hot-fixes from a Release branch (*Reverse/Backwards Integration*)

>IMPORTANT! Normally, this should be done by the release manager **in VERY RARE scenarios** (and it's also likely an indication there's been a failure in the releasing process), but if you are a contributor and have been asked to do this, here are the steps to be followed:

1. On the main `ebpf-for-windows` repo, create and checkout a new working branch from the "`main`" branch.
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
1. Wait for  the CI/CD pipeline for the PR to complete successfully.
1. Submit the PR for review (from its draft state), and wait for it to be approved and merged into the main repo's "`main`" branch.
1. Create a tag for the PR's commit number, on the main repo's "`main`" branch, with meaningful name (i.e., "RI-from-release-vX.Y.Z").