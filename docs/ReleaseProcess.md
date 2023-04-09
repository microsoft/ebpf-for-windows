# Release Process

This file details the steps for creating a versioned release of
eBPF for Windows:

>**Note**: Currently releases are *not* production signed and therefore considered as "pre-releases". Their versioning is currently fixed to *Major Version (i.e., "X")* set to "`0`", therefore versioned as "`0.Y.Z`".

1. On the main `ebpf-for-windows` repo, create a new release branch from `main`, i.e., "`release/X.Y`", and request the Admin of the main `ebpf-for-windows` repo to protect and apply release policies to the release branch.
1. Wait for the main `ebpf-for-windows` repo's Admin to complete the previous step (the process may not be quick).
1. On your private repo fork, create a new branch from the "`release/X.Y`" branch on the main `ebpf-for-windows` repo and check it out.
1. Update the source code with the following steps:
    * Update the version number in the following files, making sure to follow [Semantic Versioning 2.0](https://semver.org) ("`X.Y.Z`"):
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
1. Commit all the changes in the working branch.
    >NOTE: the formatting rules may complain about the formatting of the generated `.c` files from the script above, in this case, format them with the following:
    >```bash
    ># In bash
    >./scripts/format-code --staged
    ># In PowerShell
    >.\\scripts\\format-code.ps1 --staged
    >```
1. Create a **Draft** pull-request for your branch into the main repo's "`release/X.Y`" branch (which you created in step 1), and title the PR as *"Release v`X.Y.Z`"* (replace "`X.Y.Z`" with the version number being released).
1. Once the CI/CD pipeline for the PR completes, download the
   "`ebpf-for-windows - MSI installer (Build-x64_Release)`" and "`ebpf-for-windows - NuGet package (Build-x64_Release)`" build artifacts
   (accessible via the "`Actions`" tab on GitHub).
1. Extract the `*.msi` and `*.nupkg` files, respectively, out of them, and rename them in the following format (replace "`X.Y.Z`" with the version number being released):

    - `eBPF-for-Windows.X.Y.Z.msi`
    - `eBPF-for-Windows.X.Y.Z.nupkg`

1. Test the MSI manually (since not yet tested in CI/CD):
    1. Copy the MSI into a VM.
        >**Note**: currently only test-signed VMs are supported.
    1. Install the MSI by *enabling all its features* from the GUI.
    1. **After** the MSI has successfully installed, open a **new** *Admin Command Prompt*, and run the following commands to make sure the eBPF platform is correctly installed and working, e.g.:

        ```bash
        # Verify that the eBPF drivers are running:
        sc.exe query eBPFCore
        sc.exe query NetEbpfExt

        # Verify that the netsh extension is operational:
        netsh ebpf show prog

        # Run the unit tests, and expect a full pass:
        cd <eBPF install folder>\testing
        unit_tests.exe -d yes

        # Test some additional commands, e.g.:
        bpftool prog show
        ```
1. Submit the PR for review (from its draft state), and wait for it to be approved and merged into the main repo's "`release/X.Y`" branch.
1. Create a tag for the PR's commit number, with the version number being released, i.e. "`vX.Y.Z`".
1. Go to the repo on GitHub and click on "`<Code>`" and click on right the "`Create a new release`" link.
1. Click on the "`Choose a tag`" combo box and select the tag with new version number as "`vX.Y.Z`" created earlier.
1. Fill in the release title as "`vX.Y.Z`" (replace "`X.Y.Z`" with the version number being released).
1. Manually enter release notes or click "`Generate release notes`".
1. Attach the `.msi` and `.nupkg` files by dropping them in the "`Attach binaries by dropping them here or selecting them.`" area.
1. Check the "`Set as a pre-release`" checkbox, unless the release is production-signed.
1. Once the uploads are complete (it may take a while), click "`Publish release`".
1. Upload the `.nupkg` file to [nuget.org](nuget.org), and put a markup link to "`.\README.md`" as the description for the package (the metadata inside the `.nuget` package itself will automatically populate all the other form fields).
