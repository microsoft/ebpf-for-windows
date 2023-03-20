# Release Process

This file details the steps for creating a versioned release of
eBPF for Windows:

>**Note**: Currently releases are *not* production signed.

1. On your private repo fork, create a new release branch from `main`, i.e., "`user/release-vX.Y.Z`".
1. Update the version number, making sure to follow [Semantic Versioning 2.0](https://semver.org) ("`x.y.z`"), in the following files:
    * `resource\ebpf_version.h`
    * `installer\Product.wxs`, within the following XML attribute:

        ```xml
        <Wix... <Product... Version="x.y.z" ...>...>
        ```
    * `docs\tutorial.md`
1. Open Visual Studio and *Rebuild* `ebpf-for-windows.sln` in "`x64/Debug`" mode.
1. Regenerate the expected `bpf2c` output (i.e. the corresponding "`.c`" files for all the solution's test/demo "`.o`" files), by running the following script:

    ```ps
    .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\
    ```
1. Commit all the changes in the release branch into your forked repo.
1. Create a **Draft** pull-request for the release branch into the main `ebpf-for-windows` repo, and title the PR as *"Release v`X.Y.Z`"* (replace "`X.Y.Z`" with the version number being released).
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
1. Submit the PR for review (from its draft state), and wait for it to be approved and merged into `main`.
1. Go to the repo on GitHub and click on "`<Code>`" and click on right the "`Create a new release`" link.
1. Click on the "`Choose a tag`" combo box and input the new version number as "`vX.Y.Z`", then click on "`Create new tag: X.Y.Z on publish`".
1. Click on the "`Target`" combo box, select the "`Recent commits`" tab and search for the commit checksum for the release PR just merged into `main`.
1. Fill in the release title as "`vX.Y.Z`" (replace "`X.Y.Z`" with the version number being released).
1. Manually enter release notes or click "`Generate release notes`".
1. Attach the `.msi` and `.nupkg` files by dropping them in the "`Attach binaries by dropping them here or selecting them.`" area.
1. Check the "`Set as a pre-release`" checkbox, unless the release is production-signed.
1. Once the uploads are complete (it may take a while), click "`Publish release`".
1. Upload the `.nupkg` file to [nuget.org](nuget.org), and put a markup link to "`.\README.md`" as the description for the package (the metadata inside the `.nuget` package itself will automatically populate all the other form fields).
