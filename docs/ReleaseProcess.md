# Release Process

This file details the steps for creating a versioned release of
eBPF for Windows.

Note: Currently releases are not production signed.

1. Update the version number, making sure to follow [Semantic Versioning 2.0](https://semver.org), in the following files:
    * resource\ebpf_version.h
    * installer\Product.wxs (in the XML attribute `<Wix... <Product... Version="x.y.z" ...>...>`)
    * docs\tutorial.md
2. Regenerate the expected bpf2c output:
    ``` .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\```
   and (until issue #2026 is fixed) manually update:
    * .\tests\bpf2c_tests\expected\bpf_{dll,raw,sys}.c
    * .\tests\bpf2c_tests\expected\empty_{dll,raw,sys}.c
3. Create a pull request with the version number changes
4. Once the build completes on the PR, download the
   "ebpf-for-windows.msi" and "ebpf-for-windows nuget" build artifacts
   (accessible via the Actions tab on github)
5. Extract the .msi and .nupkg, respectively, out of them
6. Test the MSI manually (since not yet tested in CI/CD):
    1. Copy the MSI into a VM (if not already there)
    2. Install it, and run a command or two (bpftool prog show, netsh eb sh prog) to make sure it's installed
7. Add a tag to the commit with the version number changes
   (e.g., "git tag v0.3.0", "git push --tags")
8. Go to the repo on github and click on "tags" (a bit to the right of the branch combo box)
9. Find the tag you created, and click "..." on the right and "Create release"
10. Start uploading the .msi and .nupkg files
11. Manually enter release notes or click "Generate release notes"
12. Click "This is a pre-release" unless the release is production-signed
13. Once the uploads are complete (it may take a while), click "Publish release"
14. Upload the .nupkg file to nuget.org
