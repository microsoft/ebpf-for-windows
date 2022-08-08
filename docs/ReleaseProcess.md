# Release Process

This file details the steps for creating a versioned release of
eBPF for Windows.

Note: Currently releases are not production signed.

1. Update the version number, making sure to follow [Semantic Versioning 2.0](https://semver.org), in the following two files:
    * .github\workflows\reusable-build.yml
    * tools\nuget\ebpf-for-windows.nuspec
    * scripts\deploy-ebpf.ps1
2. Create a pull request with the version number changes
3. Once the build completes on the PR, download the
   "ebpf-for-windows.msi" and "ebpf-for-windows nuget" build artifacts
   (accessible via the Actions tab on github)
4. Extract the .msi and .nupkg, respectively, out of them
5. Test the MSI manually (since not yet tested in CI/CD):
    1. Copy the MSI into a VM (if not already there)
    2. Install it, and run a command or two (bpftool prog show, netsh eb sh prog) to make sure it's installed
6. Add a tag to the commit with the version number changes
   (e.g., "git tag v0.3.0", "git push --tags")
7. Go to the repo on github and click on "tags" (a bit to the right of the branch combo box)
8. Find the tag you created, and click "..." on the right and "Create release"
9. Start uploading the .msi and .nupkg files
10. Manually enter release notes or click "Generate release notes"
11. Click "This is a pre-release" unless the release is production-signed
12. Once the uploads are complete (it may take a while), click "Publish release"
13. Upload the .nupkg file to nuget.org
