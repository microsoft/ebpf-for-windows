# Releasing the eBPF Redistributable NuGet Package

## Retrieving the eBPF binaries to be signed

1. Download the latest build artifacts for the "`regular_native_only NativeOnlyRelease`" build from the [Azure DevOps CICD pipeline](https://mscodehub.visualstudio.com/eBPFForWindows/_build?definitionId=2094&_a=summary), related to the release branch you want to publish, and extract them to a local folder.

1. Make sure to **retain the CICD run**, by clicking on upper-right three vertical dots ("..."), and selecting "*Retain*", so that the build artifacts are not deleted after a configured number days.

1. From the extracted folder, copy the `eBPF-for-Windows-Redist.X.Y.Z.nupkg` file to a working directory of your choice, and unzip its contents to a sub folder named `eBPF-for-Windows-Redist.X.Y.Z` (you can use [7-Zip](https://www.7-zip.org/) file manager to directly open the NuGet package as a ZIP archive).

1. From within the `eBPF-for-Windows-Redist.X.Y.Z\package\bin` folder, copy following list of binaries to a separate working directory, for them to be signed. **This folder should have strict ACLs**, and typically would be a shared folder on the network, accessible by the signing team:

    - `Bpftool.exe`
    - `Ebpfapi.dll`
    - `Ebpfnetsh.dll`
    - `drivers\ebpfcore.sys`
    - `drivers\netebpfext.sys`
    - `drivers\printk.sys` (if needed, this can be copied from the `regular_native-only Release` build artifacts, as it is not included in the NuGet package)
    
    **Special cases** (binaries that are not included in the NuGet package, but that we offer to sign for internal customers):

    - `drivers\redirect.bpf.sys` (i.e., supplied by IMDS)

## Repackaging the signed eBPF binaries

Once the binaries have been signed, they need to be repackaged into a new NuGet package, which will be published to the [eBPF internal NuGet feed](https://mscodehub.visualstudio.com/eBPFForWindows/_artifacts/feed/eBPFForWindows).
To do this, follow these steps:

1. Copy (overwriting) all the files from the working directory where the signed binaries are located, into the `eBPF-for-Windows-Redist.X.Y.Z\package\bin` folder, respecting the sub folders from which they were copied from (i.e. the drivers should be placed into the `drivers` sub folder).

1. Repackage the `eBPF-for-Windows-Redist.X.Y.Z` folder into a new NuGet package, by simply zipping the entire **content** of folder back into a ZIP archive, and renaming the archive to `eBPF-for-Windows-Redist.X.Y.Z.nupkg`.


## Publishing the eBPF Redistributable NuGet package

>**IMPORTANT**: be mindful **before** publishing the package, as once it is published, **the version number cannot be re-used (!!)**, nor the package updated with another version of the binaries. If you need to update the package, you will need to increment the version number, and publish a new package.

Ensure you have the rights to access the [eBPF internal NuGet feed](https://mscodehub.visualstudio.com/eBPFForWindows/_artifacts/feed/eBPFForWindows). In case not, please contact the [Edge OS eBPF v-team](edgeosebpf@microsoft.com) to request membership to the `redmond\ebpfforwindows` Security Group.

From the working directory where the new `eBPF-for-Windows-Redist.X.Y.Z.nupkg` package (containing the signed binaries) is located, run the following command to publish the new NuGet package to the [eBPF internal NuGet feed](https://mscodehub.visualstudio.com/eBPFForWindows/_artifacts/feed/eBPFForWindows):

```
nuget.exe push eBPF-for-Windows-Redist.X.Y.Z.nupkg -Source https://mscodehub.pkgs.visualstudio.com/eBPFForWindows/_packaging/eBPFForWindows/nuget/v3/index.json -ApiKey eBPF
```

## Test the eBPF Redistributable NuGet package download

From the working directory where the signed binaries are located, run the following command to test the new NuGet package:

```cmd
nuget.exe install eBPF-for-Windows-Redist -version X.Y.Z -Source https://mscodehub.pkgs.visualstudio.com/eBPFForWindows/_packaging/eBPFForWindows/nuget/v3/index.json
```