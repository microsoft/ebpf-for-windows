# HLK Testing for eBPF for Windows

## Pre-requisites and resources

Firstly, go through these steps:

- Setup your account on the ESRP portal, by watching [these videos](https://microsoft.sharepoint.com/teams/prss/Codesign/SitePages/MODS.aspx) first!
- [Signing drivers, and driver packages for submission to HDC - OSGWiki](https://www.osgwiki.com/wiki/Signing_drivers,_and_driver_packages_for_submission_to_HDC)

    >NOTE: to verify you have the right access (takes 1 or 2 days to process the submission), you should see the `Hardware` tile on your [HDC Dashboard](https://partner.microsoft.com/en-us/dashboard/home), and on the [My access](https://partner.microsoft.com/en-us/dashboard/account/v3/myaccess) tab, you should see the `Hardware` feature in the list with `Access granted` status, with the message *"You have access to this workspace. To get any additional access, contact your organization's admin*".
- [Requesting access to Hardware Dev Center - OSGWiki](https://www.osgwiki.com/wiki/Requesting_access_to_Hardware_Dev_Center)
- [Partner Center for Windows Hardware - Windows drivers | Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/?redirectedfrom=MSDN)

Official instructions for HLK testing:

- [Windows HLK Getting Started](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/getstarted/windows-hlk-getting-started)
- [Windows HLK Prerequisites](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/getstarted/windows-hlk-prerequisites)
- [Internal OneNote](https://microsoft.sharepoint.com/teams/STACKTeam-CoreNetworkingMobileConnectivityPeripheralsStackSe/_layouts/15/Doc.aspx?sourcedoc={e5f3987d-f4e8-4007-982c-c6d70061bb25}&action=edit&wd=target%28Automation.one%7C941bd9af-f699-4939-a157-d9c625bcaf53%2FHLK%7C7cb32c20-e285-4335-a63e-9a80c2a8fca3%2F%29&wdorigin=NavigationUrl) (with legacy notes)

## HLK Controller setup

Firstly, select the right VHLK for the Controller to use based on the target system that you want to certify your drivers on, as indicated [here](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/).

- [HLK-Controller(W10-1809) for certifying WS2019](https://go.microsoft.com/fwlink/p/?linkid=2195154&clcid=0x409&culture=en-us&country=us): WIN-7T3Q115F1KT
- [HLK-Controller(WS2022) for certifying WS2022](https://go.microsoft.com/fwlink/p/?linkid=2195153&clcid=0x409&culture=en-us&country=us): WIN-E4K8S4S8SV2
- Controllers have the following pre-built credentials: `HLKAdminUser`/`Testpassword,1`.
- Download the playlist file from [here](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/), unzip it and copy the related playlist file to the Controller:
  - Windows Server 2019: [`.\2019\HLK Version 1809 CompatPlaylist x64 Server.xml`](.\2019\HLK%20Version%201809%20CompatPlaylist%20x64%20Server.xml)
  - Windows Server 2022: [`.\2022\HLK Version 21H2 CompatPlaylist x64 ARM64 server.xml`](.\2022\HLK%20Version%2021H2%20CompatPlaylist%20x64%20ARM64%20server.xml)

Setup the VMs as follows:

- Select `"Generation 1"`.
- Use the downloaded VHLK as virtual hard disk for the VM.
- Use 4096GB RAM and at least 2 virtual processors.
- As network adapter, use the `"Default Switch"` (or create one to be used by both the Controller and the Client).

## HLK Client setup

Like for the Controller, select the right VHD image for the Client to use based on the target system that you want to certify your drivers on, e.g.:

- Windows Server 2019: \\winbuilds\release\rs5_release_svc_asdb_prod1\17763.11385.230323-1842\amd64fre\vhd\vhd_server_serverdatacenter_en-us_vl
- Windows Server 2022: \\winbuilds\release\fe_release_svc_prod1\20348.1667.230327-1739\amd64fre\vhd\vhd_server_serverdatacenter_en-us_vl

Setup the VMs as follows:

- Select `"Generation 1"`.
- Use 4096GB RAM and at least 2 virtual processors.
- As network adapter, use the `"Default Switch"` (or create one to be used by both the Controller and the Client).

>NOTE: from now on, the client machines names will be referred as follows (from existing HLK VM labs):
>
> - Windows Server 2019: `WIN-7T3Q115F1KT`
> - Windows Server 2022: `WIN-E4K8S4S8SV2`

Also, make sure to set the following:

- *It is recommended that the client system is on A/C (plugged in) and that the Power Options are set to Never for Put the computer to sleep settings.*  (from the official HLK documentation linked above).
- Secure Boot must be disabled - [Disabling Secure Boot | Microsoft Docs](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/disabling-secure-boot?view=windows-11).
- Make sure to turn **On** `"File and printer sharing"` from `Network and Sharing Center -> Change advanced sharing settings`.

Then, boot up the client VM and follow these steps:

- Enable test-mode with the following command, then reboot the machine:

    ```bash
    bcdedit /set testsigning on
    shutdown /r -t 0
    ```

- Create a new `"HLKAdminUser"` user with password `"Testpassword,1"` and add it to the `Administrators` group.
- Install the eBPF drivers to be tested, using the MSI from the "`regular_native_only NativeOnlyRelease`" build, with *all* the options enabled.
- Query if the eBPF drivers are running, e.g.:

    ```bash
    >sc.exe query eBPFCore

    SERVICE_NAME: eBPFCore
            TYPE               : 1  KERNEL_DRIVER
            STATE              : 4  RUNNING
                                    (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x0
            WAIT_HINT          : 0x0

    >sc.exe query NetEbpfExt

    SERVICE_NAME: NetEbpfExt
            TYPE               : 1  KERNEL_DRIVER
            STATE              : 4  RUNNING
                                    (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
            WIN32_EXIT_CODE    : 0  (0x0)
            SERVICE_EXIT_CODE  : 0  (0x0)
            CHECKPOINT         : 0x0
            WAIT_HINT          : 0x0
    ```

    If not, start the drivers, e.g.:

    ```bash
    net start eBPFCore
    net start NetEbpfExt
    ```

- (Optional) Load any eBPF program that will be bundled as a native `.sys` file, e.g.:

    ```bash
    netsh ebpf add program printk.sys
    netsh ebpf add program redirect.bpf.sys
    
    # Both commands should return: The program was successfully added, e.g.:    
    Loaded with ID 393217
    ```

- The eBPF drivers to be tested MUST be installed **before** the HLK Client is installed.
  - If the eBPF drivers need to be updated:
    - From the HLK Studio on the Controller, set the target machine to `"Not Ready"` before doing any action on the client.
    - On the Client, reinstall the eBPF drivers.
    - On the Client, restart the `"HLK Communication Service"` service from the *Services* tab in the *Windows Task manager*.
    - From the HLK Studio on the Controller, set the target machine to `"Ready"`.
- Due to some HLK issues (as of this writing), install the HLK Client MSI, (*not* the `Setup.cmd` as documented online), e.g.:
  - Windows Server 2019: `\\WIN-7T3Q115F1KT\HLKInstall\Client\Setupamd64.msi`
  - Windows Server 2022: `\\WIN-E4K8S4S8SV2\HLKInstall\Client\Setupamd64.msi`

## Running the HLK tests

From the HLK Controller, open the HLK Studio, and follow these steps:

- Complete step #3-only, from here: [Step 3: Create a machine pool (step-3-create-a-machine-pool)](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/getstarted/step-3-create-a-machine-pool)

On HLK Studio, navigate sequentially to the following tabs:

- **Configuration** (menu' at the top of the window)
  - Set the machine status to `"Ready"` (TIP: sometimes the automatic refresh does not work, select something else then re-select the machine pool).
  - Once the Client is in the `"Ready"` status, move the test system from the `"Default Pool"` into the new pool (e.g., `"eBPF pool"`) by first selecting it and then dragging it onto the newly-created pool.

    >NOTE: If the machine fails to go in the `"Ready"` status (eventually with the below error), you can try to reboot the HLK Controller, and/or restart the `"HLK Communication Service"` service from the *Services* tab in the *Windows Task manager*.
    >
    >![HLK Studio connection error](.\images\Connection_error.png)

- **Project**
  - Create a new project, e.g. `"eBPF HLK - WS2022"`, or load an existing one by double-clicking on it.
  - When setting up the HLK project needed to run the tests, **do not** check the checkbox named `Windows Driver Project`.

- **Selection**
  - Select the machine pool (i.e. `"eBPF pool"`) from the combo box at the top of the window.
  - Select `"software device"` on the left list, search for the drivers to be tested, i.e.:
    - `NETEBPFEXT.SYS`
    - `EBPFCORE.SYS`
    - `PRINTK.SYS` (optional)
    - `REDIRECT.EBPF.SYS` (optional, for IMDS)
  - Once done, click on `"show selected"` to see the list of selected drivers.

- **Tests**
  - Click on `"Load Playlist"`, to load the playlist file for the target system (to download the full playlist file, see [Download Windows Hardware Compatibility playlist](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/#download-windows-hardware-compatibility-playlist)):

    - WS2019: [`HLK Version 1809 CompatPlaylist x64 Server.xml`](.\policies\2019\HLK%20Version%201809%20CompatPlaylist%20x64%20Server.xml)
    - WS2022: [`HLK Version 21H2 CompatPlaylist x64 ARM64 server.xml`](.\policies\2022\HLK%20Version%2021H2%20CompatPlaylist%20x64%20ARM64%20server.xml)

  - Select *ALL* the tests, then click on `"Run Selected"`
        >NOTE: You can use `HLK Manager` to monitor the tests, from `"Explorers"->"Job Monitor"`.

  - **Notes on the test execution**
        Unfortunately, the tests that have a "person" icon next to them, are not unattended tests, therefore, they need to be assisted manually upon prompts. This is the list of interactions **on the HLK Client** that were found so far, as of eBPF v0.10.0 (typically, in the following order):

    - `"Hardware-enforced Stack Protection Compatibility"`: answer `"Y"` for "Yes", as the solution is built with `<CETCompat>true</CETCompat>` (see [here](https://github.com/microsoft/ebpf-for-windows/blob/3f3b834c2fa85a57559135b6bfd4e48dae7cf4a2/Directory.Build.props#L51)).

        ![Hardware-enforced Stack Protection Compatibility](.\images\Hardware-enforced_Stack_Protection_Compatibility_Test.png)

    - `"TransitionTechnologies_Tests"`: acknowledge all prompts by clicking `"OK` on the dialog box prompts that will appear during each individual test of this group.

    - `"WindowsFilteringPlatform_Tests"`: will prompt for filling in a "WFPLogo.Info" file within Notepad, and then save it. The file is already precompiled for the `NetEbpfExt.sys` driver, which is the subject of this test, and is located within the same folder of this documentation ([.\test_data\WFPLogo.Info](.\test_data\WFPLogo.Info)), so just copy-paste its contents into the open Notepad window, **save it (!!)** then click `OK` on the prompt.
        There will be a few more prompts, just click `"OK` on the dialog box prompts that will appear during the tests.

        ![WFPLogo.Info](.\images\WFPLogoInfo.png)

        >NOTE: To view the tests running on the client (and therefore their prompts), you must login as the `"DTMLLUAdminUser"` user, same test password. Many times the HLK Client will reboot, and therefore you must reconnect and login (with the aforementioned user) each time you expect a manual interaction from the current test being run by the HLK Controller.

- **Results**
    On this page, you can see the results of the tests which must all succeeded, besides a few that might fail, but for which there is an official "Errata". The erratas applicable to the tests run so far for eBPF (mainly for the WPF-related tests), are available in the [`"Errata"` subfolder](.\errata) of this documentation.

    The errata documents **MUST** be included in the HLKX package, as described in the next step.

    Just as an example, here below are the results of the tests run on the HLK Client for eBPF v0.10.0, on *Windows Server 2019* and *Windows Server 2022*, the latter with an errata applied to the `"AppContainer_Tests"` test failure, as described in [WS2022 - AppContainer_Tests errata.docx](.\errata\WS20222%20-%20AppContainer_Tests%20errata.docx):

    ![Windows Server 2019](.\images\WS2019_Results.png)

    ![Windows Server 2022](.\images\WS2022_Results.png)

- **Packaging** (Ref: [Step 8: Create a submission package](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/getstarted/step-8-create-a-submission-package))
  - Copy the drivers + INF files that were tested on the HLK Client, in a folder on the Controller.
  - Provide the `"Driver Folder"` by clicking on `"Add Driver Folder"`:
    - Select the folder from the previous step, and then select all the drivers on the `"Product` tab, then the local (i.e. `English`) on the `"Locales"` tab.
  - Provide errata documents in the `"Supplemental folder"` option, where you should have previously stored all the applicable errata documents for the tests that failed.
  - **IMPORTANT**: If you have multiple `.hlkx` log files (aka "HLKX packages") from multiple systems (i.e. HLK Controllers), you **MUST** merge them into a single HLKX file. This must be done from *"a"* HLK Controller of your choice (e.g. rule of thumb can be using the one with the latest OS being tested, i.e. WS2022 in this doc's context), and by clicking on `"Merge Package"` from the `"Results"`, and select `"Add"` for each one of them (you will see them being listed under the `"Drivers Folder"`). T
  - Click on `"Create Package"`, and chose `"Do not sign"` on the `"Signing Options"` dialog box.
  - The HLKX package will be created in the provided folder.

## Signing a release for production

### Signing the User-Mode binaries

- **[One-time operation]** Create a new `Sign Operation` in the [ESRP Portal](https://portal.esrp.microsoft.com/), by adding ["`CP-230012`" ,"`SigntoolSign`"] and ["`CP-230012`", "`SigntoolVerify`"]. Here is a screenshot of how the  `"Operation Details"` should look like:

    ![](.\images\Operation_Details_UM.png)

- Create a new request in [ESRP Portal](https://portal.esrp.microsoft.com/):
  - Select the `"MANUAL SIGN"` tab from the left menu, then `"Sign Request"` from the drop menu.
  - Select `"New Request"` and fill in the fields:
    - `Description`: e.g., `"eBPF for Windows v0.11.0 - User-mode binaries"`
    - `Sign Operation`: e.g., `"eBPF Signing - User-mode Binaries"` (created as described above).
    - `Approvers`: you need 2 reviewers to approve your manual submission (they can be from your same Team).
    - Click on `"Browse file"` and upload all the user-mode binaries that need to be signed.
    - Click on `"Submit"`.
- Once approved, the signed binaries will be available to download, within the request page in the ESRP Portal.

    Here is a screenshot of how a request should look like:

    ![](.\images\Sign_Request_UM.png)

### Signing the HLKX package

Ref. docs: [Create a new hardware submission](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-submission-create)
>NOTE: Make sure you submit the **merged `.hlkx` package** for manual signing.

- **[One-time operation]**Create a new `Sign Operation` in the [ESRP Portal](https://portal.esrp.microsoft.com/), by following the below instructions: ["Signing drivers, and driver packages for submission to HDC - OSGWiki"](https://www.osgwiki.com/wiki/Signing_drivers,_and_driver_packages_for_submission_to_HDC).

    Here is a screenshot of how the  `"Operation Details"` should look like:

    ![](.\images\Operation_Details_HLKX.png)

- Create a new request in [ESRP Portal](https://portal.esrp.microsoft.com/):
  - Select the `"MANUAL SIGN"` tab from the left menu, then `"Sign Request"` from the drop menu.
  - Select `"New Request"` and fill in the fields:
    - `Description`: e.g., `"eBPF for Windows v0.10.0 - HLK package"`
    - `Sign Operation`: e.g., `"eBPF Signing - HLKX packages"` (created from the steps in the OSGWiki page linked above).
    - `Approvers`: you need 2 reviewers to approve your manual submission (they can be from your same Team).
    - Click on `"Browse file"` and upload the combined HLKX package to be signed.
    - Click on `"Submit"`.
- Once approved, the signed HLKX package will be available to download, within the request page in the ESRP Portal.

    Here is a screenshot of how a request should look like:

    ![](.\images\Sign_Request_HLKX.png)

#### Submitting the HLKX package to HDC for driver signing

- Go to your [HDC Dashboard](https://partner.microsoft.com/en-us/dashboard/home).

- Click on the `Hardware` tile and then on `Create a new submission`:

    ![](.\images\HDC-Hardware_button.png)

- Click on the `Submit the Hardware` button:

    ![](.\images\HDC-Submit_new_hw.png)

- Fill in the "`Product name`" and drop your ESRP-signed HLKX package in the underlying area:

    ![](.\images\HDC-Upload-hklx.png)

- Once approved, download the production-signed HLKX package, inside which you will find the prod-signed eBPF drivers, to be packaged as required:

    ![](.\images\HDC-Download-hklx.png)
