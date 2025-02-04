# Background
The driver tests utilize a 1ES hosted pool for execution. This document details information about
the setup and how to update it.

Note that this configuration relies on Azure resources that only Microsoft employees have access
to. If any changes are required, please raise issues in the weekly triage meeting.

# Architecture
The tests execute on a 1ES runner machine. This machine is an Azure VM, which has been configured
with our setup scripts. The setup scripts create an inner VM with a particular OS image to execute
the tests on. By using this nested VM structure, we are able to extract crash dumps and logs from
any failures.

# Azure Resources
All of the azure resources are stored in the `ebpf-cicd-rg` resource group in the
`CoreOS_LIOF_eBPF_for_Windows_Dev` subscription.

The current set of pools and images are as follows:
- Pool: `ebpf-cicd-runner-pool-server-2019`:
  - Images:
    - `server2025`

# Image Creation and Update
The following sections explain how one can make changes to the 1ES runner image, including
onboarding a new OS version or updating the runner configuration scripts.

## Image Creation Scripts
This repo holds a few scripts that are used for configuring the 1ES runners. The scripts are
currently stored in the `1ES` and `scripts` directories. A build artifact called `1ES Artifacts`
also gets populated, which holds the unified set of scripts that can be copied to the Azure
Storage Blob.

### Scripts:
- `Setup.ps1` - This script is executed on the 1ES runner at image creation time to prepare the VM.
Notably, this includes creating the inner VM and running an initial configuration script on it.
- `configure_vm.ps1` - This script is invoked by `Setup.ps1` and executes within the inner VM to
configure any necessary state on it.
- `prepare_1es_artifacts.ps1` -  This script is invoked by the build pipeline to package together
all necessary scripts.
- `artifacts.json` - This holds the artifacts that must be configured in the 1ES image. This file
itself contains placeholder text, which `prepare_1es_artifacts.ps1` updates in the produced build
artifacts.
- `scripts\common.psm1` - This holds some common helper functions that the runtime tests also
utilize. It is used by `Setup.ps1`.
- `scripts\config_test_vm.psm1` - This holds some common helper functions that the runtime tests
also utilize, focusing on functionality related to the inner VM. It is used by `Setup.ps1`

## Creating a New Image
The following steps can be used to onboard a new test image:
- Create a new azure storage blob container within the `ebpfcicdstorage` storage account.
- Update the `prepare_1es_artifacts.ps1` script with the new storage blob name.
- Upload files from the `1ES Artifacts` build artifact into the storage blob.
- Upload a `.zip` file containing the `.vhd` file containing the base OS image to be used in the
inner VM.
- Using the Azure Portal, give the `Storage Blob Data Reader` permission to
`1ES Resource Management` Service Principal for this storage blob container.
- Using the Azure Portal, create the 1ES image. Use the following parameters:
```
-Resource Group - ebpf-cicd-rg
-Region - West US 2
-Image Type - Define a custom image(1ES Managed)
-Image - WindowsServer 2022-datacenter-g2
-Artifacts - This must be non-empty, but will be overwritten in subsequent steps below.
Initially, this utilize the subset of tasks that do not require the managed identity, i.e:
{
    "artifacts": [
        {
            "name": "windows-enabledismfeature",
            "parameters": {
                "FeatureName": "Microsoft-Hyper-V"
            }
        },
        {
            "name": "windows-enabledismfeature",
            "parameters": {
                "FeatureName": "Microsoft-Hyper-V-Management-PowerShell"
            }
        },
        {
            "name": "windows-restart"
        }
    ]
}
-Advanced > Enable Trusted Launch (Make sure it is enabled)
```
- Wait for the image creation to complete.
- Follow the steps in the `Updating an Existing Image` section in this document to add the managed
identity and script execution to build the runner VM in this image.
- Once the image has been successfully created, navigate to the `1ES Hosted Pool`, and in the
`Pool` section, update the `Images` to add the newly created image.
- Follow the steps in the `Onboarding a TEst to Utilize 1ES Runner` section in this document to
configure a test to utilize the runner.
- Test by queueing a CICD run, and observe that the test runs successfully. The `pre-test` command
outputs the build image of the inner VM that the test executes on. This should be validated to
ensure that the test is actually running on the expected VM image.

## Updating an Existing Image
The following steps can be used to update the Image.
- Make any script changes as necessary to the files in the ebpf-for-windows Github repo.
- Navigate to the appropriate storage blob container for this image and update the scripts in the
appropriate storage container.
- Navigate to the 1ES image in the Azure portal. Under `Identity` add the `ebpf-cicd-identity` if
not already added.
- Ensure the image Artifact is up to date (i.e consistent with the artifact.json that is generated
in the `1ES Artifacts` build artifact). Note that the build artifact produces a unique
`artifact.json` file for each image, which notably contains the updated storage blob name.
- Click `apply`. Look under `Monitoring` and `Image Logs` to look for any errors in image creation.
- Ensure that any script changes are checked in to the ebpf-for-windows Github repo, to ensure that
all build images continue to use the same set of scripts.

## Onboarding a Test to Utilize 1ES Runner
- In the `cicd.yml`, set the `envrionment` parameter:
```
Set the pool and image name:
    environment: '["self-hosted", "1ES.Pool=<POOL_NAME>", "1ES.ImageOverride=<IMAGE_NAME>"]'
For example:
    environment:
        '[
            "self-hosted",
            "1ES.Pool=ebpf-cicd-runner-pool-server-2019",
            "1ES.ImageOverride=server2025"
        ]'
```

The changes in `reusable-test.yml` have been made once as part of onboarding our repo to utilize
1ES runners. This section is noted here to help guide any future changes in this area. The following
has been done:
- The `runs_on` parameter is set (notably using the `self-hosted` tag, along with the `1ES.Pool`
and `1ES.ImageOverride` values as specified in the specific testcase)
- A new task for the pre, run, and post test jobs were added. Notably, this passes a fixed
`-SelfHostedRunnerName '1ESRunner'` value. This is done to give a predictable name, instead of the
dynamic name which may change whenver a new 1ES image is used.
- Existing tests were updated to use `contains(inputs.environment, '1ES')` as an indicator that the
job is using the 1ES runner (and negation of this condition to indicate it is not using the 1ES runner).