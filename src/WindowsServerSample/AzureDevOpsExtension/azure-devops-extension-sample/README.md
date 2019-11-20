# Azure DevOps Web Sample Extension

[![Build Status](https://dev.azure.com/ms/azure-devops-extension-sample/_apis/build/status/Microsoft.azure-devops-extension-sample)](https://dev.azure.com/ms/azure-devops-extension-sample/_build/latest?definitionId=14)

This repository generates an [Azure DevOps extension](https://docs.microsoft.com/en-us/azure/devops/extend/overview?view=vsts) containing a number of different contributions of various types.

## Dependencies

The sample repository depends on a few Azure DevOps packages:

- [azure-devops-extension-sdk](https://github.com/Microsoft/azure-devops-extension-sdk): Required module for Azure DevOps extensions which allows communication between the host page and the extension iframe.
- [azure-devops-extension-api](https://github.com/Microsoft/azure-devops-extension-api): Contains REST client libraries for the various Azure DevOps feature areas.
- [azure-devops-ui](https://developer.microsoft.com/azure-devops): UI library containing the React components used in the Azure DevOps web UI.

Some external dependencies:
- `React` - Is used to render the UI in the samples, and is a dependency of `azure-devops-ui`.
- `TypeScript` - Samples are written in TypeScript and complied to JavaScript
- `SASS` - Extension samples are styled using SASS (which is compiled to CSS and delivered in webpack js bundles).
- `webpack` - Is used to gather dependencies into a single javascript bundle for each sample.

## Building the sample project

Just run:

    npm run build

This produces a .vsix file which can be uploaded to the [Visual Studio Marketplace](https://marketplace.visualstudio.com/azuredevops)

## Using the extension

The preferred way to get started is to use the `tfx extension init` command which will clone from this sample and prompt you for replacement information (like your publisher id). Just run:

    npm install -g tfx-cli
    tfx extension init

You can also clone the sample project and change the `publisher` property in `azure-devops-extension.json` to your own Marketplace publisher id. Refer to the online [documentation](https://docs.microsoft.com/en-us/azure/devops/extend/publish/overview?view=vsts) for setting up your own publisher and publishing an extension.

# Samples

Individual sample contributions are self-contained folders under `./src/Samples`. Within each sample you will find:
1. `{SampleName}.json` - describes the contribution objects being added to Azure DevOps
2. `{SampleName}.html` - page which is rendered within an iframe on the appropriate Azure DevOps page or pages. It may be visible UI (such as a Hub) or a background iframe (such as a Menu action handler). This will include a sample reference for `{SampleName}.js`, and for visible frames it will contain a single `<div>` element with an id of `root`.
3. `{SampleName}.ts(x)` - Root script that is run when the frame is loaded. A webpack entry is added for this file which will generate a single `js` file with this content and all its dependencies.
4. `{SampleName}.scss` - optional sass file containing the styles (CSS) for the UI
5. Additional ts/tsx files - For samples that are too big for one file, the code will be broken up appropriately

## BreadcrumbService

This sample adds a breadcrumb service which adds a "Sample Breadcrumb Item" global breadcrumb item to the sample hub.  Visit the "Sample Hub" in the `Pipelines` hub group to see this item.

## CodeEditorContribution

This sample adds a language definition and a JSON schema for the code editor. 

To see the language definition in action, add a new file to git or TFVC called "sample.mylog", then copy the example log content from [the Monaco playground](https://microsoft.github.io/monaco-editor/playground.html#extending-language-services-custom-languages).

To see the JSON schema in action, add a new file to git or TFVC called "myconfig.json", then begin editing it.

## Feature

This sample shows how to hook into the Preview Features panel (under the user profile menu). It adds a simple hub that is only shown when an "ABC" feature is turned on. The feature can be toggled per-user or per-organization.

This also defines a second feature (ABC v2) which controls whether v1 or v2 of the ABC hub is used (when the ABC feature is turned on). When enabled, a "property-provider" contribution modifies the name and url of the hub contribution. Here we add a v2=true query parameter to our existing hub page, but you could also
specify a completely different html page here. This feature shows off a bit more advanced functionality provided by preview features. It can be toggled per-user, per-project, or per-organization (the "null" hostScopeValue). It is on by default (defaultState: true). And it has an override rule which causes the v2 feature to be OFF (and disabled in the preview features panel) whenever the ABC feature is off.

## Hub

This sample adds a hub named "Sample Hub" into the `Pipelines` hub group. If you visit a project-level page, you will find Sample Hub under the `Pipelines` navigation element in the vertical navigation menu on the left of the page.

The hub uses a Pivot component to draw 4 different tabs:
1. An `Overview` tab contains some simple details about the current user and project
2. A `Navigation` tab contains a few actions that allow you to integrate with the page's URL and title
3. An `Extension Data` tab demonstrates reading and writing to the extension data service
4. A `Messages` tab shows how to display global messages

There are also actions at the top-right of the hub which demonstrate opening dialogs and panels, including custom content within them (used in the `Panel` sample).

## Menu

This sample adds a "Sample build definition menu item" to the `Builds` hub in the dropdown actions menu in the top-right of the page. The menu handler gets the current build definition from the context that is passed to it, it makes a REST call, and shows the result in a message box.

## Panel

This sample is leveraged within the `Hub` sample. It is content that contains a toggle button along with OK/Cancel buttons. It can be used as custom panel or dialog content.

## Pivot

This sample adds a "Sample Pivot" pivot (tab) to the Organization (Project Collection) home page, next to "Projects", "My work items", and "My pull requests".

This pivot makes a REST call for all the projects in the organization and it displays them in a grid view.

## Pill

This sample adds pills to the title of the Pipeline definition (Runs) page.

## RepositoryActions

This sample adds a "Sample repository action" menu item to the repository picker in the header of code hub pages. If a "href" property is provided, clicking on the action will navigate to the given url. If a "uri" is provided, that code will be executed when the action is clicked.

## RepositoryServiceHub

This sample adds a "Repository Information" hub to the `Code` hub group. It demonstrates how to interact with the `IVersionControlRepositoryService` to obtain basic information about a user's currently selected Git repository.

## WorkItemFormGroup

This sample adds a "Sample WorkItem Form Group" extension to workitem form to show how to interact with the `IWorkItemFormService` service and `IWorkItemNotificationListener`. It gives UI to show case how to change field values using the form service and displaying workitem form notification events.

## WorkItemOpen

This sample adds a "Sample WorkItem Open" hub to the Boards hub group to show how to interact with the `IWorkItemFormNavigationService` service. It gives UI for you to open an existing work item (by id) or open the work item form for a new work item (by work item type). Either of these options open a dialog in the host frame.

# References

The full set of documentation for developing extensions can be found at [https://docs.microsoft.com/en-us/azure/devops/extend](https://docs.microsoft.com/en-us/azure/devops/extend/?view=vsts).


# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.