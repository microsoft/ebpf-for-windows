import "es6-promise/auto";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, getClient, IHostPageLayoutService } from "azure-devops-extension-api";
import { BuildDefinition, BuildRestClient } from "azure-devops-extension-api/Build";

SDK.register("sample-build-menu", () => {
    return {
        execute: async (context: BuildDefinition) => {
            const result = await getClient(BuildRestClient).getDefinition(context.project.id, context.id, undefined, undefined, undefined, true);
            const dialogSvc = await SDK.getService<IHostPageLayoutService>(CommonServiceIds.HostPageLayoutService);
            dialogSvc.openMessageDialog(`Fetched build definition ${result.name}. Latest build: ${JSON.stringify(result.latestBuild)}`, { showCancel: false });
        }
    }
});

SDK.init();