import "es6-promise/auto";
import * as SDK from "azure-devops-extension-sdk";
import { ObservableArray } from "azure-devops-ui/Core/Observable";
import { IContributedPill } from "azure-devops-extension-api";

SDK.register("sample-pill-service", () => {
    const items = new ObservableArray<IContributedPill>([{
        text: "Sample pill #1"
    }]);
    return {
        getPills: (pillGroupId: string, pipelineDetails?: { definitionId: number; definitionName: string; }) => {
            console.log("details: " + JSON.stringify(pipelineDetails));
            window.setTimeout(() => {
                items.push({
                    text: "Delayed pill" + (pipelineDetails ? ` (${pipelineDetails.definitionName})` : ""),
                    color: { red: 255, green: 244, blue: 206 }
                });
            }, 1000);

            return items;
        }
    };
});

SDK.init();