import "es6-promise/auto";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IGlobalMessagesService, IHostPageLayoutService } from "azure-devops-extension-api";

SDK.register("SampleCommandService", () => {
    async function runCommand(commandName: string, testArgument: string) {
        const dialogService = await SDK.getService<IHostPageLayoutService>(CommonServiceIds.HostPageLayoutService);
        dialogService.openMessageDialog(`Running the ${commandName} command for ${testArgument}`, {
            showCancel: false,
            title: "Running test command",
            okText: "Close",
            onClose: async () => {
                const messagesService = await SDK.getService<IGlobalMessagesService>(CommonServiceIds.GlobalMessagesService);
                messagesService.closeBanner();
            }
        });
    }
    return {
        yesCommand: async (testArgument: string) => {
            runCommand("Yes", testArgument);
        },
        noCommand: async (testArgument: string) => {
            runCommand("No", testArgument);
        }
    }
});

SDK.init();