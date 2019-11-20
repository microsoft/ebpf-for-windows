import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IGlobalMessagesService, IHostNavigationService, MessageBannerLevel } from "azure-devops-extension-api";

import { Button } from "azure-devops-ui/Button";
import { ButtonGroup } from "azure-devops-ui/ButtonGroup";
import { Dropdown } from "azure-devops-ui/Dropdown";
import { ListSelection } from "azure-devops-ui/List";
import { IListBoxItem } from "azure-devops-ui/ListBox";

export interface IMessagesTabState {
    messageLevel?: MessageBannerLevel;
    selection: ListSelection;
}

export class MessagesTab extends React.Component<{}, IMessagesTabState> {

    constructor(props: {}) {
        super(props);

        const selection = new ListSelection();
        selection.select(0, 1);

        this.state = {
            messageLevel: MessageBannerLevel.info,
            selection
        };
    }

    public render(): JSX.Element {
        return (
            <div className="page-content page-content-top flex-column rhythm-vertical-16">
                <div className="flex-row flex-center">
                    <label htmlFor="message-level-picker">Message level: </label>
                    <Dropdown<MessageBannerLevel>
                        className="margin-left-8"
                        items={[
                            { id: "info", data: MessageBannerLevel.info, text: "Info"},
                            { id: "error", data: MessageBannerLevel.error, text: "Error"},
                            { id: "Warning", data: MessageBannerLevel.warning, text: "Warning"},
                            { id: "Success", data: MessageBannerLevel.success, text: "Success"}
                        ]}
                        onSelect={this.onMessageLevelChanged}
                        selection={this.state.selection}
                    />
                </div>
                <ButtonGroup>
                    <Button onClick={this.showMessageBanner} text="Show banner" />
                    <Button onClick={this.showMessageBannerWithButtons} text="Show banner with buttons" />
                </ButtonGroup>
                <ButtonGroup>
                    <Button onClick={this.showToast} text="Show toast" />
                </ButtonGroup>
            </div>
        );
    }

    private onMessageLevelChanged = (event: React.SyntheticEvent<HTMLElement>, item: IListBoxItem<MessageBannerLevel>): void => {
        this.setState({ messageLevel: item.data });
    }

    private showMessageBanner = async (): Promise<void> => {

        const { messageLevel } = this.state;

        const globalMessagesSvc = await SDK.getService<IGlobalMessagesService>(CommonServiceIds.GlobalMessagesService);
        globalMessagesSvc.addBanner({
            level: messageLevel,
            messageFormat: "This is a message from the sample extension. {0}",
            messageLinks: [{
                name: "Learn more",
                href: "https://docs.microsoft.com/en-us/azure/devops/extend/get-started/node"
            }]
        });
    }

    private showMessageBannerWithButtons = async (): Promise<void> => {

        const { messageLevel } = this.state;

        const globalMessagesSvc = await SDK.getService<IGlobalMessagesService>(CommonServiceIds.GlobalMessagesService);
        globalMessagesSvc.addBanner({
            dismissable: false,
            customIcon: "LightningBolt",
            level: messageLevel,
            message: "Some action needs to be performed. Do you wish to perform the action now?",
            buttons: [
                {
                    text: "Yes",
                    command: SDK.getExtensionContext().id + ".sample-service-yes-command",
                    commandArguments: [ "test1" ]
                },
                {
                    text: "No",
                    command: SDK.getExtensionContext().id + ".sample-service-no-command",
                    commandArguments: [ "test2" ]
                }
            ],
            helpInfo: {
                href: "https://www.microsoft.com",
                tooltip: "This tooltip can display more information about this action..."
            }
        });
    }

    private showToast = async (): Promise<void> => {

        const globalMessagesSvc = await SDK.getService<IGlobalMessagesService>(CommonServiceIds.GlobalMessagesService);
        globalMessagesSvc.addToast({
            callToAction: "Lean more",
            duration: 3000,
            message: "This is a toast from an extension",
            onCallToActionClick: async () => {
                const navService = await SDK.getService<IHostNavigationService>(CommonServiceIds.HostNavigationService);
                navService.openNewWindow("https://docs.microsoft.com/en-us/azure/devops/extend/get-started/node", "");
            }
        });
    }
}