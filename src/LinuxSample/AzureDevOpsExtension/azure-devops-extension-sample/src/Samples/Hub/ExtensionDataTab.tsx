import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IExtensionDataManager, IExtensionDataService } from "azure-devops-extension-api";

import { Button } from "azure-devops-ui/Button";
import { TextField } from "azure-devops-ui/TextField";

export interface IExtensionDataState {
    dataText?: string;
    persistedText?: string;
    ready?: boolean;
}

export class ExtensionDataTab extends React.Component<{}, IExtensionDataState> {

    private _dataManager?: IExtensionDataManager;

    constructor(props: {}) {
        super(props);
        this.state = {};
    }

    public componentDidMount() {
        this.initializeState();
    }

    private async initializeState(): Promise<void> {
        await SDK.ready();
        const accessToken = await SDK.getAccessToken();
        const extDataService = await SDK.getService<IExtensionDataService>(CommonServiceIds.ExtensionDataService);
        this._dataManager = await extDataService.getExtensionDataManager(SDK.getExtensionContext().id, accessToken);

        this._dataManager.getValue<string>("test-id").then((data) => {
            this.setState({
                dataText: data,
                persistedText: data,
                ready: true
            });
        }, () => {
            this.setState({
                dataText: "",
                ready: true
            });
        });
    }

    public render(): JSX.Element {
        const { dataText, ready, persistedText } = this.state;

        return (
            <div className="page-content page-content-top flex-row rhythm-horizontal-16">
                <TextField
                    value={dataText}
                    onChange={this.onTextValueChanged}
                    disabled={!ready}
                />
                <Button
                    text="Save"
                    primary={true}
                    onClick={this.onSaveData}
                    disabled={!ready || dataText === persistedText}
                />
            </div>
        );
    }

    private onTextValueChanged = (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>, value: string): void => {
        this.setState({ dataText: value });
    }

    private onSaveData = (): void => {
        const { dataText } = this.state;
        this.setState({ ready: false });
        this._dataManager!.setValue<string>("test-id", dataText || "").then(() => {
            this.setState({
                ready: true,
                persistedText: dataText
            });
        });
    }
}