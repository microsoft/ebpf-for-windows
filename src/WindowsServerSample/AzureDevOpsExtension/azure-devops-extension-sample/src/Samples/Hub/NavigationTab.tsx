import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IHostNavigationService } from "azure-devops-extension-api";

import { Button } from "azure-devops-ui/Button";
import { ButtonGroup } from "azure-devops-ui/ButtonGroup";

export interface INavigationTabState {
    currentHash?: string;
    currentQueryParams?: string;
}

export class NavigationTab extends React.Component<{}, INavigationTabState> {

    constructor(props: {}) {
        super(props);
        this.state = {};
    }

    public componentDidMount() {
        this.initialize();
    }

    public render(): JSX.Element {
        const { currentHash, currentQueryParams } = this.state;
        return (
            <div className="page-content page-content-top flex-column rhythm-vertical-16">
                {
                    currentQueryParams &&
                    <div>Current query params: {currentQueryParams}</div>
                }
                {
                    currentHash &&
                    <div>Current hash: {currentHash}</div>
                }
                <ButtonGroup>
                    <Button text="Get QueryParams" primary={true} onClick={this.onGetQueryParamsClick} />
                    <Button text="Update QueryParams" onClick={this.onUpdateQueryParamsClick} />
                </ButtonGroup>
                <ButtonGroup>
                    <Button text="Get Hash" onClick={this.onGetHashClick} />
                    <Button text="Update hash" onClick={this.onUpdateHashClick} />
                </ButtonGroup>
                <ButtonGroup>
                    <Button text="Update document title" onClick={this.onUpdateDocumentTitle} />
                </ButtonGroup>
            </div>
        );
    }

    private async initialize() {
        const navigationService = await SDK.getService<IHostNavigationService>(CommonServiceIds.HostNavigationService);
        navigationService.onHashChanged((hash: string) => {
            this.setState({ currentHash: hash });
        });
    }

    private onGetHashClick = async (): Promise<void> => {
        const navService = await SDK.getService<IHostNavigationService>(CommonServiceIds.HostNavigationService);
        const hash = await navService.getHash();
        this.setState({ currentHash: hash });
    }

    private onUpdateHashClick = async (): Promise<void> => {
        const navService = await SDK.getService<IHostNavigationService>(CommonServiceIds.HostNavigationService);
        navService.setHash("time=" + new Date().getTime());
    }

    private onGetQueryParamsClick = async (): Promise<void> => {
        const navService = await SDK.getService<IHostNavigationService>(CommonServiceIds.HostNavigationService);
        const hash = await navService.getQueryParams();
        this.setState({ currentQueryParams: JSON.stringify(hash) });
    }

    private onUpdateQueryParamsClick = async (): Promise<void> => {
        const navService = await SDK.getService<IHostNavigationService>(CommonServiceIds.HostNavigationService);
        navService.setQueryParams({ time: "" + new Date().getTime()});
    }

    private onUpdateDocumentTitle = async (): Promise<void> => {
        const navService = await SDK.getService<IHostNavigationService>(CommonServiceIds.HostNavigationService);
        navService.setDocumentTitle("Sample hub new title: " + new Date().getTime());
    }
}