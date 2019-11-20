import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { CommonServiceIds, IProjectPageService, IHostNavigationService, INavigationElement, IPageRoute } from "azure-devops-extension-api";

export interface IOverviewTabState {
    userName?: string;
    projectName?: string;
    iframeUrl?: string;
    extensionData?: string;
    extensionContext?: SDK.IExtensionContext;
    host?: SDK.IHostContext;
    navElements?: INavigationElement[];
    route?: IPageRoute;
}

export class OverviewTab extends React.Component<{}, IOverviewTabState> {

    constructor(props: {}) {
        super(props);

        this.state = {
            iframeUrl: window.location.href
        };
    }

    public componentDidMount() {
        this.initializeState();
    }

    private async initializeState(): Promise<void> {
        await SDK.ready();
        
        const userName = SDK.getUser().displayName;
        this.setState({
            userName,
            extensionContext: SDK.getExtensionContext(),
            host: SDK.getHost()
         });

        const projectService = await SDK.getService<IProjectPageService>(CommonServiceIds.ProjectPageService);
        const project = await projectService.getProject();
        if (project) {
            this.setState({ projectName: project.name });
        }

        const navService = await SDK.getService<IHostNavigationService>(CommonServiceIds.HostNavigationService);
        const navElements = await navService.getPageNavigationElements();
        this.setState({ navElements });

        const route = await navService.getPageRoute();
        this.setState({ route });
    }

    public render(): JSX.Element {

        const { userName, projectName, host, iframeUrl, extensionContext, route, navElements } = this.state;

        return (
            <div className="page-content page-content-top flex-column rhythm-vertical-16">
                <div>Hello, {userName}!</div>
                {
                    projectName &&
                    <div>Project: {projectName}</div>
                }
                <div>iframe URL: {iframeUrl}</div>
                {
                    extensionContext &&
                    <div>
                        <div>Extension id: {extensionContext.id}</div>
                        <div>Extension version: {extensionContext.version}</div>
                    </div>
                }
                {
                    host &&
                    <div>
                        <div>Host id: {host.id}</div>
                        <div>Host name: {host.name}</div>
                        <div>Host service version: {host.serviceVersion}</div>
                    </div>
                }
                {
                    navElements && <div>Nav elements: {JSON.stringify(navElements)}</div>
                }
                {
                    route && <div>Route: {JSON.stringify(route)}</div>
                }
            </div>
        );
    }
}