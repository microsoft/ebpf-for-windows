import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";

import { Header } from "azure-devops-ui/Header";
import { Page } from "azure-devops-ui/Page";

import { showRootComponent } from "../../Common";

class FeatureHubContent extends React.Component<{}, {}> {

    public componentDidMount() {
        SDK.init();
    }

    public render(): JSX.Element {
        const iframeUrl = window.location.href;
        const isV2 = window.location.search.indexOf("v2=true") >= 0;
        return (
            <Page className="sample-hub flex-grow">
                <Header title={"ABC Sample hub" + (isV2 ? " (version 2)" : "")} />
                <div className="page-content">
                    <p>Feature ABC page</p>
                    <p>iframe url: {iframeUrl}</p>
                </div>
            </Page>
        );
    }
}

showRootComponent(<FeatureHubContent />);