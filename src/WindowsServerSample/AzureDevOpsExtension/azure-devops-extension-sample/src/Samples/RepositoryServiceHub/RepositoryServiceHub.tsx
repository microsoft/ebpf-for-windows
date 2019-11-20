import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";
import { GitServiceIds, IVersionControlRepositoryService } from "azure-devops-extension-api/Git/GitServices";

import { Header, TitleSize } from "azure-devops-ui/Header";
import { Page } from "azure-devops-ui/Page";

import { showRootComponent } from "../../Common";
import { GitRepository } from "azure-devops-extension-api/Git/Git";

interface IRepositoryServiceHubContentState {
    repository: GitRepository | null;
}

class RepositoryServiceHubContent extends React.Component<{}, IRepositoryServiceHubContentState> {
    constructor(props: {}) {
        super(props);
        
        this.state = { repository: null };
    }

    public async componentWillMount() {
        SDK.init();
        const repoSvc = await SDK.getService<IVersionControlRepositoryService>(GitServiceIds.VersionControlRepositoryService);
        const repository = await repoSvc.getCurrentGitRepository();

        this.setState({
            repository
        });
    }

    public render(): JSX.Element {

        return (
            <Page className="sample-hub flex-grow">

                <Header title="Repository Information Sample Hub"
                    titleSize={TitleSize.Medium} />

                <div style={{marginLeft: 32}}>
                    <h3>ID</h3>
                    {
                        this.state.repository &&
                        <p>{this.state.repository.id}</p>
                    }
                    <h3>Name</h3>
                    {
                        this.state.repository &&
                        <p>{this.state.repository.name}</p>
                    }
                    <h3>URL</h3>
                    {
                        this.state.repository &&
                        <p>{this.state.repository.url}</p>
                    }
                </div>
            </Page>
        );
    }
}

showRootComponent(<RepositoryServiceHubContent />);