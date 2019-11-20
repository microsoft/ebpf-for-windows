import "./Pivot.scss";

import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";

import { showRootComponent } from "../../Common";

import { getClient } from "azure-devops-extension-api";
import { CoreRestClient, ProjectVisibility, TeamProjectReference } from "azure-devops-extension-api/Core";

import { Table, ITableColumn, renderSimpleCell, renderSimpleCellValue } from "azure-devops-ui/Table";
import { ArrayItemProvider } from "azure-devops-ui/Utilities/Provider";

interface IPivotContentState {
    projects?: ArrayItemProvider<TeamProjectReference>;
    columns: ITableColumn<any>[];
}

class PivotContent extends React.Component<{}, IPivotContentState> {

    constructor(props: {}) {
        super(props);

        this.state = {
            columns: [{
                id: "name",
                name: "Project",
                renderCell: renderSimpleCell,
                width: 200
            },
            {
                id: "description",
                name: "Description",
                renderCell: renderSimpleCell,
                width: 300
            },
            {
                id: "visibility",
                name: "Visibility",
                renderCell: (rowIndex: number, columnIndex: number, tableColumn: ITableColumn<TeamProjectReference>, tableItem: TeamProjectReference): JSX.Element => {
                    return renderSimpleCellValue<any>(columnIndex, tableColumn, tableItem.visibility === ProjectVisibility.Public ? "Public" : "Private");
                },
                width: 100
            }]
        };
    }

    public componentDidMount() {
        SDK.init();
        this.initializeComponent();
    }

    private async initializeComponent() {
        const projects = await getClient(CoreRestClient).getProjects();
        this.setState({
            projects: new ArrayItemProvider(projects)
        });
    }

    public render(): JSX.Element {
        return (
            <div className="sample-pivot">
                {
                    !this.state.projects &&
                    <p>Loading...</p>
                }
                {
                    this.state.projects &&
                    <Table
                        columns={this.state.columns}
                        itemProvider={this.state.projects}
                    />
                }
            </div>
        );
    }
}

showRootComponent(<PivotContent />);