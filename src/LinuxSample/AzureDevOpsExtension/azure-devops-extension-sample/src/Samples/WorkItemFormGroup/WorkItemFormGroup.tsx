import {
  IWorkItemChangedArgs,
  IWorkItemFieldChangedArgs,
  IWorkItemFormService,
  IWorkItemLoadedArgs,
  WorkItemTrackingServiceIds
} from "azure-devops-extension-api/WorkItemTracking";
import * as SDK from "azure-devops-extension-sdk";
import { Button } from "azure-devops-ui/Button";
import * as React from "react";
import { showRootComponent } from "../../Common";

interface WorkItemFormGroupComponentState {
  eventContent: string;
}

class WorkItemFormGroupComponent extends React.Component<{},  WorkItemFormGroupComponentState> {
  constructor(props: {}) {
    super(props);
    this.state = {
      eventContent: ""
    };
  }

  public componentDidMount() {
    SDK.init().then(() => {
      this.registerEvents();
    });
  }

  public render(): JSX.Element {
    return (
      <div>
        <Button
          className="sample-work-item-button"
          text="Click me to change title!"
          onClick={() => this.onClick()}
        />
        <div className="sample-work-item-events">{this.state.eventContent}</div>
      </div>
    );
  }

  private registerEvents() {
    SDK.register(SDK.getContributionId(), () => {
      return {
        // Called when the active work item is modified
        onFieldChanged: (args: IWorkItemFieldChangedArgs) => {
          this.setState({
            eventContent: `onFieldChanged - ${JSON.stringify(args)}`
          });
        },

        // Called when a new work item is being loaded in the UI
        onLoaded: (args: IWorkItemLoadedArgs) => {
          this.setState({
            eventContent: `onLoaded - ${JSON.stringify(args)}`
          });
        },

        // Called when the active work item is being unloaded in the UI
        onUnloaded: (args: IWorkItemChangedArgs) => {
          this.setState({
            eventContent: `onUnloaded - ${JSON.stringify(args)}`
          });
        },

        // Called after the work item has been saved
        onSaved: (args: IWorkItemChangedArgs) => {
          this.setState({
            eventContent: `onSaved - ${JSON.stringify(args)}`
          });
        },

        // Called when the work item is reset to its unmodified state (undo)
        onReset: (args: IWorkItemChangedArgs) => {
          this.setState({
            eventContent: `onReset - ${JSON.stringify(args)}`
          });
        },

        // Called when the work item has been refreshed from the server
        onRefreshed: (args: IWorkItemChangedArgs) => {
          this.setState({
            eventContent: `onRefreshed - ${JSON.stringify(args)}`
          });
        }
      };
    });
  }

  private async onClick() {
    const workItemFormService = await SDK.getService<IWorkItemFormService>(
      WorkItemTrackingServiceIds.WorkItemFormService
    );
    workItemFormService.setFieldValue(
      "System.Title",
      "Title set from your group extension!"
    );
  }
}

showRootComponent(<WorkItemFormGroupComponent />);
