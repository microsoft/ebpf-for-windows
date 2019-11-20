import "./Panel.scss";

import * as React from "react";
import * as SDK from "azure-devops-extension-sdk";

import { Button } from "azure-devops-ui/Button";
import { ButtonGroup } from "azure-devops-ui/ButtonGroup";
import { Toggle } from "azure-devops-ui/Toggle";
import { showRootComponent } from "../../Common";

interface IPanelContentState {
    message?: string;
    toggleValue?: boolean;
    ready?: boolean;
}

class PanelContent extends React.Component<{}, IPanelContentState> {
    
    constructor(props: {}) {
        super(props);
        this.state = {};
    }

    public componentDidMount() {
        SDK.init();
        
        SDK.ready().then(() => {
            const config = SDK.getConfiguration();
            const message = config.message || "Custom dialog message";
            const toggleValue = !!config.initialValue;
            this.setState({ message, toggleValue, ready: true });

            if (config.dialog) {
                // Give the host frame the size of our dialog content so that the dialog can be sized appropriately.
                // This is the case where we know our content size and can explicitly provide it to SDK.resize. If our
                // size is dynamic, we have to make sure our frame is visible before calling SDK.resize() with no arguments.
                // In that case, we would instead do something like this:
                //
                // SDK.notifyLoadSucceeded().then(() => {
                //    // we are visible in this callback.
                //    SDK.resize();
                // });
                SDK.resize(400, 400);
            }
        });
    }

    public render(): JSX.Element {
        const { message, ready, toggleValue } = this.state;

        return (
            <div className="sample-panel flex-column flex-grow">
                <Toggle checked={toggleValue} text={message} disabled={!ready} onChange={(e, val) => this.setState({toggleValue: val})} />
                <div className="flex-grow flex-column flex-center justify-center" style={{ border: "1px solid #eee", margin: "10px 0" }}>
                    Additional content placeholder
                </div>
                <ButtonGroup className="sample-panel-button-bar">
                    <Button
                        primary={true}
                        text="OK"
                        onClick={() => this.dismiss(true)}
                    />
                    <Button
                        text="Cancel"
                        onClick={() => this.dismiss(false)}
                    />
                </ButtonGroup>
            </div>
        );
    }

    private dismiss(useValue: boolean) {
        const result = useValue ? this.state.toggleValue : undefined;
        const config = SDK.getConfiguration();
        if (config.dialog) {
            config.dialog.close(result);
        }
        else if (config.panel) {
            config.panel.close(result);
        }
    }
}

showRootComponent(<PanelContent />);