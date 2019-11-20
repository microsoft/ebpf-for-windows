import * as SDK from "azure-devops-extension-sdk";
import { ICodeEditorContribution, ICodeEditorContributionEndpoints } from "azure-devops-extension-api/Git/CodeEditorTypes";

SDK.register("my-code-editor-contribution", () => {
    const contribution: ICodeEditorContribution = {
        register: (endpoints: ICodeEditorContributionEndpoints) => {
            endpoints.registerLanguage({
                extensionPoint: { id: 'mySpecialLanguage', extensions: ['.mylog'] },
                monarchLanguage: {
                    tokenizer: {
                        root: [
                            ["\\[error.*", "invalid"],
                            ["\\[notice.*", "keyword"],
                            ["\\[info.*", "comment"],
                            ["\\[[a-zA-Z 0-9:]+\\]", "type"],
                        ]
                    }
                },
                configuration: {}
            });

            // Another option instead of defining the schema explicitly would be to fetch and parse from an external source,
            // such as http://schemastore.org/json/
            endpoints.registerJsonSchemas([
                {
                    fileMatch: ["myconfig.json", "*.myconfig.json"],
                    uri: "http://ms-samples/my-json-schema",
                    schema: {
                        type: "object",
                        properties: {
                            p1: {
                                enum: ["v1", "v2"]
                            },
                            p2: {
                                $ref: "http://ms-samples/another-schema.json" // reference the second schema
                            }
                        }
                    }
                }, {
                    uri: "http://ms-samples/another-schema.json",
                    schema: {
                        type: "object",
                        properties: {
                            q1: {
                                enum: ["x1", "x2"]
                            }
                        }
                    }
                }
            ]);
        }
    };
    return contribution;
});
SDK.init();