import "es6-promise/auto";
import * as SDK from "azure-devops-extension-sdk";
import { ObservableArray } from "azure-devops-ui/Core/Observable";
import { IBreadcrumbItem } from "azure-devops-ui/Breadcrumb";

SDK.register("sample-breadcrumb-service", () => {

    const items = new ObservableArray<IBreadcrumbItem>([{
        key: "sample-breadcrumb",
        text: "Sample breadcrumb item",
        href: "#",
        rank: 1000
    }]);

    window.setTimeout(() => {
        items.push({
            key: "sample-breadcrumb-2",
            text: "Sample breadcrumb item 2 (async)",
            href: "#",
            rank: 2000
        });
    }, 1000);

    return items;
});

SDK.init();