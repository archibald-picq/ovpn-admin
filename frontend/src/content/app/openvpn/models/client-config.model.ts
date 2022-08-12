import { Route } from "./route.model";

export class ClientConfig {
    public staticAddress: string;
    public pushRoutes: Route[] = [];
    public iRoutes: Route[] = [];

    constructor(staticAddress: string) {
        this.staticAddress = staticAddress;
    }

    public addPushRoute(route: Route): void {
        this.pushRoutes.push(route);
    }

    public addIRoute(route: Route): void {
        this.iRoutes.push(route);
    }

    public static parse(fromServer: Record<string, any>): ClientConfig {
        const config = new ClientConfig(fromServer.clientAddress);
        if (fromServer.customIRoutes) {
            fromServer.customIRoutes.forEach((route: Record<string, any>) => config.addIRoute(Route.parse(route)));
        }
        if (fromServer.customRoutes) {
            fromServer.customRoutes.forEach((route: Record<string, any>) => config.addPushRoute(Route.parse(route)));
        }
        return config;
    }

    public clone(): ClientConfig {
        const config = new ClientConfig(this.staticAddress);
        this.pushRoutes.forEach((route) => config.addPushRoute(route.clone()));
        this.iRoutes.forEach((route) => config.addIRoute(route.clone()));
        return config;
    }
}
