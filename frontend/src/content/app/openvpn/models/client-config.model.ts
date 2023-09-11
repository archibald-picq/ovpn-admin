import {Route} from "./route.model";

export class ClientConfig {
    constructor(
      public staticAddress: string,
      public readonly pushRoutes: Route[],
      public readonly iRoutes: Route[],
    ) {}

    public static hydrate(fromServer: Record<string, any>): ClientConfig {
        return new ClientConfig(
          fromServer.clientAddress,
          fromServer.customRoutes?.map(Route.parse) ?? [],
          fromServer.customIRoutes?.map(Route.parse) ?? [],
        );
    }

    public clone(): ClientConfig {
        return new ClientConfig(
          this.staticAddress,
          this.pushRoutes.map((route) => route.clone()),
          this.iRoutes.map((route) => route.clone()),
        );
    }
}
