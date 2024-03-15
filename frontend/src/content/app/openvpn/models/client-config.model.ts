import {Route} from "./route.model";
import {ICcd} from './client-certificate.interface';

export class ClientConfig implements ICcd {
    constructor(
      public clientAddress: string,
      public readonly customRoutes: Route[],
      public readonly customIRoutes: Route[],
    ) {}

    public static hydrate(fromServer: ICcd): ClientConfig {
        return new ClientConfig(
          fromServer.clientAddress,
          fromServer.customRoutes?.map(Route.parse) ?? [],
          fromServer.customIRoutes?.map(Route.parse) ?? [],
        );
    }

    public clone(): ClientConfig {
        return new ClientConfig(
          this.clientAddress,
          this.customRoutes.map((route) => route.clone()),
          this.customIRoutes.map((route) => route.clone()),
        );
    }
}
