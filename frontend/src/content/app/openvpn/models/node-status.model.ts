import {InterfaceRunning} from './node-interface.model';

export class Route {
  constructor(
    public readonly addr: string,
    public readonly mask: number,
    public readonly dev: string,
    public readonly target: string,
  ) {
  }

  public static hydrate(obj: Route): Route {
    return new Route(
      obj.addr,
      obj.mask,
      obj.dev,
      obj.target,
    );
  }
}

export class Network {
  constructor(
    public readonly routes: Route[],
    public readonly interfaces: InterfaceRunning[],
  ) {
  }

  public static hydrate(obj: Network): Network {
    return new Network(
      obj.routes.map(Route.hydrate),
      obj.interfaces.map(InterfaceRunning.hydrate),
    );
  }
}

export class LsbInfo {
  constructor(
    public readonly prettyName: string,
    public readonly name: string,
    public readonly versionId: number,
    public readonly version: string,
    public readonly versionCodename: string,
    public readonly id: string,
    public readonly idLike: string,
    public readonly homeUrl: string,
    public readonly supportUrl: string,
    public readonly bugReportUrl: string,
  ) {
  }

  public static hydrate(obj: LsbInfo): LsbInfo {
    return new LsbInfo(
      obj.prettyName,
      obj.name,
      obj.versionId,
      obj.version,
      obj.versionCodename,
      obj.id,
      obj.idLike,
      obj.homeUrl,
      obj.supportUrl,
      obj.bugReportUrl,
    );
  }
}

export class Dpkg {
  constructor(
    public readonly version: string,
    public readonly lsb: LsbInfo|undefined,
    public readonly packages: PackageInstalled[],
  ) {
  }

  public static hydrate(obj: Dpkg): Dpkg {
    return new Dpkg(
      obj.version,
      obj.lsb ? LsbInfo.hydrate(obj.lsb) : undefined,
      obj.packages.map(PackageInstalled.hydrate),
    );
  }
}

export class PackageInstalled {
  constructor(
    public readonly name: string,
    public readonly version: string,
    public readonly arch: string,
    public readonly description: string,
    public readonly state: string,
    public readonly desiredState: string,
  ) {
  }

  public static hydrate(obj: PackageInstalled): PackageInstalled {
    return new PackageInstalled(
      obj.name,
      obj.version,
      obj.arch,
      obj.description,
      obj.state,
      obj.desiredState,
    );
  }
}
