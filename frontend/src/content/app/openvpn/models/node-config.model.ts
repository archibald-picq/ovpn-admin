
export class AptSources {

}

export class Package {
  constructor(
    public name: string,
    public version: string,
  ) {
  }

  public static hydrate(obj: Package): Package {
    return new Package(
      obj.name,
      obj.version,
    )
  }
}

export class CustomFile {

}

export class NetInterface {

}

export class NodeConfig {
  constructor(
    public readonly hostname: any,
    public readonly autoUpdate: boolean,
    public readonly aptSources: AptSources[],
    public readonly packages: Package[],
    public readonly customFiles: CustomFile[],
    public readonly interfaces: NetInterface[],
  ) {
  }

  public static hydrate(obj: NodeConfig): NodeConfig {
    return new NodeConfig(
      obj.hostname,
      obj.autoUpdate,
      obj.aptSources,
      obj.packages?.map(Package.hydrate) ?? [],
      obj.customFiles,
      obj.interfaces,
    );
  }
}
