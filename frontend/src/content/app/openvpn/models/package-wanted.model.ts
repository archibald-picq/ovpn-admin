
export class PackageWanted {
  constructor(
    public readonly state: string,
    public readonly name: string,
    public readonly version: string|undefined,
  ) {
  }

  public static hydrate(obj: PackageWanted): PackageWanted {
    return new PackageWanted(
      obj.state,
      obj.name,
      obj.version,
    );
  }
}
