
export class Route {
    constructor(
      public address: string,
      public netmask: string,
      public description?: string,
    ) { }

    public static parse(fromServer: Record<string, any>): Route {
        return new Route(fromServer.address, fromServer.netmask, fromServer.description);
    }

    public clone(): Route {
        return new Route(this.address, this.netmask, this.description);
    }

    reset() {
        this.address = '';
        this.netmask = '';
        this.description = undefined;
    }
}
