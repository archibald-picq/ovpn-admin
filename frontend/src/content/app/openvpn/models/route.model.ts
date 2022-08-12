
export class Route {
    public address: string;
    public netmask: string;
    public description?: string;

    constructor(address: string, netmask: string, description?: string) {
        this.address = address;
        this.netmask = netmask;
        this.description = description;
    }

    public static parse(fromServer: Record<string, any>): Route {
        return new Route(fromServer.address, fromServer.mask, fromServer.description);
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
