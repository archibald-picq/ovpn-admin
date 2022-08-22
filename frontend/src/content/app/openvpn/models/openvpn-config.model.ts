import { Route } from './route.model';


export class OpenvpnConfig {
    server: string;
    serverIpv6: string;
    duplicateCn: boolean;
    compLzo: boolean;
    routes: Route[];
    pushs: Route[];

    constructor(raw?: Record<string, any>) {
        this.server = raw?.server;
        this.serverIpv6 = raw?.serverIpv6;
        this.duplicateCn = raw?.duplicateCn;
        this.compLzo = raw?.compLzo;
        this.routes = (raw?.routes ?? []).map((r: Record<string, any>) => Route.parse(r));
        this.pushs = raw?.pushs ?? [];
    }

    static parse(raw: any) {
        return new OpenvpnConfig(raw);
    }

    public clone(): OpenvpnConfig {
        return new OpenvpnConfig(this);
    }
}