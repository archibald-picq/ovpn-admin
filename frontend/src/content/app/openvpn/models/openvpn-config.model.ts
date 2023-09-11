import { Route } from './route.model';
import { ServiceConfig } from '../../shared/models/service-config';

export class User {
    username: string;
    name: string;

    constructor(raw: Record<string, any>) {
        this.username = raw?.username;
        this.name = raw?.name;
    }

    static parse(raw: Record<string, any>): User {
        return new User(raw);
    }
}

export class Settings {
    server: string;
    forceGatewayIpv4: boolean;
    forceGatewayIpv4ExceptDhcp: boolean;
    forceGatewayIpv4ExceptDns: boolean;
    dnsIpv4: string;

    serverIpv6: string;
    forceGatewayIpv6: boolean;
    dnsIpv6: string;

    enableMtu: boolean;
    tunMtu: number;
    duplicateCn: boolean;
    clientToClient: boolean;
    compLzo: boolean;
    routes: Route[];
    pushs: Route[];
    auth: string;

    constructor(raw: Record<string, any>) {
        this.server = raw?.server;
        this.forceGatewayIpv4 = raw?.forceGatewayIpv4;
        this.forceGatewayIpv4ExceptDhcp = raw?.forceGatewayIpv4ExceptDhcp;
        this.forceGatewayIpv4ExceptDns = raw?.forceGatewayIpv4ExceptDns;
        this.dnsIpv4 = raw?.dnsIpv4;

        this.serverIpv6 = raw?.serverIpv6;
        this.forceGatewayIpv6 = raw?.forceGatewayIpv6;
        this.dnsIpv6 = raw?.dnsIpv6;

        this.enableMtu = raw?.enableMtu;
        this.tunMtu = raw?.tunMtu;
        this.duplicateCn = raw?.duplicateCn;
        this.clientToClient = raw?.clientToClient;
        this.compLzo = raw?.compLzo;
        this.auth = raw?.auth === ''? null: raw?.auth;
        this.routes = (raw?.routes ?? []).map((r: Record<string, any>) => Route.parse(r));
        this.pushs = raw?.pushs ?? [];
    }

    static parse(raw: Record<string, any>): Settings {
        return new Settings(raw);
    }

    public clone(): Settings {
        return new Settings(this);
    }
}

export class Preferences {
    address: string;
    defaultAddress: string;
    certificateDuration: number;
    explicitExitNotify: boolean;
    authNoCache: boolean;
    verifyX509Name: boolean;
    users: User[];

    constructor(raw?: Record<string, any>) {
        this.address = raw?.address;
        this.defaultAddress = raw?.defaultAddress ?? '';
        this.certificateDuration = raw?.certificateDuration;
        this.explicitExitNotify = raw?.explicitExitNotify;
        this.authNoCache = raw?.authNoCache;
        this.verifyX509Name = raw?.verifyX509Name;
        this.users = (raw?.users ?? []).map((u: Record<string, any>) => User.parse(u));
    }

    static parse(raw: any) {
        return new Preferences(raw);
    }

    public clone(): Preferences {
        return new Preferences(this);
    }
}

export class OpenvpnConfig extends ServiceConfig {
    settings?: Settings;
    preferences?: Preferences;
    unconfigured: boolean;

    constructor(raw?: Record<string, any>) {
        super(raw);
        if (raw?.settings) {
            this.settings = Settings.parse(raw?.settings);
        }
        if (raw?.preferences) {
            this.preferences = Preferences.parse(raw?.preferences);
        }
        this.unconfigured = raw?.unconfigured;
    }

    static hydrate(raw: any) {
        return new OpenvpnConfig(raw);
    }

    public clone(): OpenvpnConfig {
        return new OpenvpnConfig(this);
    }
}
