import { Route } from './route.model';
import { ServiceConfig } from '../../shared/models/service-config';

export class User {
    constructor(
        public username: string,
        public name?: string,
    ) {
    }

    static hydrate(raw: User): User {
        return new User(
            raw.username,
            raw.name,
        );
    }
}

export class Settings {
    constructor(
        public server: string,
        public forceGatewayIpv4: boolean,
        public forceGatewayIpv4ExceptDhcp: boolean,
        public forceGatewayIpv4ExceptDns: boolean,
        public dnsIpv4: string,
        public serverIpv6: string,
        public forceGatewayIpv6: boolean,
        public dnsIpv6: string,
        public enableMtu: boolean,
        public tunMtu: number,
        public duplicateCn: boolean,
        public clientToClient: boolean,
        public compLzo: boolean,
        public routes: Route[],
        public routesPush: Route[],
        public pushs: Route[],
        public auth: string,
    ) {

    }

    static parse(raw: Record<string, any>): Settings {
        return new Settings(
            raw?.server,
            raw?.forceGatewayIpv4,
            raw?.forceGatewayIpv4ExceptDhcp,
            raw?.forceGatewayIpv4ExceptDns,
            raw?.dnsIpv4,
            raw?.serverIpv6,
            raw?.forceGatewayIpv6,
            raw?.dnsIpv6,
            raw?.enableMtu,
            raw?.tunMtu,
            raw?.duplicateCn,
            raw?.clientToClient,
            raw?.compLzo,
            raw?.auth === ''? null: raw?.auth,
            (raw?.routes ?? []).map(Route.parse),
            (raw?.routesPush ?? []).map(Route.parse),
            raw?.pushs ?? [],
        );
    }

    public clone(): Settings {
        return Settings.parse(this);
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
        this.users = (raw?.users ?? []).map(User.hydrate);
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
