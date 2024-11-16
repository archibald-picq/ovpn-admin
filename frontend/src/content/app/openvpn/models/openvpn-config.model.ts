import { Route } from './route.model';
import { ServiceConfig } from '../../shared/models/service-config';
import {CertificatInfo} from './certificat-info.model';
import {IssuedCertificate} from './certificat-issued.model';

export class ApiKey {
    constructor(
      public id: string,
      public comment: string,
      public expires: Date,
    ) {
    }

    static hydrate(raw: ApiKey): ApiKey {
        return new ApiKey(
          raw.id,
          raw.comment,
          new Date(raw.expires),
        );
    }
}

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
        public serviceName: string,
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
        public auth: string|undefined,
        public serverCommonName: string,
        public caCert: IssuedCertificate|undefined,
        public serverCert: IssuedCertificate|undefined,
    ) {

    }

    static parse(raw: Settings): Settings {
        return new Settings(
            raw?.serviceName,
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
            (raw?.routes ?? []).map(Route.parse),
            (raw?.routesPush ?? []).map(Route.parse),
            raw?.pushs ?? [],
          raw?.auth === '' ? undefined : raw?.auth,
          raw?.serverCommonName,
          raw?.caCert ? IssuedCertificate.hydrate(raw?.caCert) : undefined,
          raw?.serverCert ? IssuedCertificate.hydrate(raw?.serverCert) : undefined,
        );
    }

    public clone(): Settings {
        return Settings.parse(this);
    }
}

export class Preferences {


    constructor(
      public address: string,
      public defaultAddress: string,
      public certificateDuration: number,
      public explicitExitNotify: boolean,
      public allowAnonymousCsr: boolean,
      public authNoCache: boolean,
      public verifyX509Name: boolean,
      public users: User[],
      public apiKeys: ApiKey[],
    ) {

    }

    static hydrate(raw: any) {
        return new Preferences(
          raw?.address,
          raw?.defaultAddress ?? '',
          raw?.certificateDuration,
          raw?.explicitExitNotify,
          raw?.allowAnonymousCsr,
          raw?.authNoCache,
          raw?.verifyX509Name,
          (raw?.users ?? []).map(User.hydrate),
          (raw?.apiKeys ?? []).map(ApiKey.hydrate),
        );
    }

    public clone(): Preferences {
        return Preferences.hydrate(this);
    }
}

export class ServerSetup {
    constructor(
        public serviceName: string,
        public pkiPath: string,
        public pkiCount: number|undefined,
        public dhPem: boolean,
        public caCert?: CertificatInfo,
        public serverCert?: CertificatInfo,
    ) {
    }

    static hydrate(raw: ServerSetup): ServerSetup {
        return new ServerSetup(
          raw.serviceName,
          raw.pkiPath,
          raw.pkiCount,
          raw.dhPem,
          raw.caCert,
          raw.serverCert,
        );
    }
}


export class OpenvpnServiceConfig extends ServiceConfig {
    constructor(
      public url?: string,
      public settings?: Settings,
      public preferences?: Preferences,
      public serverSetup?: ServerSetup,
      public unconfigured?: boolean,
      public allowSubmitCsr?: boolean,
    ) {
        super({url});
    }

    static hydrate(raw: any) {
        return new OpenvpnServiceConfig(
          raw.url,
          raw?.settings ? Settings.parse(raw?.settings): undefined,
          raw?.preferences ? Preferences.hydrate(raw?.preferences): undefined,
          raw?.serverSetup ? ServerSetup.hydrate(raw.serverSetup) : undefined,
          raw?.unconfigured,
          raw?.allowSubmitCsr ?? false,
        );
    }

    public import(raw: any) {
        this.url = raw.url;
        this.settings = raw?.settings ? Settings.parse(raw?.settings): undefined;
        this.preferences = raw?.preferences ? Preferences.hydrate(raw?.preferences): undefined;
        this.serverSetup = raw?.serverSetup ? ServerSetup.hydrate(raw.serverSetup) : undefined;
        this.unconfigured = raw?.unconfigured;
        this.allowSubmitCsr = raw?.allowSubmitCsr ?? false;
    }

    public clone(): OpenvpnServiceConfig {
        return OpenvpnServiceConfig.hydrate(this);
    }
}
