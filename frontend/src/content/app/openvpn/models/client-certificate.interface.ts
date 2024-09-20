import { ClientConfig } from './client-config.model';
import {WsRpicConnection} from './client-certificate.model';
import {Route} from './route.model';
import {BaseCertificate} from './certificate-base.interface';

export interface INode {
    address: string;
    lastSeen: Date;
}

export interface INetwork {
    address: string;
    netmask: string;
    lastSeen: Date;
}

export interface ICertificate extends BaseCertificate {
    get identity(): string;
    // country: string;
    // province: string;
    // city: string;
    // organisation: string;
    // organisationUnit: string;
    // email: string;
    expirationDate?: Date;
    revocationDate?: Date;
    accountStatus?: string;
}

export interface IConnection {
    clientId: number;
    realAddress: string;
    speedBytesReceived: number;
    speedBytesSent: number;
    bytesReceived: number;
    bytesSent: number;
    connectedSince: Date;
    lastSeen: Date;
    virtualAddress: string;
    virtualAddressIPv6: string|undefined;
    networks: INetwork[];
    nodes: INode[];
}

export interface ICcd {
    clientAddress: string;
    customRoutes: Route[];
    customIRoutes: Route[];
}

export interface IClientCertificate {
    username: string;
    certificate: ICertificate|undefined;
    connectionStatus: string;
    connections: IConnection[];
    rpic: WsRpicConnection[];
    ccd?: ICcd;

    clone(): IClientCertificate;
    merge(newClient: IClientCertificate): void;
}
