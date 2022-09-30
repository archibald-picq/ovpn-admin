import { ClientConfig } from './client-config.model';

export interface INode {
    address: string;
    lastSeen: Date;
}

export interface INetwork {
    address: string;
    netmask: string;
    lastSeen: Date;
}

export interface IConnection {
    clientId: number;
    speedBytesReceived: number;
    speedBytesSent: number;
    bytesReceived: number;
    bytesSent: number;
    connectedSince: Date;
    lastSeen: Date;
    networks: INetwork[];
    nodes: INode[];
}

export interface IClientCertificate {
    username: string;
    email: string;
    country: string;
    province: string;
    city: string;
    organisation: string;
    organisationUnit: string;
    identity: string;
    accountStatus: string;
    connectionStatus: string;
    connections: IConnection[];
    expirationDate?: Date;
    revocationDate?: Date;
    ccd?: ClientConfig;

    clone(): IClientCertificate;
    merge(newClient: IClientCertificate): void;
}
