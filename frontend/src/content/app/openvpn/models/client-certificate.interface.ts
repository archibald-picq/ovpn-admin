import { ClientConfig } from '../modals/edit-client.component';

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
    bytesReceived: number;
    bytesSent: number;
    connectedSince: Date;
    lastSeen: Date;
    networks: INetwork[];
    nodes: INode[];
}

export interface IClientCertificate {
    username: string;
    identity: string;
    accountStatus: string;
    connectionStatus: string;
    connections: IConnection[];
    expirationDate?: Date;
    revocationDate?: Date;
    ccd?: ClientConfig;

    clone(): IClientCertificate;
}
