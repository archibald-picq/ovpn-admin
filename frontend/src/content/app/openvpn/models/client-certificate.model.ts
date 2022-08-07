import { IClientCertificate, IConnection, INetwork, INode } from './client-certificate.interface';
import { ClientConfig } from '../modals/edit-client.component';

export class Network implements INetwork {
    address: string;
    lastSeen: Date;
    netmask: string;

    constructor(fromServer: Record<string, any>) {
        this.address = fromServer.address;
        this.lastSeen = ClientCertificate.parseDate(fromServer.lastSeen)!;
        this.netmask = fromServer.netmask;
    }

    public static parse(fromServer: Record<string, any>): INetwork {
        return new Network(fromServer);
    }
}

export class Node implements INode {
    address: string;
    lastSeen: Date;

    constructor(fromServer: Record<string, any>) {
        this.address = fromServer.address;
        this.lastSeen = ClientCertificate.parseDate(fromServer.lastSeen)!;
    }

    public static parse(fromServer: Record<string, any>): INode {
        return new Node(fromServer);
    }
}

export class Connection implements IConnection {
    bytesReceived: number;
    bytesSent: number;
    connectedSince: Date;
    lastSeen: Date;
    networks: INetwork[];
    nodes: INode[];

    constructor(fromServer: Record<string, any>) {
        this.bytesReceived = (fromServer.bytesReceived ?? fromServer.BytesReceived);
        this.bytesSent = (fromServer.bytesSent ?? fromServer.BytesSent);
        this.connectedSince = ClientCertificate.parseDate(fromServer.connectedSince ?? fromServer.ConnectedSince)!;
        this.lastSeen = ClientCertificate.parseDate(fromServer.lastSeen ?? fromServer.LastRef)!;
        this.networks = fromServer.networks? fromServer.networks.map((network: Record<string, any>) => Network.parse(network)): [];
        this.nodes = fromServer.nodes? fromServer.nodes.map((node: Record<string, any>) => Node.parse(node)): [];
    }

    public static parse(fromServer: Record<string, any>): IConnection {
        return new Connection(fromServer);
    }
}

export class ClientCertificate implements IClientCertificate {
    public username: string;
    public identity: string;
    public accountStatus: string;
    public connectionStatus: string;
    public connections: IConnection[];
    public expirationDate?: Date;
    public revocationDate?: Date;
    public ccd?: ClientConfig;

    constructor(fromServer: Record<string, any>) {
        this.username = fromServer.username;
        this.identity = fromServer.Identity;
        this.accountStatus = fromServer.accountStatus ?? fromServer.AccountStatus;
        this.connectionStatus = fromServer.connectionStatus ?? fromServer.ConnectionStatus;
        this.connections = (fromServer.connections ?? fromServer.Connections ?? []).map((connection: Record<string, any>) => Connection.parse(connection));
        this.expirationDate = ClientCertificate.parseDate(fromServer.expirationDate ?? fromServer.ExpirationDate);
        if (fromServer.revocationDate || fromServer.RevocationDate) {
            this.revocationDate = ClientCertificate.parseDate(fromServer.revocationDate ?? fromServer.RevocationDate);
        }
    }

    public static parse(fromServer: Record<string, any>): IClientCertificate {
        return new ClientCertificate(fromServer);
    }

    public static parseDate(str: string): Date|undefined {
        return str? new Date(str): undefined;
    }
    public clone(): IClientCertificate {
        const client = new ClientCertificate({});
        client.username = this.username;
        client.identity = this.identity;
        client.accountStatus = this.accountStatus;
        client.connectionStatus = this.connectionStatus;
        client.connections = [];
        client.expirationDate = this.expirationDate? new Date(this.expirationDate): undefined;
        client.revocationDate = this.revocationDate? new Date(this.revocationDate): undefined;
        return client;
    }
}
