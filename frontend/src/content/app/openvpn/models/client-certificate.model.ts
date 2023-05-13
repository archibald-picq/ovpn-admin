import { IClientCertificate, IConnection, INetwork, INode } from './client-certificate.interface';
import { ClientConfig } from './client-config.model';

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

export class WsRpicConnection {
	constructor(
		public readonly realAddress: string,
		public readonly ssl: boolean,
		public readonly connectedSince: Date|undefined,
		public readonly lastRef: Date|undefined,
		public readonly userAgent: string,
	) {
	}

	public static hydrate(obj: WsRpicConnection): WsRpicConnection {
		return new WsRpicConnection(
			obj.realAddress,
			obj.ssl,
			obj.connectedSince ? new Date(obj.connectedSince) : undefined,
			obj.lastRef ? new Date(obj.lastRef) : undefined,
			obj.userAgent,
		);
	}
}

export class Connection implements IConnection {


	constructor(
		public readonly clientId: number,
		public readonly realAddress: string,
		public readonly speedBytesReceived: number,
		public readonly speedBytesSent: number,
		public readonly bytesReceived: number,
		public readonly bytesSent: number,
		public readonly connectedSince: Date,
		public readonly lastSeen: Date,
		public readonly virtualAddress: string,
		public readonly virtualAddressIPv6: string|undefined,
		public readonly networks: INetwork[],
		public readonly nodes: INode[],
	) {

	}

	public static hydrate(fromServer: any): IConnection {
		return new Connection(
			fromServer.clientId,
			fromServer.realAddress,
			+fromServer.speedBytesReceived,
			+fromServer.speedBytesSent,
			+fromServer.bytesReceived,
			+fromServer.bytesSent,
			ClientCertificate.parseDate(fromServer.connectedSince)!,
			ClientCertificate.parseDate(fromServer.lastSeen ?? fromServer.lastRef)!,
			fromServer.virtualAddress,
			fromServer.virtualAddressIPv6,
			fromServer.networks? fromServer.networks.map((network: Record<string, any>) => Network.parse(network)): [],
			fromServer.nodes? fromServer.nodes.map((node: Record<string, any>) => Node.parse(node)): [],
		);
	}
}

export class ClientCertificate implements IClientCertificate {

	constructor(
		public readonly username: string,
		public readonly email: string,
		public readonly country: string,
		public readonly province: string,
		public readonly city: string,
		public readonly organisation: string,
		public readonly organisationUnit: string,
		public readonly identity: string,
		public accountStatus: string,
		public connectionStatus: string,
		public readonly connections: IConnection[],
		public readonly rpic: WsRpicConnection[],
		public readonly expirationDate?: Date,
		public readonly revocationDate?: Date,
		public readonly ccd?: ClientConfig,
	) {

	}

	public static hydrate(obj: Record<string, any>): IClientCertificate {
		return new ClientCertificate(
			obj.username,
			obj.email,
			obj.country,
			obj.city,
			obj.province,
			obj.organisation,
			obj.organisationUnit,
			obj.identity,
			obj.accountStatus,
			obj.connectionStatus,
			obj.connections?.map(Connection.hydrate) ?? [],
			obj.rpic?.map(WsRpicConnection.hydrate) ?? [],
			ClientCertificate.parseDate(obj.expirationDate),
			obj.revocationDate ? ClientCertificate.parseDate(obj.revocationDate): undefined,
			obj.ccd,
		);
	}

	public static parseDate(str: Date|string|undefined): Date|undefined {
		return str instanceof Date ? str : (str ? new Date(str) : undefined);
	}

	public clone(): IClientCertificate {
		return new ClientCertificate(
			this.username,
			this.email,
			this.country,
			this.province,
			this.city,
			this.organisation,
			this.organisationUnit,
			this.identity,
			this.accountStatus,
			this.connectionStatus,
			[],
			[],
			this.expirationDate? new Date(this.expirationDate): undefined,
			undefined,
			undefined,
		);
	}
	public merge(newClient: IClientCertificate): void {
		console.warn('merge', newClient);
		this.connectionStatus = newClient.connectionStatus;
		this.accountStatus = newClient.accountStatus;
		this.connections.splice(0, this.connections.length);
		for (const connection of newClient.connections) {
			this.connections.push(connection);
		}
		this.rpic.splice(0, this.rpic.length);
		for (const connection of newClient.rpic ?? []) {
			this.rpic.push(connection);
		}
	}
}
