import {ICertificate, IClientCertificate, IConnection, INetwork, INode} from './client-certificate.interface';
import { ClientConfig } from './client-config.model';
import { Hello } from './hello.model';

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
		public readonly hello: Hello|undefined,
	) {
	}

	public static hydrate(obj: WsRpicConnection): WsRpicConnection {
		return new WsRpicConnection(
			obj.realAddress,
			obj.ssl,
			obj.connectedSince ? new Date(obj.connectedSince) : undefined,
			obj.lastRef ? new Date(obj.lastRef) : undefined,
			obj.userAgent,
			obj.hello ? Hello.hydrate(obj.hello) : undefined,
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

export class Certificate implements ICertificate {
	constructor(
		public readonly identity: string,
		public readonly country: string,
		public readonly province: string,
		public readonly city: string,
		public readonly organisation: string,
		public readonly organisationUnit: string,
		public readonly email: string,
		public readonly expirationDate: Date|undefined,
		public readonly revocationDate: Date|undefined,
		public accountStatus: string,
	) {

	}
	public static hydrate(obj: ICertificate) : ICertificate {
		return new Certificate(
			obj.identity,
			obj.country,
			obj.province,
			obj.city,
			obj.organisation,
			obj.organisationUnit,
			obj.email,
			ClientCertificate.parseDate(obj.expirationDate),
			obj.revocationDate ? ClientCertificate.parseDate(obj.revocationDate): undefined,
			obj.accountStatus,
		);
	}
}

export class ClientCertificate implements IClientCertificate {

	constructor(
		public readonly username: string,
		public certificate: ICertificate|undefined,
		public connectionStatus: string,
		public readonly connections: IConnection[],
		public readonly rpic: WsRpicConnection[],
		public readonly ccd?: ClientConfig,
	) {

	}

	public static hydrate(obj: IClientCertificate): IClientCertificate {
		return new ClientCertificate(
			obj.username,
			obj.certificate ? Certificate.hydrate(obj.certificate) : undefined,
			obj.connectionStatus,
			obj.connections?.map(Connection.hydrate) ?? [],
			obj.rpic?.map(WsRpicConnection.hydrate) ?? [],
			obj.ccd,
		);
	}

	public static parseDate(str: Date|string|undefined): Date|undefined {
		return str instanceof Date ? str : (str ? new Date(str) : undefined);
	}

	public clone(): IClientCertificate {
		return new ClientCertificate(
			this.username,
			this.certificate,
			this.connectionStatus,
			[],
			[],
			undefined,
		);
	}
	public merge(newClient: IClientCertificate): void {
		// console.warn('merge', newClient);
		this.connectionStatus = newClient.connectionStatus;
		if (this.certificate && newClient.certificate?.accountStatus) {
			this.certificate.accountStatus = newClient.certificate?.accountStatus;
		}

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
