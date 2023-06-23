import {Component, Injector, OnDestroy, OnInit} from '@angular/core';
import {ActivatedRoute} from '@angular/router';
import {IClientCertificate} from '../models/client-certificate.interface';
import {WebsocketService} from '../services/websocket.service';
import {WsRpicConnection} from '../models/client-certificate.model';
import {BleService} from '../../shared/services/ble/ble.service';
import {NodeConfig} from '../models/node-config.model';
import {Dpkg, Network, PackageInstalled} from '../models/node-status.model';
import {InterfaceRunning} from '../models/node-interface.model';
import {Hello} from '../models/hello.model';
import {AddPackageComponent, AddPackageModalOptions} from './modals/add-package.component';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {ConfigureMasterServerComponent, ConfigureMasterServerParams} from './modals/configure-master-server.component';
import {BleCommandConnection} from '../../shared/services/ble/ble-command.service';
import {BleConnectParams} from '../../shared/services/ble/ble-connection.service';
import {AppConfigService} from '../../shared/services/app-config.service';

export interface RemoteCall {
	type: string;
	isConnected(): boolean;
	request(payload: any): Promise<any>;
}

class Log {
	public body = '';
	constructor(
		public readonly time: Date,
		public readonly dir: string,
		public message: string,
	) {
	}
}

@Component({
	selector: 'bus-openvpn-config',
	templateUrl: './config-page.component.html',
	styleUrls: ['./config-page.component.scss'],
})
export class ConfigPageComponent implements OnInit, OnDestroy {
	public logs: Log[] = [];
	public bleConnection: BleCommandConnection;
	public client: IClientCertificate;
	public rpic: WsRpicConnection|undefined;
	public config: NodeConfig;

	private usersCallback = (data: any) => {
		// console.warn('update', data);
		// this.client.merge(ClientCertificate.hydrate(data));
		this.client.rpic = data.map(WsRpicConnection.hydrate);
		this.rpic = this.client.rpic[0];
		this.wsHello = this.rpic?.hello;
		console.warn('this.wsHello', this.wsHello);
	};
	public cmdLine = '';
	public lines: string[] = [];
	public bleHello?: Hello;
	public interfacesRunning?: InterfaceRunning[];

	public wsHello?: Hello;
	public dpkg?: Dpkg;
	private connWebsocket: RemoteCall;
	private connBluetooth: RemoteCall;
	private conns: RemoteCall[];
	private init: Promise<any>;
	private packagesStatus?: PackageInstalled[];
	private apiUrl?: string;

	constructor(
		private readonly activatedRoute: ActivatedRoute,
		private readonly websocketService: WebsocketService,
		private readonly bleService: BleService,
		private readonly modalService: NgbModal,
		private readonly injector: Injector,
		appConfigService: AppConfigService,
	) {
		this.client = activatedRoute.snapshot.data.client;
		this.config = activatedRoute.snapshot.data.config;
		this.apiUrl = appConfigService.get().openvpn?.url+'/api/ws';
		this.rpic = this.client.rpic[0];
		this.wsHello = this.rpic?.hello;
		// console.warn('client', this.client);
		// console.warn('config', this.config);

		this.bleConnection = this.bleService.createCommandConnection('rpic-'+this.client.username, new BleConnectParams(
			'RPiC',
			'0000ffe0-0000-1000-8000-00805f9b34fb',
			'6e400003-b5a3-f393-e0a9-e50e24dcca9e',
			'6e400002-b5a3-f393-e0a9-e50e24dcca9e',
		));

		this.connWebsocket = {
			type: 'ws',
			isConnected: (): boolean => this.client.rpic.length !== 0,
			request: async (data: any): Promise<any> => this.websocketService.request('forward', {
				target: this.client.username,
				action: 'request',
				data,
			}),
		};

		this.connBluetooth = {
			type: 'ble',
			isConnected: (): boolean => this.bleConnection.status === 'connected',
			request: async (data: any): Promise<any> => this.bleConnection.request('request', data),
		};

		this.conns = [this.connBluetooth, this.connWebsocket];


		this.init = this.queryStatus();
	}

	public ngOnInit(): void {
		this.websocketService.bind('user.update.'+this.client.username+'.rpic', this.usersCallback);
	}

	public ngOnDestroy(): void {
		this.websocketService.unbind('user.update.'+this.client.username+'.rpic', this.usersCallback);
	}

	public async connect() {
		await this.bleConnection.selectDevice();
	}

	public submit() {
		const obj = {command: this.cmdLine};
		const json = JSON.stringify(obj);
		console.warn('submit', json, ' (',json.length,')');

		const conn = this.conns.find(c => c.isConnected());
		if (!conn) {
			console.warn('not connected');
			return;
		}
		const log = new Log(new Date(), 'down', this.cmdLine);
		this.logs.push(log);
		conn.request(obj).then(resp => {
			console.warn('response', resp);
			log.body = typeof resp === 'string' ? resp : JSON.stringify(resp, null, 2);
		});
		this.cmdLine = '';
	}

	public preferWebsocket() {
		this.conns = [this.connWebsocket, this.connBluetooth];
	}

	public preferBluetooth() {
		this.conns = [this.connBluetooth, this.connWebsocket];
	}

	public clearHistory() {
		this.logs = [];
	}

	public async disconnectBluetooth() {
		await this.bleConnection.disconnect();
	}

	private async queryStatus(): Promise<any> {
		const conn = [this.connWebsocket, this.connBluetooth].find(c => c.isConnected());
		if (!conn) {
			console.warn('not connected through BLE nor WS');
			return;
		}

		console.warn('query status through', conn);

		// console.warn('this.interfacesRunning', this.interfacesRunning);
		// console.warn('packagesStatus', this.packagesStatus);
		this.bleConnection.connect(() => {
			console.warn('onConnectBluetooth');
			this.onConnectBluetooth();
		});

		this.bleConnection.recv(data => {
			console.warn('recv', data);
		});


		this.dpkg = Dpkg.hydrate(await conn.request({command: 'dpkg'}));
		this.packagesStatus = this.dpkg.packages;
		// console.warn('packages', this.packagesStatus);

		this.interfacesRunning = Network.hydrate(await conn.request({command: 'ipa'})).interfaces;
		// console.warn('interfaces', this.interfacesRunning);

		// this.wsHello = Hello.hydrate((await this.connWebsocket.request('request', {command: 'hello'})).output);

	}

	// public get wsHello(): Hello|undefined {
	// 	return undefined;
	// }

	public getInstalledPackage(packageName: string): PackageInstalled|undefined {
		return this.packagesStatus?.find(i => i.name === packageName);
	}

	public async addPackage() {
		console.warn('button add package');

		try {
			const result = await this.modalService.open(AddPackageComponent, {
				centered: true,
				injector: Injector.create({
					providers: [{
						provide: AddPackageModalOptions,
						useValue: new AddPackageModalOptions(this.connWebsocket, this.connBluetooth),
					}],
					parent: this.injector,
				}),
			}).result;
			console.warn('result', result);
		} catch (e) {
			console.warn(e);
		}
	}

	public manageRepositories() {
		console.warn('button manage repositories');
	}

	public renderUptime(bootTime: Date): string {
		const now = (new Date()).getTime();
		const boot = bootTime.getTime();
		const uptime = Math.ceil((now - boot) / 1000);
		if (uptime > 60) {
			const min = Math.floor(uptime/60);
			const sec = uptime % 60;
			return `${min} min, ${sec} s`;
		}
		return `${uptime} s`;
	}

	public async configure() {
		try {
			const result = await this.modalService.open(ConfigureMasterServerComponent, {
				centered: true,
				injector: Injector.create({
					providers: [{
						provide: ConfigureMasterServerParams,
						useValue: new ConfigureMasterServerParams(
							this.client.username,
							this.apiUrl,
							this.connWebsocket,
							this.connBluetooth,
						),
					}],
					parent: this.injector,
				}),
			}).result;
			if (result) {
				console.warn('result', result);
			}
		} catch (e) {
			console.warn(e);
		}
	}


	private async onConnectBluetooth() {
		const request = await this.connBluetooth.request({command: 'hello'});
		this.bleHello = Hello.hydrate(request);
		console.warn('request', this.bleHello);
	}

	public async leave() {
		const result = await this.connBluetooth.request({command: 'leave-server'});
		console.warn('result', result);

	}

	public async closeWs() {
		const result = await this.connBluetooth.request({command: 'close-ws'});
		console.warn('result', result);
	}
}
