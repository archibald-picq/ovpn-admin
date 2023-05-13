import {Component, OnDestroy, OnInit} from '@angular/core';
import {ActivatedRoute} from '@angular/router';
import {IClientCertificate} from '../models/client-certificate.interface';
import {WebsocketService} from '../services/websocket.service';
import {ClientCertificate} from '../models/client-certificate.model';

@Component({
	selector: 'bus-openvpn-config',
	templateUrl: './config-page.component.html',
	styleUrls: ['./config-page.component.scss'],
})
export class ConfigPageComponent implements OnInit, OnDestroy {
	public client: IClientCertificate;

	private usersCallback = (data: any) => {
		// console.warn('update', data);
		this.client.merge(ClientCertificate.hydrate(data));
	};

	constructor(
		private readonly activatedRoute: ActivatedRoute,
		private readonly websocketService: WebsocketService,
	) {
		this.client = activatedRoute.snapshot.data.client;
		console.warn('client', this.client);
	}

	public ngOnInit(): void {
		this.websocketService.bind('user.update.'+this.client.username, this.usersCallback);
	}

	public ngOnDestroy(): void {
		this.websocketService.unbind('user.update.'+this.client.username, this.usersCallback);
	}

}
