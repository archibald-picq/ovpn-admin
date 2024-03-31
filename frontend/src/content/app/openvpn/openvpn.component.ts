import {Component, OnDestroy, OnInit} from "@angular/core";
import {WebsocketService} from "./services/websocket.service";
import {ActivatedRoute} from '@angular/router';
import {OpenvpnConfig} from './models/openvpn-config.model';

@Component({
	selector: 'bus-openvpn',
	// templateUrl: './openvpn.component.html',
	// styleUrls: ['./openvpn.component.scss'],
	template: `<router-outlet></router-outlet>`,
})
export class OpenvpnComponent implements OnInit, OnDestroy {
	public config: OpenvpnConfig;
	constructor(
		private readonly websocketService: WebsocketService,
		private readonly activatedRoute: ActivatedRoute,
	) {
		this.config = this.activatedRoute.snapshot.data.config;
	}

	ngOnInit(): void {
		this.websocketService.connect();
	}

	ngOnDestroy(): void {
		this.websocketService.disconnect();
	}

}
