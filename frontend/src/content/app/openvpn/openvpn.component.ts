import {Component, OnDestroy, OnInit} from "@angular/core";
import {WebsocketService} from "./services/websocket.service";

@Component({
    selector: 'bus-openvpn',
    template: `<router-outlet></router-outlet>`,
})
export class OpenvpnComponent implements OnInit, OnDestroy {
    constructor(
        private readonly websocketService: WebsocketService,
    ) {
    }

    ngOnInit(): void {
        this.websocketService.connect();
    }

    ngOnDestroy(): void {
        this.websocketService.disconnect();
    }

}
