import { Component, OnDestroy, OnInit } from '@angular/core';
import { WebsocketService } from '../services/websocket.service';

export class Packet {
    constructor(public readonly time: Date, public readonly dir: string, public readonly content: string) {}
}

@Component({
    selector: 'bus-openvpn-log',
    templateUrl: './log.component.html',
    styleUrls: ['./log.component.scss'],
})
export class LogPageComponent implements OnInit, OnDestroy {
    public loading = false;
    public lines: Packet[] = [];

    private rawRead = (data: any) => {
        this.lines.push(new Packet(new Date(), 'read', data));
    };
    private rawWrite = (data: any) => {
        this.lines.push(new Packet(new Date(), 'write', data));
    };

    constructor(
        private readonly websocketService: WebsocketService,
    ) {
    }

    ngOnInit(): void {
        this.websocketService.bind('read', this.rawRead);
        this.websocketService.bind('write', this.rawWrite);
    }

    ngOnDestroy(): void {
        this.websocketService.unbind('read', this.rawRead);
        this.websocketService.unbind('write', this.rawWrite);
    }


}
