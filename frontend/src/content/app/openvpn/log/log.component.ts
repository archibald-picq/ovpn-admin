import { Component, OnDestroy, OnInit } from '@angular/core';
import { WebsocketService } from '../services/websocket.service';

@Component({
    selector: 'bus-openvpn-log',
    templateUrl: './log.component.html',
    styleUrls: ['./log.component.scss'],
})
export class LogPageComponent implements OnInit, OnDestroy {
    public loading = false;
    public lines: string[] = [];
    private callback = (data: any) => {
        // console.warn('data', data);
    };
    private rawRead = (data: any) => {
        this.lines.push(data);
    };
    private rawWrite = (data: any) => {
        this.lines.push(data);
    };

    constructor(
        private readonly websocketService: WebsocketService,
    ) {
    }

    ngOnInit(): void {
        this.websocketService.connect();
        this.websocketService.bind('users', this.callback);
        this.websocketService.bind('read', this.rawRead);
        this.websocketService.bind('write', this.rawWrite);
    }

    ngOnDestroy(): void {
        this.websocketService.unbind('read', this.rawRead);
        this.websocketService.unbind('write', this.rawWrite);
        this.websocketService.unbind('users', this.callback);
        this.websocketService.disconnect();
    }


}
