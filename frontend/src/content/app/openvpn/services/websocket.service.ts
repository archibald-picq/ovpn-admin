import { Injectable } from "@angular/core";
import { AppConfigService } from '../../shared/services/app-config.service';

class WebsocketRequest {
    resolve: (resp: any) => void;
    reject: (err: any) => void;
    constructor(public readonly id: number, public readonly payload: any, resolve: (resp: any) => void, reject: (err: any) => void) {
        this.resolve = resolve;
        this.reject = reject;
    }
}

type Callback = (data: any) => void;

@Injectable()
export class WebsocketService {
    private server?: WebSocket;
    private pending: WebsocketRequest[] = [];
    private reqId = 1;
    private streams: Record<string, Callback[]> = {};
    private status = 'closed';
    private url?: string;
    private protocol = 'ovpn';
    private shouldReconnect = false;

    constructor(
        protected readonly appConfigService: AppConfigService,
    ) {
        // console.warn('openvpn', appConfigService.get());
        this.url = appConfigService.get().openvpn?.url;
    }

    public bind(streamName: string, callback: Callback): void {
        if (!this.streams[streamName]) {
            this.streams[streamName] = [];
            if (this.server?.readyState === 1) {
                this.server.send(JSON.stringify({action: 'register', data: {stream: streamName}}));
            // } else {
            //     console.warn('not yet connected to register stream "'+streamName+'"');
            }
        }
        this.streams[streamName].push(callback);
    }

    public unbind(streamName: string, callback: Callback): void {
        if (!this.streams[streamName]) {
            return;
        }

        const p = this.streams[streamName].indexOf(callback);
        if (p === -1) {
            return;
        }
        this.streams[streamName].splice(p, 1);
        if (this.streams[streamName].length === 0) {
            if (this.server?.readyState === 1) {
                this.server?.send(JSON.stringify({action: 'unregister', data: {stream: streamName}}));
            } else {
                console.warn('not connected');
            }
            delete this.streams[streamName];
        }
    }

    public trigger(streamName: string, data: any): void {
        if (!this.streams[streamName]) {
            return;
        }
        this.streams[streamName].forEach((s) => s(data));
    }

    public connect(): void {
        if (this.url === undefined) {
            console.warn('Cant connect to ovpn-admin: no url provided');
            return;
        }
        if (this.server) {
            console.warn('Already connected');
            return;
        }
        this.shouldReconnect = true;

        const url = this.getUrl();
        console.warn('connect to ovpn-admin ws at', url);
        // console.warn('WS url', url);
        this.server = new WebSocket(url, this.protocol);

        this.server.onmessage = (msg) => this.onmessage(msg);
        this.server.onclose = (e) => this.onclose(e);
        this.server.onerror = (e) => this.onerror(e);
        this.server.onopen = () => this.onopen();
        // Object.values(this.streams).forEach((stream) => {
        //     stream.status = 'connecting';
        // });
        this.status = 'connecting';
    }

    public disconnect(): void {
        this.shouldReconnect = false;
        if (!this.server) {
            console.warn('Not connected');
            return;
        }
        this.server.close();
    }

    private onmessage(message: MessageEvent) {
        // console.warn('message', message);
        let obj;
        try {
            // console.warn('message.data: ', typeof message.data, message.data);
            obj = JSON.parse(message.data);
        } catch (e: any) {
            console.warn('Unparsable payload "' + message + '": ', e.message);
            return;
        }
        // console.info('obj', obj);
        if (obj.id) {
            try {
                this.handlePendingResponse(obj);
            } catch (e) {
                console.warn('Error handling response from initiated request', obj.id);
            }
        } else if (obj.stream) {
            // console.info('obj ', obj);
            // console.warn('receiving update for stream', obj.stream);
            if (this.streams[obj.stream]) {
                this.trigger(obj.stream, obj.data);
            } else {
                console.warn(`Stream '${obj.stream}' has not been requested`);
            }
        } else {
            console.warn('Unsupported object: ', obj);
        }
    }

    private onclose(e: any) {
        console.warn('onclose', e);
        // Object.values(this.streams).forEach((stream) => {
        //     stream.status = 'closed';
        // });
        this.status = 'closed';
        this.server = undefined;
        if (this.shouldReconnect) {
            setTimeout(() => this.connect(), 1000);
        }
    }

    private onerror(e: any) {
        console.warn('error', e);
    }

    private onopen() {
        console.warn('connected to', this.getUrl());
        // Object.values(this.streams).forEach((stream) => {
        //     stream.status = 'opened';
        // });
        this.status = 'opened';

        Object.keys(this.streams).forEach((streamName) => {
           this.server?.send(JSON.stringify({action: 'register', data: {stream: streamName}}));
        });
        if (this.pending.length) {
            // console.warn('finally connected to send', this.pending[0]);
            this.server?.send(JSON.stringify(this.pending[0].payload));
        }
        // this.send({
        //     register: 'peripherals',
        // });
    }

    private handlePendingResponse(obj: Record<string, any>) {
        const p = this.pending.findIndex((pd) => pd.id === obj.id);
        if (p === -1) {
            console.warn('reply from not pending request', obj.id);
        } else {
            if (typeof obj.data !== 'undefined') {
                this.pending[p].resolve(obj.data);
            } else if (typeof obj.error !== 'undefined') {
                this.pending[p].reject(obj.error);
            } else {
                console.warn('Invalid message with pending request', obj.id, obj);
            }
            this.pending.splice(p, 1);
        }
    }

    async request(action: string, data: any) {
        return new Promise((resolve, reject) => {
            const payload = {
                id: ++this.reqId,
                action,
                data,
            };
            this.pending.push(new WebsocketRequest(payload.id, payload, resolve, reject));
            if (this.server) {
                this.server.send(JSON.stringify(payload));
            // } else {
            //     console.warn('websocket not yet connected?', this);
            }
        });
    }

    private send(obj: {}) {
        this.server?.send(JSON.stringify(obj));
    }

    private getUrl(): string {
        return (this.url ? this.url : this.getLocalUrl()).replace(/^http/, 'ws')+'/api/ws';
    }

    private getLocalUrl(): string {
        const port = document.location.port &&
          ((document.location.protocol === 'https:' && document.location.port !== '443') ||
          (document.location.protocol === 'http:' && document.location.port !== '80'))? ':'+document.location.port: '';
        return document.location.protocol+'//'+document.location.hostname+port;
    }
}
