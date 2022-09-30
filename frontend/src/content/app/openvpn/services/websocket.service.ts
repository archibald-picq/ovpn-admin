import { Injectable } from "@angular/core";
import { AppConfigService } from '../../shared/services/app-config.service';

class WebsocketRequest {
    id: number;
    resolve: (resp: any) => void;
    reject: (err: any) => void;
    constructor(id: number, resolve: (resp: any) => void, reject: (err: any) => void) {
        this.id = id;
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
    private shouldConnect = false;
    // private subject: AnonymousSubject<MessageEvent>;
    // public messages: Subject<Message>;

    constructor(
        protected readonly appConfigService: AppConfigService,
    ) {
        this.url = appConfigService.get().openvpn?.url;
    }

    // synchronize(streamName: string): StreamCallback {
    //     this.connect();
    //     if (!this.streams[streamName]) {
    //         this.streams[streamName] = new StreamCallback();
    //     }
    //     return this.streams[streamName];
    // }

    public bind(streamName: string, callback: Callback): void {
        if (!this.streams[streamName]) {
            this.streams[streamName] = [];
            if (this.server && this.status === 'opened') {
                this.server.send(JSON.stringify({action: 'register', data: streamName}));
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
            this.server?.send(JSON.stringify({action: 'unregister', data: streamName}));
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
        this.shouldConnect = true;
        const url = (this.url || this.getLocalUrl()).replace(/^http/, 'ws')+'/api/ws';
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
        this.shouldConnect = false;
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
        }
        catch(e: any) {
            console.warn('Unparsable payload "'+message+'": ', e.message);
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
        if (this.shouldConnect) {
            setTimeout(() => this.connect(), 1000);
        }
    }

    private onerror(e: any) {
        console.warn('error', e);
    }

    private onopen() {
        console.warn('opended');
        // Object.values(this.streams).forEach((stream) => {
        //     stream.status = 'opened';
        // });
        this.status = 'opened';
        Object.keys(this.streams).forEach((streamName) => {
           this.server?.send(JSON.stringify({action: 'register', data: streamName}));
        });
        // this.send({
        //     register: 'peripherals',
        // });
    }

    private handlePendingResponse(obj: Record<string, any>) {
        const p = this.pending.findIndex((pd) => pd.id === obj.id);
        if (p === -1) {
            console.warn('reply from not pending request', obj.id);
        } else {
            if (typeof obj.response !== 'undefined') {
                this.pending[p].resolve(obj.response);
            } else if (typeof obj.error !== 'undefined') {
                this.pending[p].reject(obj.error);
            } else {
                console.warn('Invalid message with pending request', obj.id);
            }
            this.pending.splice(p, 1);
        }
    }

    async request(obj: any) {
        return new Promise((resolve, reject) => {
            const id = this.reqId++;
            this.pending.push(new WebsocketRequest(id, resolve, reject));
            obj.id = id;
            this.server!.send(JSON.stringify(obj));
        });
    }

    private send(obj: {}) {
        this.server?.send(JSON.stringify(obj));
    }

    private getLocalUrl(): string {
        return document.location.protocol+'//'+document.location.hostname;
    }
}