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

// export class LocalDevice {
//     public address: string;
//     public name?: string;
//     public firstSeen?: Date;
//     public lastSeen?: Date;
//     public broadcastPackets?: number;
//     public avgBroadcastPeriod?: number;
//     public timeSinceLastSeen?: number;
//     public rssi?: number;
//
//     private constructor(address: string) {
//         this.address = address;
//     }
//
//     public static parse(record: Record<string, any>): LocalDevice {
//         const device = new LocalDevice(record.address);
//         LocalDevice.importTo(device, record);
//         return device;
//     }
//
//     public static importTo(device: LocalDevice, record: Record<string, any>): void {
//         // console.warn('assign', record);
//         device.name = record.name;
//         device.firstSeen = record.firstSeen? new Date(record.firstSeen): undefined;
//         device.lastSeen = record.lastSeen? new Date(record.lastSeen): undefined;
//         device.broadcastPackets = record.broadcastPackets;
//         device.avgBroadcastPeriod = record.avgBroadcastPeriod;
//         device.timeSinceLastSeen = record.timeSinceLastSeen;
//         device.rssi = record.rssi;
//     }
//
//     compare(other: LocalDevice, active: string) {
//         if (active === 'address') {
//             return this.address < other.address? 1: (this.address > other.address? -1: 0);
//         }
//         if (active === 'firstSeen') {
//             const a = this.firstSeen?.getTime()?? 0;
//             const b = other.firstSeen?.getTime()??0;
//             return (a < b) ? -1: (a > b? 1: 0);
//         }
//         if (active === 'lastSeen') {
//             const a = this.lastSeen?.getTime()?? 0;
//             const b = other.lastSeen?.getTime()??0;
//             return (a < b) ? -1: (a > b? 1: 0);
//         }
//         if (active === 'avgBroadcastPeriod') {
//             const a = this.avgBroadcastPeriod?? Infinity;
//             const b = other.avgBroadcastPeriod?? Infinity;
//             return (a < b) ? -1: (a > b? 1: 0);
//         }
//         if (active === 'rssi') {
//             const a = this.rssi?? -Infinity;
//             const b = other.rssi?? -Infinity;
//             return (a < b) ? -1: (a > b? 1: 0);
//         }
//         return 0;
//     }
// }
//
// export class StreamCallback {
//     status = 'disconnected';
//     objects: LocalDevice[] = [];
//     sortConfig?: Sort;
//
//     init(payload: Record<string, any>[]): void {
//         payload.forEach((record: Record<string, any>) => {
//             this.rawAdd(record);
//         });
//         if (this.sortConfig) {
//             this.sort(this.sortConfig);
//         }
//         this.trigger('update');
//     }
//
//     add(payload: Record<string, any>): void {
//         // TODO: handle full payload
//         // TODO: handle partial object update
//         // TODO: handle object delete
//         console.warn('add to stream', this, 'with', payload);
//         this.rawAdd(payload);
//
//         if (this.sortConfig) {
//             this.sort(this.sortConfig);
//         }
//         this.trigger('update');
//     }
//
//     private rawAdd(payload: Record<string, any>): void {
//         let oldDevice: LocalDevice|undefined = this.findItem((item) => item.address === payload.address);
//
//         if (oldDevice) {
//             console.warn('adding device', payload.address, 'that already exists');
//             return;
//         }
//         oldDevice = LocalDevice.parse(payload);
//         this.objects.push(oldDevice);
//     }
//
//     remove(address: string) {
//         const p = this.objects.findIndex((item) => item.address === address);
//         if (p === -1) {
//             console.warn('Cant find item to remove');
//             return;
//         }
//         this.objects.splice(p, 1);
//         this.trigger('update');
//     }
//
//     update(payload: Record<string, any>): void {
//         const oldDevice: LocalDevice|undefined = this.findItem((item) => item.address === payload.address);
//         if (!oldDevice) {
//             console.warn('update device that do not exists ', payload.address);
//             return;
//         }
//         LocalDevice.importTo(oldDevice, payload);
//         if (this.sortConfig) {
//             this.sort(this.sortConfig);
//         }
//     }
//
//     private findItem(predicate: (item: LocalDevice) => boolean): LocalDevice|undefined {
//         const p = this.objects.findIndex(predicate);
//         return p === -1? undefined: this.objects[p];
//     }
//
//     sort(sort: Sort) {
//         this.sortConfig = sort;
//         // console.warn('sort', sort);
//         this.objects.sort((a, b) => a.compare(b, sort.active));
//         if (sort.direction === 'desc') {
//             this.objects.reverse();
//         }
//
//     }
//
//     private onUpdateCallbacks: (() => void)[] = [];
//     public on(eventName: string, callback: () => void) {
//         if (eventName === 'update') {
//             this.onUpdateCallbacks.push(callback);
//         } else {
//             console.warn('Unsupported eventName', eventName);
//         }
//     }
//
//     public trigger(eventName: string) {
//         if (eventName === 'update') {
//             this.onUpdateCallbacks.forEach((callback) => callback());
//         } else {
//             console.warn('Unsupported eventName', eventName);
//         }
//     }
// }

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
        const url = (this.url || document.location.href.replace(/\/$/, '')).replace(/http:\/\//, 'ws://').replace(/https:\/\//, 'wss://')+'/api/ws';
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

    // private updateStream(stream: StreamCallback, obj: Record<string, any>) {
    //     if (obj.init) {
    //         stream.init(obj.init);
    //     } else if (obj.update) {
    //         stream.update(obj.update);
    //     }
    // }
}