import {BleConnection, BleConnectParams, PersistentBleConnection} from './ble-connection.service';

class Request {
  constructor(
    public readonly id: number,
    public readonly buffer: ArrayBuffer,
    public readonly resolve: (value: unknown) => void,
    public readonly reject: (reason?: any) => void,
  ) {
  }
}

export class BleCommandConnection extends BleConnection {
  private requestId = 0;
  private requestQueue: Request[] = [];
  private stream: ArrayBuffer = new ArrayBuffer(0);
  private onMessageCb?: (e: any) => void;
  private decoder = new TextDecoder('utf-8');

  constructor(
      persist: PersistentBleConnection|string,
      params: BleConnectParams,
  ) {
    super(persist, params);

    super.recv((buffer: ArrayBuffer) => {
      this.stream = BleCommandConnection.concat(this.stream, buffer);
      this.consumeStream();
    });
  }
  public recv(cb: (e: any) => void) {
    this.onMessageCb = cb;
  }

  protected onDisconnected(event: any) {
    this.requestQueue = [];
    this.stream = new ArrayBuffer(0);
    super.onDisconnected(event);
  }

  private consumeStream() {
    // const buffer = new ArrayBuffer([this.stream);
    if (this.stream.byteLength < 1) {
      console.warn('Not enough byte to parse payload');
      return;
    }
    const firstByte = (new DataView(this.stream).getUint8(0));
    if (firstByte === 0x42) {
      if (this.stream.byteLength < 5) {
        console.warn('Not enough bytes (expect at least 5 bytes)');
        return;
      }
      // console.warn('sizeBytes', buffer.slice(1, 5));
      const size = (new DataView(this.stream).getUint32(1));
      // const size = (new Uint32Array(buffer.slice(1, 5)))[0];
      if (this.stream.byteLength < 5 + size) {
        console.warn('Not enough data yet (expect '+(size+5)+', got '+this.stream.byteLength+')');
        return;
      }
      const str = this.decoder.decode(this.stream.slice(5, size+5));
      this.stream = this.stream.slice(5 + size);
      // console.warn('parsing "', str, '"');
      const obj = JSON.parse(str);
      // console.warn('obj', obj);
      this.confirmResponse(obj);
    } else {
      console.warn('Invalid first byte', firstByte);
    }
  }

  private confirmResponse(obj: any) {
    if (!obj.id) {
      this.onMessageCb?.(obj);
      return;
    }
    const requestIndex = this.requestQueue.findIndex(r => r.id === obj.id);
    if (requestIndex === -1) {
      console.warn('Unexpected response for unknown request', obj);
      return;
    }
    const request = this.requestQueue[requestIndex];
    this.requestQueue.splice(requestIndex, 1);
    console.warn('resolve', request, 'with', obj);
    if (obj.error) {
      request.reject(obj.error);
    } else {
      request.resolve(obj.data);
    }
    if (this.requestQueue.length > 0) {
      this.processQueue();
    }
  }

  private processQueue() {
    super.send(this.requestQueue[0].buffer);
  }

  public async request(action: string, data: any): Promise<any> {
    return new Promise((resolve, reject) => {
      if (this.status !== 'connected') {
        reject('Not connected');
        return;
      }
      const req = {
        id: ++this.requestId,
        action,
        data,
      }
      const payload = JSON.stringify(req);
      const enc = new TextEncoder();
      const content = enc.encode(payload);
      // console.warn('message length', content.byteLength);
      // if (content.byteLength > 255) {
      //   reject('Content too big ('+content.byteLength+' bytes)');
      //   return;
      // }
      const bufferSize = new ArrayBuffer(5);
      new DataView(bufferSize).setUint8(0, 0x42);
      new DataView(bufferSize).setUint32(1, content.byteLength);

      const buffer = new Uint8Array([...new Uint8Array(bufferSize), ...content]);
      // for (let i = 0; i < buffer.byteLength; i++) {
      //   console.warn('byte['+i+']', buffer[i]);
      // }
      // const buffer = Buffer.from(payload, 'utf-8');
      this.requestQueue.push(new Request(req.id, buffer, resolve, reject));
      console.warn('sending', payload, 'queue', this.requestQueue);
      if (this.requestQueue.length === 1) {
        this.processQueue();
      } else {
        console.warn(this.requestQueue.length - 1, 'requests already in progress');
      }
    });
  }

  private static concat(...views: ArrayBuffer[]): ArrayBuffer {
    let length = 0;
    for (const v of views) {
      length += v.byteLength;
    }

    const buf = new Uint8Array(length);
    let offset = 0;
    for (const v of views) {
      const uint8view = new Uint8Array(v, 0, v.byteLength);
      buf.set(uint8view, offset);
      offset += uint8view.byteLength;
    }

    return buf.buffer;
  }
}
