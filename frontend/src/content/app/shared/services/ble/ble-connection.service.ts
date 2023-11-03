/// <reference types="web-bluetooth" />


export class PersistentBleConnection {
  public device?: BluetoothDevice;
  public serialService?: BluetoothRemoteGATTService;
  public serialCharacteristicRx?: BluetoothRemoteGATTCharacteristic;
  public serialCharacteristicTx?: BluetoothRemoteGATTCharacteristic;
  public callback?: (e: ArrayBuffer) => void;
  public onConnect?: () => void;
}

export class BleConnectParams {
  constructor(
    public readonly name: string,
    public readonly service: string,
    public readonly characteristicRx: string,
    public readonly characteristicTx?: string,
  ) {
  }
}

export class BleConnection {
  public static WRITE_THROTTLE = 0;
  public static MAX_BLE_PAYLOAD_SIZE = 20;
  public status: 'disconnected' | 'prompting' | 'connecting' | 'discovering' | 'failed' | 'connected' = 'disconnected';
  private expectedState: 'connected' | 'idle';
  private persistent: PersistentBleConnection;

  constructor(
    private readonly persist: PersistentBleConnection|string,
    private readonly params: BleConnectParams,
  ) {
    // console.warn('reuse', peristentBleConnection.device);
    this.persistent = BleConnection.getPersistentObject(persist);

    if (this.persistent.device?.gatt?.connected) {
      console.warn('Reusing gatt connection', this.persistent);
      this.status = 'connected';
      this.expectedState = 'connected';
    } else {
      // this.persistent.device = undefined;
      this.persistent.serialService = undefined;
      this.persistent.serialCharacteristicRx = undefined;
      this.expectedState = 'idle';
    }
  }

  private static getPersistentObject(persist: PersistentBleConnection|string): PersistentBleConnection {
    if (!(typeof persist === 'string')) {
      return persist;
    }
    const persistentConnections: Record<string, PersistentBleConnection> = (window as any).bleConnections ?? ((window as any).bleConnections = {});
    return persistentConnections[persist] ?? (persistentConnections[persist] = new PersistentBleConnection());
  }

  public recv(cb: (e: ArrayBuffer) => void) {
    // console.warn('binding new function', cb);
    this.persistent.callback = cb;
  }

  public connect(cb: () => void) {
    this.persistent.onConnect = cb;
    // console.warn('on connect', this.persistent.device);
    if (this.persistent.device?.gatt?.connected) {
      this.persistent.onConnect();
    }
  }

  public async selectDevice(): Promise<void> {
    if (this.status !== 'disconnected' && this.status !== 'failed') {
      console.warn('Cant start connection at state', this.status);
      return Promise.reject();
    }
    return new Promise((resolve, reject) => {
      this.status = 'prompting';
      // console.warn('request', this.params.name, 'with service', this.params.service);
      try {
        navigator.bluetooth.requestDevice({
          filters: [{
            namePrefix: this.params.name,
          }],
          // acceptAllDevices: true,
          optionalServices: [
            this.params.service,
          ],
        })
          .then((device) => {
            this.persistent.device = device;
            device.addEventListener('gattserverdisconnected', (event) => this.onDisconnected(event));
            this.connectToPeripheral(device).then(
              () => resolve(),
              () => reject(),
            );
          })
          .catch((error) => {
            console.warn('error: ', error, error.message);
            this.status = 'failed';
            reject(error);
          });
      } catch(e) {
        reject(e);
      }
    });
  }

  private async connectToPeripheral(device: BluetoothDevice): Promise<void> {
    return new Promise((resolve, reject) => {
      // updateViewConnecting();
      this.status = 'connecting';
      this.exponentialBackoff(3 /* max retries */, 2 /* seconds delay */,
        () => {
          this.persistent.device = device;
          console.warn('Connecting to Bluetooth Device...', this.persistent.device);
          return this.persistent.device?.gatt?.connect();
        },
        (server: any) => {
          console.warn('Bluetooth Device connected. Discovering services...');
          this.discoverServices(server).then(
            () => resolve(),
            () => reject(),
          )
        },
        () => {
          console.warn('Failed to reconnect.');
          reject();
        });
    });
  }

  private async discoverServices(server: BluetoothRemoteGATTServer): Promise<void> {
    try {
      this.status = 'discovering';

      this.persistent.serialService = await server.getPrimaryService(this.params.service);
      this.persistent.serialCharacteristicRx = await this.persistent.serialService.getCharacteristic(this.params.characteristicRx);
      this.persistent.serialCharacteristicRx.addEventListener('characteristicvaluechanged', (event: any) => {
        // console.warn('received', event.target.value.buffer.byteLength);

        if (!this.persistent.callback) {
          console.warn('event without callback', event.target.value.buffer, 'is it an old session ?');
        } else {
          this.persistent.callback(event.target.value.buffer);
        }
      });
      await this.persistent.serialCharacteristicRx.startNotifications();

      if (this.params.characteristicTx) {
        this.persistent.serialCharacteristicTx = await this.persistent.serialService.getCharacteristic(this.params.characteristicTx);
      }

      this.status = 'connected';

      console.warn('connected', this.persistent);

      if (this.persistent.onConnect) {
        this.persistent.onConnect();
      }
    } catch (error) {
      console.warn('error: ', error);
      this.onDisconnected(error);
      throw error;
    }
  }

  private exponentialBackoff(max: number, delay: number, toTry: any, success: (r:any) => void, fail: () => void) {
    try {
      toTry().then((result: any) => success(result))
        .catch((e: any) => {
          console.warn('error', e);
          if (max === 0) {
            fail();
            return ;
          }
          // time('Retrying in ' + delay + 's... (' + max + ' tries left)');
          setTimeout(() => {
            this.exponentialBackoff(--max, delay * 2, toTry, success, fail);
          }, delay * 1000);
        });
    } catch (e) {
      console.warn('failed', e);
    }
  }

  protected onDisconnected(event: any) {
    console.warn('disconnected', event, 'expected', this.expectedState);
    this.status = 'disconnected';
    const device = this.persistent.device;
    this.persistent.device = undefined;
    this.persistent.serialService = undefined;
    this.persistent.serialCharacteristicRx = undefined;
    if (device && this.expectedState !== 'idle') {
      setTimeout(() => {
        this.connectToPeripheral(device);
      });
    }
  }

  public async send(buffer: ArrayBuffer): Promise<void> {

    async function wait(ms: number) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }
    // console.warn('send', buffer.byteLength);
    while (buffer.byteLength > 0) {
      const size = Math.min(BleConnection.MAX_BLE_PAYLOAD_SIZE, buffer.byteLength);
      const part = buffer.slice(0, size);
      buffer = buffer.slice(size);

      // console.warn('sending', part.byteLength);
      let retry = 0;
      while (retry < 5) {
        try {
          // console.warn('sending to', this.persistent.serialCharacteristicTx ? 'Tx': 'Rx');
          await (this.persistent.serialCharacteristicTx ?? this.persistent.serialCharacteristicRx)?.writeValue(part);
          break;
        } catch (e) {
          if (e instanceof DOMException) {
            if (e.code === 11) {  // GATT Service no longer exists.
              console.warn(e.message);
              this.disconnect();
              throw {message: 'Disconnected'};
            } else if (e.code === 9) { // GATT operation failed for unknown reason.
              console.warn(e.message);
              this.disconnect();
              throw {message: 'Disconnected'};
            }
            console.warn('code', e.code, 'message', e.message);
          } else {
            console.warn('error', e);
          }
          retry++;
          if (retry >= 5) {
            throw {message: 'Too much failure'};
          }
          await wait(100);
        }
      }

      if (BleConnection.WRITE_THROTTLE && buffer.byteLength > 0) {
        await wait(BleConnection.WRITE_THROTTLE);
      }
    }
    // console.warn('done sending');
  }

  // private softReconnect(): void {
  //   const device = this.persistent.device;
  //   try {
  //     if (this.persistent.device?.gatt?.connected) {
  //       this.persistent.device?.gatt?.disconnect();
  //     }
  //   } catch (e) {
  //     console.warn('Error disconnecting', e);
  //   }
  //   this.status = 'failed';
  //   this.persistent.device = undefined;
  //   this.persistent.serialService = undefined;
  //   this.persistent.serialCharacteristicRx = undefined;
  //   this.persistent.serialCharacteristicTx = undefined;
  //   if (device) {
  //     this.connectToPeripheral(device);
  //   }
  // }

  public async disconnect(): Promise<boolean> {
    return new Promise<any>(resolve => {
      if (!this.persistent.device?.gatt?.connected) {
        resolve(false);
        return ;
      }
      this.persistent.device.gatt.disconnect();
      this.expectedState = 'idle';
      this.status = 'disconnected';
      this.persistent.device = undefined;
      this.persistent.serialService = undefined;
      this.persistent.serialCharacteristicRx = undefined;
      this.persistent.serialCharacteristicTx = undefined;
      resolve(true);
    });
  }
}
