import { Injectable } from '@angular/core';
import {BleConnection, BleConnectParams, PersistentBleConnection} from './ble-connection.service';
import {BleCommandConnection} from './ble-command.service';


@Injectable()
export class BleService {
  public createConnection(persistent: PersistentBleConnection|string, params: BleConnectParams): BleConnection {
    return new BleConnection(persistent, params);
  }
  public createCommandConnection(persistent: PersistentBleConnection|string, params: BleConnectParams): BleCommandConnection {
    return new BleCommandConnection(persistent, params);
  }
}
