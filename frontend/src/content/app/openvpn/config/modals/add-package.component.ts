import {Component} from '@angular/core';
import {NgbActiveModal} from '@ng-bootstrap/ng-bootstrap';
import { PackageState } from '../../models/package-state.model';
import {PackageWanted} from '../../models/package-wanted.model';
import {RemoteCall} from '../config-page.component';

export class AddPackageModalOptions {
  constructor(
    public readonly connWebsocket: RemoteCall,
    public readonly connBluetooth: RemoteCall,
  ) {
  }
}

@Component({
  selector: 'bus-add-package',
  templateUrl: './add-package.component.html',
  styleUrls: ['./add-package.component.scss'],
})
export class AddPackageComponent {
  public loading = false;
  public error: string|undefined|any;
  public name = '';
  public version?: string;
  public autoUpdate = true;
  public saveToMaster = true;

  constructor(
    public readonly modal: NgbActiveModal,
    public readonly options?: AddPackageModalOptions,
  ) {
  }

  public async save(): Promise<void> {
    if (!this.name) {
      this.error = 'Missing package name';
      // console.warn('Missing package name');
      return;
    }
    const conn = this.options ? [this.options.connWebsocket, this.options.connBluetooth].find(c => c.isConnected()) : null;
    if (!conn) {
      this.error = 'Not connected through BLE nor WS';
      console.warn('not connected through BLE nor WS');
      return;
    }
    try {
      this.error = undefined;
      const result = await conn.request({command: 'apt-install', data: {
        package: this.name,
        version: this.version,
        autoUpdate: this.autoUpdate,
        save: true,
      }});
      console.warn('result', result);
      this.modal.close(new PackageWanted(
        PackageState.INSTALLED,
        this.name,
        this.version,
      ));
    }
    catch (e: any) {
      this.error = e.message;
    }

  }
}
