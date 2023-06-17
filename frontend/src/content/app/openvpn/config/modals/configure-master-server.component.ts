import {Component} from '@angular/core';
import {NgbActiveModal} from '@ng-bootstrap/ng-bootstrap';
import {RemoteCall} from '../config-page.component';

export class ConfigureMasterServerParams {
  constructor(
    public readonly name: string,
    public readonly url: string|undefined,
    public readonly connWebsocket: RemoteCall,
    public readonly connBluetooth: RemoteCall,
  ) {
  }
}

@Component({
  selector: 'bus-configure-master-server',
  templateUrl: './configure-master-server.component.html',
  styleUrls: ['./configure-master-server.component.scss'],
})
export class ConfigureMasterServerComponent {
  public loading = false;
  public defaultServer = '';
  public defaultName = 'my-pi';
  public name = '';
  public url?: string;
  public error?: any;

  constructor(
    public readonly modal: NgbActiveModal,
    public readonly params: ConfigureMasterServerParams,
  ) {
    this.name = this.params.name;
    this.url = this.params.url;
  }

  public async save(): Promise<void> {
    this.error = undefined;
    try {
      const result = await this.params.connBluetooth.request({
        command: 'join-server',
        data: {url: this.url, name: this.name}
      });
      console.warn('result', result);
      this.modal.close();
    } catch (e) {
      this.error = e;
    }
  }
}
