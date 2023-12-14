import {Component} from '@angular/core';

@Component({
  selector: 'bus-openvpn-join-master',
  templateUrl: './join-master.component.html',
  styleUrls: ['./join-master.component.scss'],
})
export class JoinMasterComponent {
  public loading = false;
  public url?: string;
  public error?: string;

  public async save(): Promise<void> {

  }
}
