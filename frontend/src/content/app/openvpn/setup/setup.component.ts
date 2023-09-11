import {Component} from '@angular/core';

@Component({
  selector: 'bus-openvpn-setup',
  templateUrl: './setup.component.html',
  styleUrls: ['./setup.component.scss'],
})
export class SetupComponent {
  public loading = false;
  public username = '';
  public name = '';
  public password = '';
  public passwordConfirm = '';

  public save() {
    console.warn('create server certificate');
  }
}
