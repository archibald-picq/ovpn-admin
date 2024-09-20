import {Component, Input} from '@angular/core';
import {CertificatInfo} from '../models/certificat-info.model';

@Component({
  selector: 'bus-openvpn-certificate-form',
  templateUrl: './certificate-form.component.html',
  styleUrls: ['./certificate-form.component.scss'],
})
export class CertificateFormComponent {
  @Input()
  public certificate: CertificatInfo = {commonName: ''};
  @Input()
  public loading = false;

}
