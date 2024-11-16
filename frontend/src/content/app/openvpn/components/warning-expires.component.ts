import {Component, Injector, Input} from '@angular/core';
import {OpenvpnServiceConfig} from '../models/openvpn-config.model';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {
  RotateServerCertificateComponent,
  RotateServerCertificateOptions
} from '../modals/rotate-server-certificate.component';
import {IssuedCertificate} from '../models/certificat-issued.model';
import {ICertificate} from '../models/client-certificate.interface';

@Component({
  selector: 'bus-openvpn-warning-expires',
  templateUrl: './warning-expires.component.html',
  styleUrls: ['./warning-expires.component.scss'],
})
export class WarningExpiresComponent {
  @Input()
  public config?: OpenvpnServiceConfig;

  constructor(
    private readonly modalService: NgbModal,
    private readonly injector: Injector,
  ) {
  }

  public async rotateServerCertificate() {
    console.warn('renew');
    try {
      console.warn('rotate server certificate', this.config?.settings?.serverCert);
      const newCertificate: ICertificate = await this.modalService.open(RotateServerCertificateComponent, {
        centered: true,
        injector: Injector.create([{
          provide: RotateServerCertificateOptions,
          useValue: new RotateServerCertificateOptions(this.config?.settings?.serverCert, 'save'),
        }], this.injector),
      }).result;

      if (this.config?.settings) {
        this.config.settings.serverCert = IssuedCertificate.hydrate({
          serialNumber: newCertificate.serialNumber!,
          commonName: this.config.settings.serverCert!.commonName,
          city: newCertificate.city,
          country: newCertificate.country,
          email: newCertificate.email,
          expiresAt: new Date(newCertificate.expirationDate!),
          organisation: newCertificate.organisation,
          organisationUnit: newCertificate.organisationUnit,
          province: newCertificate.province,
        });
      }
      // console.warn('new client', newClient);
      // this.clients.push(newClient);
      // const p = this.clients.indexOf(client);
      // if (p === -1) {
      //     console.warn('Error in UI');
      // } else {
      //     this.clients.splice(p, 1, newClient);
      // }
      // console.warn('all clients', this.clients);
      // this.applySorting();
    } catch (e) {
      console.warn('Cancel delete client');
    }
  }
}
