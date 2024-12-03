import {Component, Injector, Input} from '@angular/core';
import {OpenvpnServiceConfig} from '../models/openvpn-config.model';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {
  RotateServerCertificateComponent,
  RotateServerCertificateOptions
} from '../modals/rotate-server-certificate.component';

@Component({
  selector: 'bus-openvpn-warning-expires',
  templateUrl: './warning-expires.component.html',
  styleUrls: ['./warning-expires.component.scss'],
})
export class WarningExpiresComponent {
  @Input()
  public config?: OpenvpnServiceConfig;

  public renewWarningDate: Date = new Date();
  public now: Date = new Date();
  constructor(
    private readonly modalService: NgbModal,
    private readonly injector: Injector,
  ) {
    this.renewWarningDate.setDate(this.renewWarningDate.getDate() + 30);
  }

  public async rotateServerCertificate() {
    console.warn('renew');
    try {
      console.warn('rotate server certificate', this.config?.settings?.serverCert);
      await this.modalService.open(RotateServerCertificateComponent, {
        centered: true,
        injector: Injector.create([{
          provide: RotateServerCertificateOptions,
          useValue: new RotateServerCertificateOptions(this.config!.settings!),
        }], this.injector),
      }).result;

    } catch (e) {
      console.warn('Cancel delete client');
    }
  }

  diffDates(from: Date, to: Date) {
    const seconds = Math.abs((from.getTime() - to.getTime()) / 1000);
    const hours = seconds / 60 / 60;
    if (hours <= 24) {
      return Math.floor(hours)+' hours';
    }
    const days = hours / 24;
    return Math.floor(days) + ' days';
  }
}
