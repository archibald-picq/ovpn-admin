import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { OpenvpnService } from '../services/openvpn.service';
import {ICertificate, IClientCertificate} from '../models/client-certificate.interface';
import {CertificatInfo} from '../models/certificat-info.model';
//

export class RotateServerCertificateOptions {
    constructor(
      public readonly info: CertificatInfo | undefined,
      public readonly editMode: 'save' | 'return',
      public readonly title: string = 'Renew server certificate',
  ) {
    }
}

@Component({
    selector: 'bus-openvpn-rotate-server-certificate',
    templateUrl: './rotate-server-certificate.component.html',
    styleUrls: ['./rotate-server-certificate.component.scss'],
})
export class RotateServerCertificateComponent {
    public certificate: CertificatInfo = {} as CertificatInfo;
    public error = '';
    public loading = false;
    public showHint = true;
    public popupTitle = 'Renew server certificate';

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        private readonly options: RotateServerCertificateOptions,
    ) {
        if (options.info) {
            this.certificate.commonName = options.info.commonName;
            this.certificate.email = options.info.email;
            this.certificate.country = options.info.country;
            this.certificate.province = options.info.province;
            this.certificate.city = options.info.city;
            this.certificate.organisation = options.info.organisation;
            this.certificate.organisationUnit = options.info.organisationUnit;
        }
        if (options.editMode === 'return') {
            this.showHint = false;
        }
        if (options.title) {
            this.popupTitle = options.title;
        }
        if (!this.certificate.expiresAt) {
            this.certificate.expiresAt = new Date();
            this.certificate.expiresAt.setFullYear(this.certificate.expiresAt.getFullYear()+2);
        }
    }

    public async save(): Promise<void> {
        if (this.options.editMode === 'save') {
            try {
                this.loading = true;
                this.error = '';
                const certificate: ICertificate = await this.openvpnService.rotateCertificate(this.certificate.commonName, this.certificate);
                console.warn('client created', certificate);
                this.modal.close(certificate);
            } catch (e: any) {
                this.error = e.error.message;
                console.warn('service call failed: ', e.error.message);
            }
            this.loading = false;
        } else {
            this.modal.close(this.certificate);
        }
    }

  protected readonly close = close;
}
