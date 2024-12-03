import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { OpenvpnService } from '../services/openvpn.service';
import {ICertificate, IClientCertificate} from '../models/client-certificate.interface';
import {CertificatInfo} from '../models/certificat-info.model';
import {Settings} from '../models/openvpn-config.model';
import {IssuedCertificate} from '../models/certificat-issued.model';
//

export class RotateServerCertificateOptions {
    constructor(
      public readonly settings: Settings,
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
    public popupTitle = 'Renew server certificate';
    public settings: Settings;

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        private readonly options: RotateServerCertificateOptions,
    ) {
        if (options.settings) {
            this.certificate.commonName = options.settings.serverCert!.commonName;
            this.certificate.email = options.settings.serverCert!.email;
            this.certificate.country = options.settings.serverCert!.country;
            this.certificate.province = options.settings.serverCert!.province;
            this.certificate.city = options.settings.serverCert!.city;
            this.certificate.organisation = options.settings.serverCert!.organisation;
            this.certificate.organisationUnit = options.settings.serverCert!.organisationUnit;
        }
        if (!this.certificate.expiresAt) {
            this.certificate.expiresAt = new Date();
            this.certificate.expiresAt.setFullYear(this.certificate.expiresAt.getFullYear()+2);
        }
        this.settings = options.settings;
    }

    public async save(): Promise<void> {
        try {
            this.loading = true;
            this.error = '';
            const certificate: ICertificate = await this.openvpnService.rotateCertificate(this.certificate.commonName, this.certificate);
            console.warn('certificate created', certificate);

            this.settings.serverCert = IssuedCertificate.hydrate({
                serialNumber: certificate.serialNumber!,
                commonName: this.settings.serverCert!.commonName,
                city: certificate.city,
                country: certificate.country,
                email: certificate.email,
                expiresAt: new Date(certificate.expirationDate!),
                organisation: certificate.organisation,
                organisationUnit: certificate.organisationUnit,
                province: certificate.province,
            });
            this.modal.close(certificate);
        } catch (e: any) {
            this.error = e.error.message;
            console.warn('service call failed: ', e.error.message);
        }
        this.loading = false;
    }

  protected readonly close = close;
}
