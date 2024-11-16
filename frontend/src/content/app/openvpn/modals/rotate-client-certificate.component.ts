import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { IClientCertificate } from '../models/client-certificate.interface';
import { OpenvpnService } from '../services/openvpn.service';
import {BaseCertificate} from '../models/certificate-base.interface';
import {CertificatInfo} from '../models/certificat-info.model';

export class RotateClientOptions {
    constructor(public readonly client: IClientCertificate) {
    }
}

@Component({
    selector: 'bus-openvpn-confirm-rotate-client-certificate',
    templateUrl: './rotate-client-certificate.component.html',
    styleUrls: ['./rotate-client-certificate.component.scss'],
})
export class RotateClientCertificateComponent {
    public certificate: CertificatInfo;
    public error = '';
    public loading = false;

    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: RotateClientOptions,
    ) {
        this.certificate = {
            commonName: this.options.client.username,
            email: this.options.client.certificate?.email ?? '',
            country: this.options.client.certificate?.country ?? '',
            province: this.options.client.certificate?.province ?? '',
            city: this.options.client.certificate?.city ?? '',
            organisation: this.options.client.certificate?.organisation ?? '',
            organisationUnit: this.options.client.certificate?.organisationUnit ?? '',
            expiresAt: undefined,
            serialNumber: undefined,
        };

        if (!this.certificate.expiresAt) {
            this.certificate.expiresAt = new Date();
            this.certificate.expiresAt.setFullYear(this.certificate.expiresAt.getFullYear()+2);
        }
    }

    public async save(): Promise<void> {
        try {
            this.loading = true;
            this.error = '';
            const newCertificate = await this.openvpnService.rotateCertificate(this.options.client.username, this.certificate);
            console.warn('created certificate', newCertificate);
            this.options.client.certificate = newCertificate;
            // newClient.certificate!.accountStatus = 'Active';
            // newClient.certificate!.revocationDate = undefined;
            // this.options.client.certificate!.accountStatus = 'Revoked';
            // this.options.client.certificate!.revocationDate = new Date();
            this.modal.close(this.options.client);
        } catch (e: any) {
            this.error = e.error.message;
            console.warn('service call failed: ', e.error.message);
        }
        this.loading = false;
    }
}
