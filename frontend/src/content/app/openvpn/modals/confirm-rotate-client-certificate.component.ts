import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { IClientCertificate } from '../models/client-certificate.interface';
import { OpenvpnService } from '../services/openvpn.service';
import {BaseCertificate} from '../models/certificate-base.interface';

export class RotateClientOptions {
    constructor(public readonly client: IClientCertificate) {
    }
}

@Component({
    selector: 'bus-openvpn-confirm-rotate-client-certificate',
    templateUrl: './confirm-rotate-client-certificate.component.html',
    styleUrls: ['./confirm-rotate-client-certificate.component.scss'],
})
export class ConfirmRotateClientCertificateComponent {
    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: RotateClientOptions,
    ) {

    }

    public async save(): Promise<void> {
        try {
            const newInfo: BaseCertificate = {
                email: this.options.client.certificate?.email ?? '',
                country: this.options.client.certificate?.country ?? '',
                province: this.options.client.certificate?.province ?? '',
                city: this.options.client.certificate?.city ?? '',
                organisation: this.options.client.certificate?.organisation ?? '',
                organisationUnit: this.options.client.certificate?.organisationUnit ?? '',
            };
            const newClient = await this.openvpnService.rotateCertificate(this.options.client.username, newInfo);
            newClient.certificate!.accountStatus = 'Active';
            newClient.certificate!.revocationDate = undefined;
            this.options.client.certificate!.accountStatus = 'Revoked';
            this.options.client.certificate!.revocationDate = new Date();
            this.modal.close(newClient);
        } catch (e) {
            console.warn('service call failed');
        }
    }
}
