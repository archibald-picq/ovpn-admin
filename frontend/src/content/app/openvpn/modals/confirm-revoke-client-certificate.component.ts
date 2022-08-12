import {Component} from "@angular/core";
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";
import { IClientCertificate } from '../models/client-certificate.interface';
import { OpenvpnService } from '../services/openvpn.service';

export class RevokeClientOptions {
    constructor(public readonly client: IClientCertificate) {
    }
}

@Component({
    selector: 'bus-openvpn-confirm-revoke-client-certificate',
    templateUrl: './confirm-revoke-client-certificate.component.html',
    styleUrls: ['./confirm-revoke-client-certificate.component.scss'],
})
export class ConfirmRevokeClientCertificateComponent {
    constructor(
        private readonly openvpnService: OpenvpnService,
        public readonly modal: NgbActiveModal,
        public readonly options: RevokeClientOptions,
    ) {

    }

    public async doRevokeCertificate(): Promise<void> {
        try {
            await this.openvpnService.revokeCertificate(this.options.client);
            this.options.client.accountStatus = 'Revoked';
            this.options.client.revocationDate = new Date();
            this.modal.close('Save click');
        } catch (e) {
            console.warn('service call failed');
        }
    }
}